// ble — BLE LE scanning via raw HCI socket on Linux.
//
// We deliberately don't depend on libbluetooth: the constants and structs we
// need are stable Linux kernel ABI, so we inline them. This keeps the build
// dep-free across distros (no bluez-libs-devel needed).

#define _XOPEN_SOURCE 700

#include "praia_plugin.h"
#include "signal_state.h"
#include "ble_parser.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

// ── Linux Bluetooth ABI (inline; from <bluetooth/*.h> & <linux/sockios.h>) ──

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
constexpr int BTPROTO_HCI       = 1;
constexpr int HCI_CHANNEL_RAW   = 0;
constexpr int HCI_CHANNEL_USER  = 1;  // exclusive; needs device powered off
constexpr int SOL_HCI           = 0;
constexpr int HCI_FILTER        = 2;

constexpr uint8_t HCI_COMMAND_PKT = 0x01;
constexpr uint8_t HCI_EVENT_PKT   = 0x04;

constexpr uint8_t EVT_CMD_COMPLETE  = 0x0E;
constexpr uint8_t EVT_CMD_STATUS    = 0x0F;
constexpr uint8_t EVT_LE_META       = 0x3E;
constexpr uint8_t EVT_LE_ADV_REPORT = 0x02; // subevent of LE Meta

constexpr uint16_t OGF_HOST_CTL            = 0x03;
constexpr uint16_t OCF_SET_EVENT_MASK      = 0x0001;
constexpr uint16_t OGF_LE_CTL              = 0x08;
constexpr uint16_t OCF_LE_SET_EVENT_MASK   = 0x0001;
constexpr uint16_t OCF_LE_SET_SCAN_PARAMS  = 0x000B;
constexpr uint16_t OCF_LE_SET_SCAN_ENABLE  = 0x000C;

constexpr uint16_t makeOpcode(uint16_t ogf, uint16_t ocf) {
    return static_cast<uint16_t>((ogf << 10) | (ocf & 0x03FF));
}

struct sockaddr_hci {
    sa_family_t hci_family;
    uint16_t    hci_dev;
    uint16_t    hci_channel;
};

// Same layout libbluetooth uses; the kernel reads this into a 14-byte struct.
struct hci_filter_t {
    uint32_t type_mask;
    uint32_t event_mask[2];
    uint16_t opcode;
};

// ── Helpers ─────────────────────────────────────────────────────────────────

static inline void checkInterrupted() {
    if (g_pendingSignals.load(std::memory_order_relaxed) & (1u << SIGINT))
        throw RuntimeError("Interrupted", 0);
}

static std::string formatBdaddr(const uint8_t* a) {
    // Address bytes on the wire are little-endian; print MSB first.
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             a[5], a[4], a[3], a[2], a[1], a[0]);
    return std::string(buf);
}

static const char* advTypeStr(uint8_t t) {
    switch (t) {
        case 0x00: return "ind";
        case 0x01: return "direct-ind";
        case 0x02: return "scan-ind";
        case 0x03: return "nonconn-ind";
        case 0x04: return "scan-rsp";
        default:   return "unknown";
    }
}

static double nowSeconds() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
}

// ── Buffered reports per handle ────────────────────────────────────────────

struct PendingReport {
    uint8_t  eventType;
    uint8_t  addrType;
    uint8_t  addr[6];
    int8_t   rssi;
    std::vector<uint8_t> data;
    double   timestamp;
};

struct BleHandle {
    int sock = -1;
    int devId = 0;
    bool scanning = false;
    bool exclusive = true;
    bool eventsEnabled = false; // tracks one-time LE event-mask init
    std::deque<PendingReport> pending;
};

static std::unordered_map<int64_t, BleHandle> handles;
static int64_t nextId = 1;

// ── HCI command/response ───────────────────────────────────────────────────

static void writeCommand(int sock, uint16_t opcode, const uint8_t* params, uint8_t plen) {
    uint8_t buf[1 + 3 + 255];
    buf[0] = HCI_COMMAND_PKT;
    buf[1] = static_cast<uint8_t>(opcode & 0xFF);
    buf[2] = static_cast<uint8_t>((opcode >> 8) & 0xFF);
    buf[3] = plen;
    if (plen) memcpy(buf + 4, params, plen);
    ssize_t want = 4 + plen;
    if (write(sock, buf, want) != want)
        throw RuntimeError(std::string("ble: HCI write failed: ") + strerror(errno), 0);
}

// Block until we see a Command Complete (or Command Status) for `opcode`,
// returning its status byte (0x00 = success). Honors SIGINT and timeoutMs.
static uint8_t waitCommandComplete(int sock, uint16_t opcode, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs);
    while (true) {
        checkInterrupted();
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0)
            throw RuntimeError("ble: timed out waiting for HCI command-complete", 0);

        struct pollfd pfd = {sock, POLLIN, 0};
        int pr = poll(&pfd, 1, static_cast<int>(std::min<int64_t>(remaining, 200)));
        if (pr < 0) {
            if (errno == EINTR) continue;
            throw RuntimeError(std::string("ble: poll: ") + strerror(errno), 0);
        }
        if (pr == 0) continue;

        uint8_t buf[260];
        ssize_t n = read(sock, buf, sizeof(buf));
        if (n < 3) continue;
        if (buf[0] != HCI_EVENT_PKT) continue;
        uint8_t code = buf[1];
        uint8_t plen = buf[2];
        if (n < 3 + plen) continue;
        if (code == EVT_CMD_COMPLETE && plen >= 4) {
            // payload: num_pkts(1) opcode(2) status(1) ...
            uint16_t evtOp = static_cast<uint16_t>(buf[4] | (buf[5] << 8));
            if (evtOp == opcode) return buf[6];
        } else if (code == EVT_CMD_STATUS && plen >= 4) {
            // payload: status(1) num_pkts(1) opcode(2)
            uint16_t evtOp = static_cast<uint16_t>(buf[5] | (buf[6] << 8));
            if (evtOp == opcode) return buf[3];
        }
        // Other events (LE Meta etc.) seen during cmd-complete wait are dropped.
        // That's OK: scanning isn't running yet (we haven't sent enable=1) or
        // is being torn down (we already set enable=0 first).
    }
}

// HCI_CHANNEL_USER hands us a freshly-reset controller. The default event
// masks don't include LE Meta Event, so without these the controller never
// forwards Advertising Report events to us — scan looks "successful" but
// produces zero reports. Enable LE Meta in the global event mask, and turn on
// the bits in the LE-specific mask that we care about.
static void enableLeEvents(int sock) {
    // Set Event Mask: take the spec default and OR in bit 61 (LE Meta).
    uint8_t mask[8] = {0xFF, 0xFF, 0xFB, 0xFF, 0x07, 0xF8, 0xBF, 0x3D};
    // (this is the BT 5.0 default; bit 61 = LE Meta is included.)
    uint16_t op = makeOpcode(OGF_HOST_CTL, OCF_SET_EVENT_MASK);
    writeCommand(sock, op, mask, 8);
    uint8_t status = waitCommandComplete(sock, op, 1000);
    if (status != 0) {
        char msg[80];
        snprintf(msg, sizeof(msg), "ble: Set Event Mask failed: status=0x%02X", status);
        throw RuntimeError(msg, 0);
    }
    // LE Set Event Mask: enable all LE events. We only care about Adv Report
    // (bit 1) for now, but enabling everything is harmless and forward-friendly.
    uint8_t leMask[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    op = makeOpcode(OGF_LE_CTL, OCF_LE_SET_EVENT_MASK);
    writeCommand(sock, op, leMask, 8);
    status = waitCommandComplete(sock, op, 1000);
    if (status != 0) {
        char msg[80];
        snprintf(msg, sizeof(msg), "ble: LE Set Event Mask failed: status=0x%02X", status);
        throw RuntimeError(msg, 0);
    }
}

static void sendSetScanParams(int sock, bool active, uint16_t intervalUnits, uint16_t windowUnits) {
    uint8_t p[7];
    p[0] = active ? 0x01 : 0x00;
    p[1] = static_cast<uint8_t>(intervalUnits & 0xFF);
    p[2] = static_cast<uint8_t>((intervalUnits >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(windowUnits & 0xFF);
    p[4] = static_cast<uint8_t>((windowUnits >> 8) & 0xFF);
    p[5] = 0x00; // own_addr_type = public
    p[6] = 0x00; // scan filter policy = accept all
    uint16_t op = makeOpcode(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMS);
    writeCommand(sock, op, p, 7);
    uint8_t status = waitCommandComplete(sock, op, 1000);
    if (status != 0) {
        char msg[80];
        snprintf(msg, sizeof(msg), "ble: LE Set Scan Parameters failed: status=0x%02X", status);
        throw RuntimeError(msg, 0);
    }
}

static void sendSetScanEnable(int sock, bool enable, bool filterDup) {
    uint8_t p[2] = {
        static_cast<uint8_t>(enable ? 0x01 : 0x00),
        static_cast<uint8_t>(filterDup ? 0x01 : 0x00),
    };
    uint16_t op = makeOpcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE);
    writeCommand(sock, op, p, 2);
    uint8_t status = waitCommandComplete(sock, op, 1000);
    // status 0x0C = "Command Disallowed" — fired when toggling scan to a state
    // it's already in. Treat that as success rather than as a hard error,
    // since the end state is what the caller wanted.
    if (status != 0 && status != 0x0C) {
        char msg[80];
        snprintf(msg, sizeof(msg), "ble: LE Set Scan Enable failed: status=0x%02X", status);
        throw RuntimeError(msg, 0);
    }
}

// ── LE Advertising Report parsing ──────────────────────────────────────────

// Parse the payload of an LE Meta event whose subevent is Advertising Report.
// `payload` starts at the byte after the subevent code (i.e. at num_reports).
// Format (Core Spec Vol 4 Part E §7.7.65.2): all per-report fields first,
// then RSSI bytes (one per report) at the end.
static std::vector<PendingReport> parseAdvReports(const uint8_t* payload, size_t len) {
    std::vector<PendingReport> out;
    if (len < 1) return out;
    uint8_t numReports = payload[0];
    size_t off = 1;
    out.resize(numReports);
    double ts = nowSeconds();

    for (uint8_t i = 0; i < numReports; i++) {
        if (off + 9 > len) return {}; // need event(1)+addrType(1)+addr(6)+dlen(1)
        out[i].eventType = payload[off++];
        out[i].addrType  = payload[off++];
        memcpy(out[i].addr, payload + off, 6); off += 6;
        uint8_t dlen = payload[off++];
        if (off + dlen > len) return {};
        out[i].data.assign(payload + off, payload + off + dlen);
        out[i].timestamp = ts;
        off += dlen;
    }
    for (uint8_t i = 0; i < numReports; i++) {
        if (off >= len) return {};
        out[i].rssi = static_cast<int8_t>(payload[off++]);
    }
    return out;
}

static Value reportToValue(const PendingReport& r) {
    auto m = gcNew<PraiaMap>();
    m->entries["address"]     = Value(formatBdaddr(r.addr));
    m->entries["addressType"] = Value(std::string(r.addrType == 0 ? "public" : "random"));
    m->entries["rssi"]        = Value(static_cast<int64_t>(r.rssi));
    m->entries["advType"]     = Value(std::string(advTypeStr(r.eventType)));
    m->entries["data"]        = Value(std::string(reinterpret_cast<const char*>(r.data.data()), r.data.size()));
    m->entries["timestamp"]   = Value(r.timestamp);
    return Value(m);
}

// Read one HCI packet (poll up to timeoutMs). If it's an LE Adv Report event,
// pushes its sub-reports onto the handle's pending queue. Returns true iff a
// packet was consumed (regardless of type); false on timeout.
static bool readOneEvent(BleHandle& h, int timeoutMs) {
    struct pollfd pfd = {h.sock, POLLIN, 0};
    int pr = poll(&pfd, 1, timeoutMs);
    checkInterrupted();
    if (pr < 0) {
        if (errno == EINTR) return false;
        throw RuntimeError(std::string("ble: poll: ") + strerror(errno), 0);
    }
    if (pr == 0) return false;

    uint8_t buf[2048];
    ssize_t n = read(h.sock, buf, sizeof(buf));
    checkInterrupted();
    if (n <= 0) return false;
    if (buf[0] != HCI_EVENT_PKT || n < 3) return true;
    uint8_t code = buf[1];
    uint8_t plen = buf[2];
    if (static_cast<ssize_t>(3 + plen) > n) return true;
    if (code != EVT_LE_META || plen < 1) return true;
    if (buf[3] != EVT_LE_ADV_REPORT) return true;

    auto reports = parseAdvReports(buf + 4, static_cast<size_t>(plen) - 1);
    for (auto& r : reports) h.pending.push_back(std::move(r));
    return true;
}

// ── Plugin registration ────────────────────────────────────────────────────

extern "C" void praia_register(PraiaMap* module) {
    // ble.open(adapterIndex?, opts?) -> handle
    //   adapterIndex defaults to 0 (i.e. hci0).
    //   opts: {exclusive: bool} — if true (default), open HCI_CHANNEL_USER so
    //   bluetoothd doesn't fight our scan-parameter changes. The caller is
    //   responsible for `btmgmt power off` first; HCI_CHANNEL_USER requires
    //   the kernel to have released the controller.
    module->entries["open"] = Value(makeNative("ble.open", -1,
        [](const std::vector<Value>& args) -> Value {
            int dev = 0;
            bool exclusive = true;
            if (!args.empty() && args[0].isInt())
                dev = static_cast<int>(args[0].asInt());
            if (args.size() > 1 && args[1].isMap()) {
                auto opts = args[1].asMap();
                auto it2 = opts->entries.find(Value(std::string("exclusive")));
                if (it2 != opts->entries.end() && it2->second.isBool())
                    exclusive = it2->second.asBool();
            }

            int sock = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
            if (sock < 0)
                throw RuntimeError(std::string("ble.open(): socket: ") + strerror(errno) +
                                   " (need root or CAP_NET_RAW)", 0);

            struct sockaddr_hci addr = {};
            addr.hci_family  = AF_BLUETOOTH;
            addr.hci_dev     = static_cast<uint16_t>(dev);
            addr.hci_channel = exclusive ? HCI_CHANNEL_USER : HCI_CHANNEL_RAW;
            if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
                int e = errno;
                ::close(sock);
                std::string hint;
                if (exclusive && (e == EBUSY || e == EUSERS))
                    hint = " (controller is in use — power it off via 'btmgmt --index " +
                           std::to_string(dev) + " power off' or stop bluetoothd)";
                throw RuntimeError(std::string("ble.open(): bind hci") +
                                   std::to_string(dev) + ": " + strerror(e) + hint, 0);
            }

            // HCI_FILTER setsockopt is only valid on RAW channel — USER
            // channel hardcodes "deliver everything" and rejects filter
            // changes (EBADFD). We do our own filtering in readOneEvent
            // anyway, so this is purely an optimization for RAW.
            if (!exclusive) {
                struct hci_filter_t filt = {};
                filt.type_mask     = 0xFFFFFFFFu;
                filt.event_mask[0] = 0xFFFFFFFFu;
                filt.event_mask[1] = 0xFFFFFFFFu;
                filt.opcode        = 0;
                if (setsockopt(sock, SOL_HCI, HCI_FILTER, &filt, sizeof(filt)) < 0) {
                    int e = errno;
                    ::close(sock);
                    throw RuntimeError(std::string("ble.open(): setsockopt HCI_FILTER: ") + strerror(e), 0);
                }
            }

            int64_t id = nextId++;
            BleHandle h;
            h.sock = sock;
            h.devId = dev;
            h.exclusive = exclusive;
            handles[id] = std::move(h);
            return Value(id);
        }));

    // ble.startScan(handle, opts?) -> nil
    // opts: {active: bool, intervalMs: number, windowMs: number, filterDup: bool}
    module->entries["startScan"] = Value(makeNative("ble.startScan", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.empty() || !args[0].isInt())
                throw RuntimeError("ble.startScan() requires handle", 0);
            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("ble.startScan(): invalid handle", 0);

            bool active = false;
            uint16_t intervalUnits = 0x0010; // 10 ms
            uint16_t windowUnits   = 0x0010; // 10 ms
            bool filterDup = false;

            if (args.size() > 1 && args[1].isMap()) {
                auto opts = args[1].asMap();
                auto getKey = [&](const char* k) -> const Value* {
                    auto it2 = opts->entries.find(Value(std::string(k)));
                    return it2 != opts->entries.end() ? &it2->second : nullptr;
                };
                if (auto v = getKey("active");    v && v->isBool())   active    = v->asBool();
                if (auto v = getKey("filterDup"); v && v->isBool())   filterDup = v->asBool();
                auto msToUnits = [](double ms) -> uint16_t {
                    int64_t u = static_cast<int64_t>(ms * 1000.0 / 625.0);
                    if (u < 0x0004) u = 0x0004;
                    if (u > 0x4000) u = 0x4000;
                    return static_cast<uint16_t>(u);
                };
                if (auto v = getKey("intervalMs"); v && v->isNumber())
                    intervalUnits = msToUnits(v->asNumber());
                if (auto v = getKey("windowMs");   v && v->isNumber())
                    windowUnits   = msToUnits(v->asNumber());
            }

            // On exclusive (HCI_CHANNEL_USER) handles the controller is fresh
            // out of HCI Reset, so the LE event masks are zero and Adv Report
            // events would never be delivered. Initialise once per handle.
            if (it->second.exclusive && !it->second.eventsEnabled) {
                enableLeEvents(it->second.sock);
                it->second.eventsEnabled = true;
            }

            // Set Scan Parameters returns Command Disallowed (0x0C) if scan
            // is already enabled — could be from a previous startScan in this
            // process, or from bluetoothd's own discovery. Always disable
            // first; sendSetScanEnable already treats 0x0C as success, so this
            // is safe whether or not scan is on.
            sendSetScanEnable(it->second.sock, false, false);
            it->second.scanning = false;

            sendSetScanParams(it->second.sock, active, intervalUnits, windowUnits);
            sendSetScanEnable(it->second.sock, true, filterDup);
            it->second.scanning = true;
            return Value();
        }));

    // ble.nextEvent(handle, timeoutMs?) -> map | nil
    // Returns the next advertising report, blocking up to timeoutMs (default 1000).
    // Returns nil on timeout. Throws "Interrupted" on Ctrl+C.
    module->entries["nextEvent"] = Value(makeNative("ble.nextEvent", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.empty() || !args[0].isInt())
                throw RuntimeError("ble.nextEvent() requires handle", 0);
            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("ble.nextEvent(): invalid handle", 0);
            int timeoutMs = 1000;
            if (args.size() > 1 && args[1].isNumber())
                timeoutMs = static_cast<int>(args[1].asNumber());

            // Drain any reports buffered from a previous multi-report event.
            if (!it->second.pending.empty()) {
                auto r = std::move(it->second.pending.front());
                it->second.pending.pop_front();
                return reportToValue(r);
            }

            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(timeoutMs);
            while (true) {
                checkInterrupted();
                auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now()).count();
                if (remaining <= 0) return Value(); // timeout
                int slice = static_cast<int>(std::min<int64_t>(remaining, 200));
                if (!readOneEvent(it->second, slice)) continue;
                if (!it->second.pending.empty()) {
                    auto r = std::move(it->second.pending.front());
                    it->second.pending.pop_front();
                    return reportToValue(r);
                }
            }
        }));

    // ble.stopScan(handle) -> nil
    module->entries["stopScan"] = Value(makeNative("ble.stopScan", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("ble.stopScan() requires handle", 0);
            auto it = handles.find(args[0].asInt());
            if (it == handles.end()) return Value();
            if (it->second.scanning) {
                sendSetScanEnable(it->second.sock, false, false);
                it->second.scanning = false;
            }
            return Value();
        }));

    // ble.close(handle) -> nil
    module->entries["close"] = Value(makeNative("ble.close", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("ble.close() requires handle", 0);
            auto it = handles.find(args[0].asInt());
            if (it == handles.end()) return Value();
            // Best-effort scan-stop on close. Swallow errors: the socket may
            // already be in a state where the cmd-complete won't come back
            // (interrupted, controller reset, etc.), and we still want to
            // close cleanly.
            if (it->second.scanning) {
                try { sendSetScanEnable(it->second.sock, false, false); }
                catch (...) {}
                it->second.scanning = false;
            }
            if (it->second.sock >= 0) ::close(it->second.sock);
            handles.erase(it);
            return Value();
        }));

    // ble.parseAd(bytes) -> map
    module->entries["parseAd"] = Value(makeNative("ble.parseAd", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isString())
                throw RuntimeError("ble.parseAd() requires data", 0);
            const auto& s = args[0].asString();
            return ble_parseAdImpl(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        }));

    // ble.capabilities() -> map describing what the platform can do
    module->entries["capabilities"] = Value(makeNative("ble.capabilities", 0,
        [](const std::vector<Value>&) -> Value {
            auto m = gcNew<PraiaMap>();
            m->entries["platform"]      = Value(std::string("linux"));
            m->entries["realAddress"]   = Value(true);   // raw HCI gives MAC
            m->entries["rawPackets"]    = Value(true);   // adv data exposed as bytes
            m->entries["selectAdapter"] = Value(true);   // multi-adapter via hci index
            m->entries["activeScan"]    = Value(true);   // configurable
            return Value(m);
        }));
}
