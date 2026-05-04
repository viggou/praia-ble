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
#include <fcntl.h>
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

// ── GATT over L2CAP/ATT (Phase 3) ──────────────────────────────────────────
//
// We bypass libbluetooth and the BlueZ DBus GATT API: open an L2CAP socket on
// CID 4 (ATT) and speak the ATT protocol directly. This gives us full control
// (raw PDUs, custom MTU, arbitrary handle reads) which is what pentesting
// tooling typically wants.

constexpr int BTPROTO_L2CAP        = 0;
constexpr uint16_t L2CAP_ATT_CID   = 0x0004;
constexpr uint8_t  BDADDR_LE_PUBLIC = 0x01;
constexpr uint8_t  BDADDR_LE_RANDOM = 0x02;

struct sockaddr_l2 {
    sa_family_t l2_family;
    uint16_t    l2_psm;
    uint8_t     l2_bdaddr[6];
    uint16_t    l2_cid;
    uint8_t     l2_bdaddr_type;
};

constexpr uint8_t ATT_OP_ERROR_RSP         = 0x01;
constexpr uint8_t ATT_OP_MTU_REQ           = 0x02;
constexpr uint8_t ATT_OP_MTU_RSP           = 0x03;
constexpr uint8_t ATT_OP_FIND_INFO_REQ     = 0x04;
constexpr uint8_t ATT_OP_FIND_INFO_RSP     = 0x05;
constexpr uint8_t ATT_OP_READ_BY_TYPE_REQ  = 0x08;
constexpr uint8_t ATT_OP_READ_BY_TYPE_RSP  = 0x09;
constexpr uint8_t ATT_OP_READ_REQ          = 0x0A;
constexpr uint8_t ATT_OP_READ_RSP          = 0x0B;
constexpr uint8_t ATT_OP_READ_BLOB_REQ     = 0x0C;
constexpr uint8_t ATT_OP_READ_BLOB_RSP     = 0x0D;
constexpr uint8_t ATT_OP_READ_BY_GROUP_REQ = 0x10;
constexpr uint8_t ATT_OP_READ_BY_GROUP_RSP = 0x11;
constexpr uint8_t ATT_OP_WRITE_REQ         = 0x12;
constexpr uint8_t ATT_OP_WRITE_RSP         = 0x13;
constexpr uint8_t ATT_OP_HANDLE_NOTIFY     = 0x1B;
constexpr uint8_t ATT_OP_HANDLE_INDICATE   = 0x1D;
constexpr uint8_t ATT_OP_HANDLE_CONFIRM    = 0x1E;
constexpr uint8_t ATT_OP_WRITE_CMD         = 0x52;

constexpr uint8_t ATT_ERR_NOT_FOUND        = 0x0A;

struct AttConn {
    int sock = -1;
    uint16_t mtu = 23;
    // Notifications received while waiting for a request response are buffered
    // here and consumed by ble.nextNotification.
    std::deque<std::pair<uint16_t, std::vector<uint8_t>>> notifications;
};

static std::unordered_map<int64_t, AttConn> attConns;
static int64_t nextAttId = 1;

// Parse "AA:BB:CC:DD:EE:FF" → 6 little-endian bytes (LSB first, as the kernel
// expects in sockaddr_l2.l2_bdaddr).
static bool parseBdaddr(const std::string& s, uint8_t out[6]) {
    if (s.size() != 17) return false;
    for (int i = 0; i < 6; i++) {
        size_t off = static_cast<size_t>(i) * 3;
        if (off + 2 > s.size()) return false;
        if (i < 5 && s[off + 2] != ':') return false;
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hex(s[off]);
        int lo = hex(s[off + 1]);
        if (hi < 0 || lo < 0) return false;
        out[5 - i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static void attSend(int sock, const uint8_t* pdu, size_t len) {
    ssize_t n = write(sock, pdu, len);
    if (n != static_cast<ssize_t>(len))
        throw RuntimeError(std::string("ble: ATT write failed: ") + strerror(errno), 0);
}

// Read one ATT PDU, blocking up to `timeoutMs`. Returns empty on timeout.
// Honors SIGINT.
static std::vector<uint8_t> attRecv(AttConn& c, int timeoutMs) {
    struct pollfd pfd = {c.sock, POLLIN, 0};
    int pr = poll(&pfd, 1, timeoutMs);
    checkInterrupted();
    if (pr < 0) {
        if (errno == EINTR) return {};
        throw RuntimeError(std::string("ble: poll: ") + strerror(errno), 0);
    }
    if (pr == 0) return {};
    uint8_t buf[1024];
    ssize_t n = read(c.sock, buf, sizeof(buf));
    checkInterrupted();
    if (n <= 0) {
        if (n == 0) throw RuntimeError("ble: ATT connection closed by peer", 0);
        throw RuntimeError(std::string("ble: ATT read: ") + strerror(errno), 0);
    }
    return std::vector<uint8_t>(buf, buf + n);
}

// Send a request and wait for the matching response. Notifications/indications
// arriving in the meantime are buffered for ble.nextNotification (and indications
// are auto-confirmed). On Error Response or timeout, throws.
static std::vector<uint8_t> attRequest(AttConn& c,
                                       const std::vector<uint8_t>& req,
                                       int timeoutMs = 5000) {
    if (req.empty()) throw RuntimeError("ble: empty ATT request", 0);
    uint8_t expectedRsp = static_cast<uint8_t>(req[0] + 1);

    attSend(c.sock, req.data(), req.size());

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs);
    while (true) {
        checkInterrupted();
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0)
            throw RuntimeError("ble: ATT request timed out", 0);

        auto pdu = attRecv(c, static_cast<int>(std::min<int64_t>(remaining, 200)));
        if (pdu.empty()) continue;
        uint8_t op = pdu[0];

        if (op == ATT_OP_HANDLE_NOTIFY && pdu.size() >= 3) {
            uint16_t vh = static_cast<uint16_t>(pdu[1] | (pdu[2] << 8));
            c.notifications.emplace_back(
                vh, std::vector<uint8_t>(pdu.begin() + 3, pdu.end()));
            continue;
        }
        if (op == ATT_OP_HANDLE_INDICATE && pdu.size() >= 3) {
            uint8_t conf = ATT_OP_HANDLE_CONFIRM;
            attSend(c.sock, &conf, 1);
            uint16_t vh = static_cast<uint16_t>(pdu[1] | (pdu[2] << 8));
            c.notifications.emplace_back(
                vh, std::vector<uint8_t>(pdu.begin() + 3, pdu.end()));
            continue;
        }
        if (op == ATT_OP_ERROR_RSP && pdu.size() >= 5) {
            uint8_t reqOp   = pdu[1];
            uint16_t handle = static_cast<uint16_t>(pdu[2] | (pdu[3] << 8));
            uint8_t errCode = pdu[4];
            char msg[160];
            snprintf(msg, sizeof(msg),
                "ble: ATT error: reqOp=0x%02X handle=0x%04X errCode=0x%02X",
                reqOp, handle, errCode);
            throw RuntimeError(msg, 0);
        }
        if (op == expectedRsp) return pdu;
        // Anything else (stray response after a previous timeout, etc.) is
        // dropped. This is conservative but safe.
    }
}

// Negotiate ATT MTU. The peer picks min(its max, ours). Default ATT MTU is 23
// (3-byte ATT header + 20-byte payload), which is painfully small for many
// reads. We request 247 (max practical for BLE 4.2+ Data Length Extension).
//
// Best-effort: peripherals that don't support Exchange MTU (some flat-out
// disconnect on receiving it) leave us at the default mtu=23. SIGINT is
// re-thrown so Ctrl+C still escapes.
static void attExchangeMtu(AttConn& c, uint16_t want) {
    std::vector<uint8_t> req = {
        ATT_OP_MTU_REQ,
        static_cast<uint8_t>(want & 0xFF),
        static_cast<uint8_t>((want >> 8) & 0xFF),
    };
    try {
        auto rsp = attRequest(c, req, 2000);
        if (rsp.size() >= 3) {
            uint16_t serverMtu = static_cast<uint16_t>(rsp[1] | (rsp[2] << 8));
            c.mtu = std::min(want, serverMtu);
            if (c.mtu < 23) c.mtu = 23;
        }
    } catch (RuntimeError& e) {
        if (std::string(e.what()) == "Interrupted") throw;
        c.mtu = 23;
    }
}

// ── GATT discovery / read / write helpers ─────────────────────────────────

struct GattService {
    std::string uuid;
    uint16_t startHandle;
    uint16_t endHandle;
};

static std::vector<GattService> gattDiscoverServices(AttConn& c) {
    std::vector<GattService> out;
    uint16_t start = 0x0001;
    while (true) {
        // Read By Group Type: opcode + start + end + type-uuid (0x2800 = primary svc)
        std::vector<uint8_t> req = {
            ATT_OP_READ_BY_GROUP_REQ,
            static_cast<uint8_t>(start & 0xFF), static_cast<uint8_t>((start >> 8) & 0xFF),
            0xFF, 0xFF,
            0x00, 0x28,
        };
        try {
            auto rsp = attRequest(c, req);
            // Format: 0x11, length(1), [start(2) end(2) uuid(2|16)] * N
            if (rsp.size() < 2) break;
            uint8_t entryLen = rsp[1];
            if (entryLen != 6 && entryLen != 20) break;
            uint16_t startBefore = start;
            for (size_t i = 2; i + entryLen <= rsp.size(); i += entryLen) {
                uint16_t s = static_cast<uint16_t>(rsp[i]   | (rsp[i+1] << 8));
                uint16_t e = static_cast<uint16_t>(rsp[i+2] | (rsp[i+3] << 8));
                std::string uuid;
                if (entryLen == 6) uuid = ble_uuidFromLE(&rsp[i+4], 2);
                else               uuid = ble_uuidFromLE(&rsp[i+4], 16);
                out.push_back({std::move(uuid), s, e});
                if (e == 0xFFFF) return out;
                start = static_cast<uint16_t>(e + 1);
            }
            // Guard against a peer sending a malformed response that doesn't
            // advance our cursor — would otherwise spin forever.
            if (start == startBefore) break;
        } catch (RuntimeError& er) {
            // ATT_ERR_NOT_FOUND (0x0A) means there are no more services.
            if (std::string(er.what()).find("errCode=0x0A") != std::string::npos)
                break;
            throw;
        }
    }
    return out;
}

struct GattChar {
    std::string uuid;
    uint16_t handle;       // declaration handle
    uint16_t valueHandle;  // value handle
    uint8_t  props;        // bitmask
};

static std::vector<GattChar> gattDiscoverChars(AttConn& c, uint16_t startHandle, uint16_t endHandle) {
    std::vector<GattChar> out;
    uint16_t start = startHandle;
    while (start <= endHandle) {
        // Read By Type with type 0x2803 (Characteristic Declaration)
        std::vector<uint8_t> req = {
            ATT_OP_READ_BY_TYPE_REQ,
            static_cast<uint8_t>(start & 0xFF), static_cast<uint8_t>((start >> 8) & 0xFF),
            static_cast<uint8_t>(endHandle & 0xFF), static_cast<uint8_t>((endHandle >> 8) & 0xFF),
            0x03, 0x28,
        };
        try {
            auto rsp = attRequest(c, req);
            // Format: 0x09, length(1), [handle(2) value(props(1)+valueHandle(2)+uuid(2|16))] * N
            if (rsp.size() < 2) break;
            uint8_t entryLen = rsp[1];
            // entryLen = 2 + 1 + 2 + (2 or 16) = 7 or 21
            if (entryLen != 7 && entryLen != 21) break;
            uint16_t startBefore = start;
            for (size_t i = 2; i + entryLen <= rsp.size(); i += entryLen) {
                uint16_t handle = static_cast<uint16_t>(rsp[i]   | (rsp[i+1] << 8));
                uint8_t  props  = rsp[i+2];
                uint16_t vh     = static_cast<uint16_t>(rsp[i+3] | (rsp[i+4] << 8));
                std::string uuid;
                if (entryLen == 7) uuid = ble_uuidFromLE(&rsp[i+5], 2);
                else               uuid = ble_uuidFromLE(&rsp[i+5], 16);
                out.push_back({std::move(uuid), handle, vh, props});
                if (handle == 0xFFFF) return out;
                start = static_cast<uint16_t>(handle + 1);
            }
            if (start == startBefore) break; // no-progress guard
        } catch (RuntimeError& er) {
            if (std::string(er.what()).find("errCode=0x0A") != std::string::npos) break;
            throw;
        }
    }
    return out;
}

// Read a characteristic value, paginating with Read Blob if the response was
// exactly mtu-1 bytes (which means there might be more — ATT doesn't tell us
// the total length, so we have to probe).
static std::vector<uint8_t> gattReadValue(AttConn& c, uint16_t valueHandle) {
    std::vector<uint8_t> out;
    {
        std::vector<uint8_t> req = {
            ATT_OP_READ_REQ,
            static_cast<uint8_t>(valueHandle & 0xFF),
            static_cast<uint8_t>((valueHandle >> 8) & 0xFF),
        };
        auto rsp = attRequest(c, req);
        out.insert(out.end(), rsp.begin() + 1, rsp.end());
        if (out.size() < static_cast<size_t>(c.mtu - 1)) return out;
    }
    // Long read: keep issuing Read Blob with growing offset until we get
    // back fewer than mtu-1 bytes (or an error).
    while (true) {
        if (out.size() > 0xFFFF) break; // ATT offset is 16-bit
        uint16_t off = static_cast<uint16_t>(out.size());
        std::vector<uint8_t> req = {
            ATT_OP_READ_BLOB_REQ,
            static_cast<uint8_t>(valueHandle & 0xFF),
            static_cast<uint8_t>((valueHandle >> 8) & 0xFF),
            static_cast<uint8_t>(off & 0xFF),
            static_cast<uint8_t>((off >> 8) & 0xFF),
        };
        try {
            auto rsp = attRequest(c, req);
            size_t added = rsp.size() - 1;
            out.insert(out.end(), rsp.begin() + 1, rsp.end());
            if (added < static_cast<size_t>(c.mtu - 1)) break;
        } catch (RuntimeError& er) {
            // 0x07 = Invalid Offset (we read past the end). Stop quietly.
            if (std::string(er.what()).find("errCode=0x07") != std::string::npos) break;
            throw;
        }
    }
    return out;
}

static void gattWriteValue(AttConn& c, uint16_t valueHandle,
                           const uint8_t* data, size_t len, bool withResponse) {
    if (len > static_cast<size_t>(c.mtu - 3))
        throw RuntimeError("ble: write payload exceeds MTU; use a shorter value or "
                           "negotiate a larger MTU", 0);
    std::vector<uint8_t> pdu;
    pdu.reserve(3 + len);
    pdu.push_back(withResponse ? ATT_OP_WRITE_REQ : ATT_OP_WRITE_CMD);
    pdu.push_back(static_cast<uint8_t>(valueHandle & 0xFF));
    pdu.push_back(static_cast<uint8_t>((valueHandle >> 8) & 0xFF));
    pdu.insert(pdu.end(), data, data + len);
    if (withResponse) {
        attRequest(c, pdu);
    } else {
        attSend(c.sock, pdu.data(), pdu.size());
    }
}

// Locate the CCCD (Client Characteristic Configuration Descriptor, UUID 0x2902)
// for a characteristic. Walks descriptors via Find Information from
// valueHandle+1 up to nextValueHandle-1 (or 0xFFFF if not provided).
static uint16_t gattFindCccd(AttConn& c, uint16_t valueHandle, uint16_t scanEnd = 0xFFFF) {
    uint16_t start = static_cast<uint16_t>(valueHandle + 1);
    while (start <= scanEnd) {
        std::vector<uint8_t> req = {
            ATT_OP_FIND_INFO_REQ,
            static_cast<uint8_t>(start & 0xFF), static_cast<uint8_t>((start >> 8) & 0xFF),
            static_cast<uint8_t>(scanEnd & 0xFF), static_cast<uint8_t>((scanEnd >> 8) & 0xFF),
        };
        try {
            auto rsp = attRequest(c, req);
            // Format: 0x05, format(1), [handle(2) uuid(2|16)] * N
            // format=1 → 16-bit UUID; format=2 → 128-bit UUID
            if (rsp.size() < 2) return 0;
            uint8_t fmt = rsp[1];
            size_t entryLen = (fmt == 1) ? 4 : (fmt == 2) ? 18 : 0;
            if (entryLen == 0) return 0;
            uint16_t startBefore = start;
            for (size_t i = 2; i + entryLen <= rsp.size(); i += entryLen) {
                uint16_t h = static_cast<uint16_t>(rsp[i] | (rsp[i+1] << 8));
                if (fmt == 1) {
                    uint16_t uuid16 = static_cast<uint16_t>(rsp[i+2] | (rsp[i+3] << 8));
                    if (uuid16 == 0x2902) return h;
                }
                // 128-bit descriptors are rare for CCCD; we only check 16-bit here.
                if (h == 0xFFFF) return 0;
                start = static_cast<uint16_t>(h + 1);
            }
            if (start == startBefore) return 0; // no-progress guard
        } catch (RuntimeError& er) {
            if (std::string(er.what()).find("errCode=0x0A") != std::string::npos) return 0;
            throw;
        }
    }
    return 0;
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
            m->entries["gatt"]          = Value(true);   // raw L2CAP/ATT GATT
            return Value(m);
        }));

    // ── GATT (Phase 3) ─────────────────────────────────────────────────────
    // GATT operations don't share state with the scanning side — Linux
    // uses BTPROTO_L2CAP which is separate from the HCI socket, and macOS
    // uses a process-wide CoreBluetooth central manager. Connect is called
    // directly with an address; no session handle needed.
    //
    // IMPORTANT: connect() requires the controller to be available to the
    // kernel BLE stack. If you previously called ble.open() with the default
    // exclusive=true, close that handle first and restore power (or just use
    // the high-level ble.scan() which handles this for you).

    // ble.connect(address, opts?) -> connHandle
    // opts: {addressType: "public"|"random" (default "random"),
    //        timeoutMs: int (default 10000), mtu: int (default 247)}
    module->entries["connect"] = Value(makeNative("ble.connect", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.empty() || !args[0].isString())
                throw RuntimeError("ble.connect(address, opts?) requires address string", 0);
            const auto& addrStr = args[0].asString();
            uint8_t bd[6];
            if (!parseBdaddr(addrStr, bd))
                throw RuntimeError("ble.connect(): invalid address '" + addrStr + "'", 0);

            uint8_t addrType = BDADDR_LE_RANDOM; // most modern BLE devices
            int timeoutMs = 10000;
            // Default MTU 23 (no Exchange MTU): some peripherals disconnect
            // the link on receiving Exchange MTU. Caller can request a higher
            // MTU explicitly with opts.mtu (e.g. 247 for BLE 4.2+ DLE).
            uint16_t wantMtu = 23;
            if (args.size() > 1 && args[1].isMap()) {
                auto opts = args[1].asMap();
                auto get = [&](const char* k) -> const Value* {
                    auto it = opts->entries.find(Value(std::string(k)));
                    return it != opts->entries.end() ? &it->second : nullptr;
                };
                if (auto v = get("addressType"); v && v->isString()) {
                    if (v->asString() == "public") addrType = BDADDR_LE_PUBLIC;
                    else if (v->asString() == "random") addrType = BDADDR_LE_RANDOM;
                }
                if (auto v = get("timeoutMs"); v && v->isNumber())
                    timeoutMs = static_cast<int>(v->asNumber());
                if (auto v = get("mtu"); v && v->isNumber())
                    wantMtu = static_cast<uint16_t>(v->asNumber());
            }

            int sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC, BTPROTO_L2CAP);
            if (sock < 0)
                throw RuntimeError(std::string("ble.connect(): socket: ") + strerror(errno), 0);

            // From here until the socket is handed off into attConns, any
            // exception (including SIGINT via checkInterrupted) must close
            // the socket — otherwise the fd leaks because Praia never gets
            // a handle to disconnect.
            try {
                // Bind to "any" local LE address on the controller before connecting.
                struct sockaddr_l2 src = {};
                src.l2_family       = AF_BLUETOOTH;
                src.l2_cid          = L2CAP_ATT_CID;
                src.l2_bdaddr_type  = BDADDR_LE_PUBLIC; // local addr type
                if (bind(sock, reinterpret_cast<struct sockaddr*>(&src), sizeof(src)) < 0)
                    throw RuntimeError(std::string("ble.connect(): bind: ") + strerror(errno), 0);

                struct sockaddr_l2 dst = {};
                dst.l2_family      = AF_BLUETOOTH;
                dst.l2_cid         = L2CAP_ATT_CID;
                dst.l2_bdaddr_type = addrType;
                memcpy(dst.l2_bdaddr, bd, 6);

                // Non-blocking connect + poll so we can honor SIGINT and a hard
                // timeout. (BlueZ's L2CAP socket has no built-in connect timeout.)
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                int rc = connect(sock, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
                if (rc < 0 && errno != EINPROGRESS)
                    throw RuntimeError(std::string("ble.connect(): ") + strerror(errno), 0);

                auto deadline = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(timeoutMs);
                while (true) {
                    checkInterrupted();
                    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now()).count();
                    if (remaining <= 0)
                        throw RuntimeError("ble.connect(): timeout connecting to " + addrStr, 0);
                    struct pollfd pfd = {sock, POLLOUT, 0};
                    int pr = poll(&pfd, 1, static_cast<int>(std::min<int64_t>(remaining, 200)));
                    if (pr < 0 && errno == EINTR) continue;
                    if (pr < 0)
                        throw RuntimeError(std::string("ble.connect(): poll: ") + strerror(errno), 0);
                    if (pr == 0) continue;
                    int err = 0; socklen_t elen = sizeof(err);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
                        int e = err ? err : errno;
                        throw RuntimeError(std::string("ble.connect(): ") + strerror(e), 0);
                    }
                    break;
                }
                fcntl(sock, F_SETFL, flags); // back to blocking
            } catch (...) {
                ::close(sock);
                throw;
            }

            int64_t id = nextAttId++;
            AttConn c;
            c.sock = sock;
            c.mtu = 23;
            attConns[id] = std::move(c);

            // Negotiate MTU (best-effort; falls back to 23 if peer rejects).
            // attExchangeMtu re-throws on SIGINT, so we have to clean up the
            // socket ourselves — Praia never got a handle to close.
            if (wantMtu > 23) {
                try {
                    attExchangeMtu(attConns[id], wantMtu);
                } catch (...) {
                    ::close(attConns[id].sock);
                    attConns.erase(id);
                    throw;
                }
            }

            return Value(id);
        }));

    // ble.disconnect(connHandle) -> nil
    module->entries["disconnect"] = Value(makeNative("ble.disconnect", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt()) throw RuntimeError("ble.disconnect() requires conn handle", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end()) return Value();
            if (it->second.sock >= 0) ::close(it->second.sock);
            attConns.erase(it);
            return Value();
        }));

    // ble.services(connHandle) -> array of {uuid, startHandle, endHandle}
    module->entries["services"] = Value(makeNative("ble.services", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt()) throw RuntimeError("ble.services() requires conn handle", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end()) throw RuntimeError("ble.services(): invalid conn handle", 0);
            auto svcs = gattDiscoverServices(it->second);
            auto arr = gcNew<PraiaArray>();
            for (auto& s : svcs) {
                auto m = gcNew<PraiaMap>();
                m->entries["uuid"]        = Value(s.uuid);
                m->entries["startHandle"] = Value(static_cast<int64_t>(s.startHandle));
                m->entries["endHandle"]   = Value(static_cast<int64_t>(s.endHandle));
                arr->elements.push_back(Value(m));
            }
            return Value(arr);
        }));

    // ble.characteristics(connHandle, startHandle, endHandle) -> array of
    //   {uuid, handle, valueHandle, props: {read, write, writeNoResp, notify, indicate, ...}}
    module->entries["characteristics"] = Value(makeNative("ble.characteristics", 3,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt() || !args[1].isInt() || !args[2].isInt())
                throw RuntimeError("ble.characteristics(conn, startHandle, endHandle)", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end())
                throw RuntimeError("ble.characteristics(): invalid conn handle", 0);
            auto chars = gattDiscoverChars(it->second,
                static_cast<uint16_t>(args[1].asInt()),
                static_cast<uint16_t>(args[2].asInt()));
            auto arr = gcNew<PraiaArray>();
            for (auto& ch : chars) {
                auto m = gcNew<PraiaMap>();
                m->entries["uuid"]        = Value(ch.uuid);
                m->entries["handle"]      = Value(static_cast<int64_t>(ch.handle));
                m->entries["valueHandle"] = Value(static_cast<int64_t>(ch.valueHandle));
                auto props = gcNew<PraiaMap>();
                props->entries["broadcast"]   = Value(static_cast<bool>(ch.props & 0x01));
                props->entries["read"]        = Value(static_cast<bool>(ch.props & 0x02));
                props->entries["writeNoResp"] = Value(static_cast<bool>(ch.props & 0x04));
                props->entries["write"]       = Value(static_cast<bool>(ch.props & 0x08));
                props->entries["notify"]      = Value(static_cast<bool>(ch.props & 0x10));
                props->entries["indicate"]    = Value(static_cast<bool>(ch.props & 0x20));
                props->entries["signedWrite"] = Value(static_cast<bool>(ch.props & 0x40));
                m->entries["props"] = Value(props);
                arr->elements.push_back(Value(m));
            }
            return Value(arr);
        }));

    // ble.read(connHandle, valueHandle) -> bytes
    module->entries["read"] = Value(makeNative("ble.read", 2,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt() || !args[1].isInt())
                throw RuntimeError("ble.read(conn, valueHandle)", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end()) throw RuntimeError("ble.read(): invalid conn handle", 0);
            auto v = gattReadValue(it->second, static_cast<uint16_t>(args[1].asInt()));
            return Value(std::string(reinterpret_cast<const char*>(v.data()), v.size()));
        }));

    // ble.write(connHandle, valueHandle, data, withResponse?) -> nil
    module->entries["write"] = Value(makeNative("ble.write", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.size() < 3 || !args[0].isInt() || !args[1].isInt() || !args[2].isString())
                throw RuntimeError("ble.write(conn, valueHandle, data, withResponse?)", 0);
            bool withResp = true;
            if (args.size() > 3 && args[3].isBool()) withResp = args[3].asBool();
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end()) throw RuntimeError("ble.write(): invalid conn handle", 0);
            const auto& s = args[2].asString();
            gattWriteValue(it->second,
                static_cast<uint16_t>(args[1].asInt()),
                reinterpret_cast<const uint8_t*>(s.data()), s.size(),
                withResp);
            return Value();
        }));

    // ble.subscribe(connHandle, valueHandle, scanEndHandle?) -> cccdHandle
    // Walks descriptors to find the CCCD and writes 0x0001 (enable
    // notifications). For indications, write 0x0002 to the returned cccdHandle
    // directly via ble.write. scanEndHandle limits the descriptor walk to a
    // service's range; if omitted, scans up to 0xFFFF.
    module->entries["subscribe"] = Value(makeNative("ble.subscribe", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.size() < 2 || !args[0].isInt() || !args[1].isInt())
                throw RuntimeError("ble.subscribe(conn, valueHandle, scanEndHandle?)", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end())
                throw RuntimeError("ble.subscribe(): invalid conn handle", 0);
            uint16_t vh = static_cast<uint16_t>(args[1].asInt());
            uint16_t scanEnd = 0xFFFF;
            if (args.size() > 2 && args[2].isInt())
                scanEnd = static_cast<uint16_t>(args[2].asInt());
            uint16_t cccd = gattFindCccd(it->second, vh, scanEnd);
            if (!cccd)
                throw RuntimeError("ble.subscribe(): no CCCD descriptor found for handle " +
                                   std::to_string(vh), 0);
            uint8_t enable[2] = {0x01, 0x00};
            gattWriteValue(it->second, cccd, enable, 2, true);
            return Value(static_cast<int64_t>(cccd));
        }));

    // ble.unsubscribe(connHandle, cccdHandle) -> nil
    module->entries["unsubscribe"] = Value(makeNative("ble.unsubscribe", 2,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt() || !args[1].isInt())
                throw RuntimeError("ble.unsubscribe(conn, cccdHandle)", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end())
                throw RuntimeError("ble.unsubscribe(): invalid conn handle", 0);
            uint8_t disable[2] = {0x00, 0x00};
            gattWriteValue(it->second, static_cast<uint16_t>(args[1].asInt()),
                           disable, 2, true);
            return Value();
        }));

    // ble.nextNotification(connHandle, timeoutMs?) -> {valueHandle, data} | nil
    // Returns the next buffered notification, blocking up to timeoutMs (default
    // 1000) by reading the ATT socket. Throws "Interrupted" on Ctrl+C.
    module->entries["nextNotification"] = Value(makeNative("ble.nextNotification", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.empty() || !args[0].isInt())
                throw RuntimeError("ble.nextNotification(conn, timeoutMs?)", 0);
            auto it = attConns.find(args[0].asInt());
            if (it == attConns.end())
                throw RuntimeError("ble.nextNotification(): invalid conn handle", 0);
            int timeoutMs = 1000;
            if (args.size() > 1 && args[1].isNumber())
                timeoutMs = static_cast<int>(args[1].asNumber());

            auto& c = it->second;
            auto popOne = [&]() -> Value {
                auto& e = c.notifications.front();
                auto m = gcNew<PraiaMap>();
                m->entries["valueHandle"] = Value(static_cast<int64_t>(e.first));
                m->entries["data"] = Value(std::string(
                    reinterpret_cast<const char*>(e.second.data()), e.second.size()));
                c.notifications.pop_front();
                return Value(m);
            };
            if (!c.notifications.empty()) return popOne();

            // No buffered notification — read from the socket until we get one
            // (auto-confirming any indications) or hit the timeout.
            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(timeoutMs);
            while (true) {
                checkInterrupted();
                auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now()).count();
                if (remaining <= 0) return Value();
                auto pdu = attRecv(c, static_cast<int>(std::min<int64_t>(remaining, 200)));
                if (pdu.empty()) continue;
                uint8_t op = pdu[0];
                if (op == ATT_OP_HANDLE_NOTIFY && pdu.size() >= 3) {
                    uint16_t vh = static_cast<uint16_t>(pdu[1] | (pdu[2] << 8));
                    c.notifications.emplace_back(
                        vh, std::vector<uint8_t>(pdu.begin() + 3, pdu.end()));
                    return popOne();
                }
                if (op == ATT_OP_HANDLE_INDICATE && pdu.size() >= 3) {
                    uint8_t conf = ATT_OP_HANDLE_CONFIRM;
                    attSend(c.sock, &conf, 1);
                    uint16_t vh = static_cast<uint16_t>(pdu[1] | (pdu[2] << 8));
                    c.notifications.emplace_back(
                        vh, std::vector<uint8_t>(pdu.begin() + 3, pdu.end()));
                    return popOne();
                }
                // Other PDUs at this point are stray — drop them.
            }
        }));
}
