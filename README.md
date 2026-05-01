# ble

BLE scanning and GATT for [Praia](https://praia.sh). Built for pentesting and recon: raw advertising packets where the OS allows it, full GATT discovery + read/write/subscribe across Linux and macOS.

Linux requires root or `CAP_NET_RAW`.

## Installation

```sh
sand install github.com/viggou/praia-ble
```

No build dependencies on Linux beyond a kernel with BlueZ support — the plugin talks to the HCI socket and L2CAP socket directly, no libbluetooth needed to build. macOS uses CoreBluetooth from the system SDK.

## Quick start

### Scan for nearby devices

```praia
use "ble"

let devs = ble.scan({duration: 5000, onAdv: lam{ d in
    print(d.address, str(d.rssi)+"dBm", d?.name ?? "-")
}})

print("found", len(devs), "unique devices")
```

`scan()` handles adapter power-management on Linux (releases `bluetoothd`'s claim for the duration via `bluetoothctl`) and uses CoreBluetooth on macOS. Returns a deduplicated list of `{address, rssi, advType, data, name?, services?, manufacturerData?, ...}`.

### Connect and read characteristics

```praia
use "ble"

let h = ble.open()
ble.startScan(h, {})

let target = nil
for (i in 0..50) {
    let e = ble.nextEvent(h, 200)
    if (e?.name == "MOMENTUM 4") { target = e; break }
}
ble.stopScan(h)

let conn = ble.connect(target.address)
let svcs = ble.services(conn)
for (s in svcs) {
    print("service", s.uuid)
    let chars = ble.characteristics(conn, s.startHandle, s.endHandle)
    for (c in chars) {
        if (c.props.read) {
            let val = ble.read(conn, c.valueHandle)
            print("  ", c.uuid, len(val), "bytes")
        }
    }
}
ble.disconnect(conn)
ble.close(h)
```

### Subscribe to notifications

```praia
use "ble"

let h = ble.open()
ble.startScan(h, {})
let evt = ble.nextEvent(h, 5000)
ble.stopScan(h)

let conn = ble.connect(evt.address)
let svcs = ble.services(conn)
let chars = ble.characteristics(conn, svcs[0].startHandle, svcs[0].endHandle)

for (c in chars) {
    if (c.props.notify) {
        let cccd = ble.subscribe(conn, c.valueHandle, svcs[0].endHandle)
        print("subscribed to", c.uuid)

        for (i in 0..20) {
            let n = ble.nextNotification(conn, 1000)
            if (n) { print("notify vh=" + str(n.valueHandle), len(n.data), "bytes") }
        }
        ble.unsubscribe(conn, cccd)
        break
    }
}
ble.disconnect(conn)
ble.close(h)
```

### Parse raw advertising bytes (Linux only)

```praia
use "ble"

let bytes = bytes.fromHex("020106" + "0509" + "54657374" + "0CFF4C00...")
let ad = ble.parseAd(bytes)
print(ad.flags, ad.name, ad?.manufacturerData)
```

## Platform differences

Call `ble.capabilities()` at runtime to branch on what's available:

| Capability | Linux | macOS |
|------------|-------|-------|
| `realAddress` (real MAC vs anonymized) | true | false (per-app NSUUID) |
| `rawPackets` (raw adv bytes in `event.data`) | true | false (parsed only) |
| `selectAdapter` (multi-adapter via index) | true | false (system default) |
| `activeScan` (`opts.active` configurable) | true | false (CB controls) |
| `gatt` | true | true |

## API

### Scanning

| Function | Description |
|----------|-------------|
| `scan(opts)` | High-level: opens session, scans for `opts.duration` ms, returns deduped device list. Opts: `adapter`, `duration`, `active`, `intervalMs`, `windowMs`, `filterDup`, `dedup`, `onAdv`. |
| `open(adapter?, opts?)` | Open a low-level session. Returns a session handle. Opts: `exclusive` (Linux, default true). |
| `startScan(handle, opts?)` | Begin scanning. Opts: `active`, `intervalMs`, `windowMs`, `filterDup`. |
| `nextEvent(handle, timeoutMs?)` | Block up to `timeoutMs` (default 1000) for the next advertising report. Returns `{address, addressType, rssi, advType, data, timestamp}` or nil. Throws "Interrupted" on Ctrl+C. |
| `stopScan(handle)` | Stop scanning. |
| `close(handle)` | Close session and release the adapter. |
| `parseAd(bytes)` | Parse AD records into `{flags, name, services, manufacturerData, serviceData, txPower, appearance}`. |

### GATT

| Function | Description |
|----------|-------------|
| `connect(address, opts?)` | Connect to a peripheral. Opts: `addressType` (`"public"` or `"random"`, Linux only), `timeoutMs` (default 10000), `mtu` (Linux only; default 23 — opt in to 247 for BLE 4.2+ DLE). On macOS, requires that a recent scan from an open session has cached the peripheral. |
| `disconnect(conn)` | Tear down the connection. |
| `services(conn)` | Discover primary services. Returns `[{uuid, startHandle, endHandle}]`. |
| `characteristics(conn, startHandle, endHandle)` | Discover characteristics in a service range. Returns `[{uuid, handle, valueHandle, props: {read, write, writeNoResp, notify, indicate, broadcast, signedWrite}}]`. |
| `read(conn, valueHandle)` | Read a characteristic value. Returns bytes. Long reads (≥ MTU-1) auto-paginate via Read Blob on Linux. |
| `write(conn, valueHandle, data, withResponse?)` | Write a value. `withResponse` defaults to true (uses ATT Write Request); pass false for Write Command. |
| `subscribe(conn, valueHandle, scanEndHandle?)` | Enable notifications. On Linux, walks descriptors to find the CCCD and writes 0x0001; pass `scanEndHandle` to limit the descriptor walk to a service's range. Returns the CCCD handle (or `valueHandle` on macOS where CB hides the CCCD). |
| `unsubscribe(conn, cccdHandle)` | Disable notifications. |
| `nextNotification(conn, timeoutMs?)` | Block for the next notification. Returns `{valueHandle, data}` or nil. Throws "Interrupted" on Ctrl+C. |

### Capabilities

| Function | Description |
|----------|-------------|
| `capabilities()` | Returns `{platform, realAddress, rawPackets, selectAdapter, activeScan, gatt}`. |

## Building from source

```sh
make
```

Requires Praia's development headers (`praia --include-path`). On Linux, gcc with C++17. On macOS, clang++ with `-fobjc-arc` and CoreBluetooth/Foundation frameworks (the Makefile handles this automatically).

## Platform notes

### Linux

- Open the HCI socket via `HCI_CHANNEL_USER` (exclusive) so legacy LE Set Scan Parameters isn't rejected by BT 5.x controllers running in extended-scan mode under `bluetoothd`. The high-level `ble.scan()` toggles `bluetoothctl power off/on` for the duration; `ble.open()` requires the user to do that themselves.
- The `data` field on each event contains the raw advertising payload (0–31 bytes, parseable via `parseAd`).
- GATT uses raw `BTPROTO_L2CAP` sockets on CID 4 (ATT) — independent of the HCI scanner socket. `connect()` requires the controller to be back under the kernel BLE stack (so close any exclusive scanner first).
- MTU exchange is opt-in. Some peripherals disconnect the link on receiving Exchange MTU; default is the BLE-spec minimum of 23. Pass `ble.connect(addr, {mtu: 247})` to negotiate higher.

### macOS

- First run prompts for Bluetooth permission. Grant access to the terminal app — the permission persists in TCC.
- `event.address` is a per-app `NSUUID`, not a MAC. Apple does not expose real Bluetooth addresses to userspace.
- `event.data` is empty (`""`) — CoreBluetooth doesn't expose raw advertising bytes. Parsed AD fields (`name`, `services`, `manufacturerData`, etc.) are populated directly from CoreBluetooth's parsed dictionary.
- Scan parameters (`active`, `intervalMs`, `windowMs`) are silently ignored; CoreBluetooth manages them internally.
- GATT pseudo-handles: CoreBluetooth doesn't expose ATT handles. The plugin synthesises stable per-connection indices for cross-platform parity. They're integers like Linux handles but are NOT real ATT handles — they index into discovery order.
- Connect requires `ble.open()` to be still alive (the scanner's central manager owns the `CBPeripheral`).

## License

MIT
