// ble — macOS backend (CoreBluetooth).
//
// CoreBluetooth's surface is more limited than Linux raw HCI:
//   - Device "address" is a per-app NSUUID, not the real MAC. Apple does not
//     expose MAC addresses to userspace — there's no way to recover them.
//   - Raw advertising bytes are not available; CoreBluetooth gives a parsed
//     dictionary only. We populate the same parsed fields that the Linux
//     backend produces from raw bytes, but `event.data` is empty.
//   - Adv-type is a heuristic from the connectable flag; "scan-rsp" is never
//     a discrete event because CoreBluetooth merges scan-response data into
//     the same delegate callback as the original advertisement.
//   - Scan parameters (active vs passive, interval/window) are not user-
//     configurable; CoreBluetooth manages them internally.
//
// Build: clang++ -x objective-c++ -fobjc-arc -framework Foundation
//                -framework CoreBluetooth ...
//
// Permission: macOS will prompt for Bluetooth access on first run. The
// terminal/IDE that launches praia inherits that permission across processes.
// Without permission, ble.open() throws with a state==Unauthorized error.

// Required by praia's fiber.h:
//   - _XOPEN_SOURCE because it includes <ucontext.h>
//   - _DARWIN_C_SOURCE because _XOPEN_SOURCE alone hides MAP_ANON on macOS
//     (fiber.h uses it for the fiber stack mmap)
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _XOPEN_SOURCE 700

// Include praia headers BEFORE Foundation/CoreBluetooth: Foundation's
// CFBase.h defines TRUE/FALSE as macros and objc.h defines Nil as a macro,
// which would otherwise clobber praia's TokenType::TRUE / TokenType::FALSE
// and ExprType::Nil enum values when the praia headers are parsed. The
// ObjC code below uses YES/NO/nil (lowercase) so the macros, once defined,
// don't interfere with anything we write here.
#include "praia_plugin.h"
#include "signal_state.h"
#include "ble_parser.h"

PRAIA_DECLARE_ABI();
PRAIA_PLUGIN_METADATA("ble", "0.2.0",
                     "Bluetooth Low Energy bindings (macOS CoreBluetooth)");

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

// ── Helpers ────────────────────────────────────────────────────────────────

static inline void checkInterrupted() {
    if (g_pendingSignals.load(std::memory_order_relaxed) & (1u << SIGINT))
        throw RuntimeError("Interrupted", 0);
}

// Convert an NSDictionary recursively into a PraiaMap. Handles NSString,
// NSNumber (int vs double via objCType), NSArray, NSDictionary, and NSData
// (passed through as a Praia byte-string preserving binary content).
static Value nsToValue(id v);

static Value nsDictToMap(NSDictionary* d) {
    auto m = gcNew<PraiaMap>();
    for (id key in d) {
        if (![key isKindOfClass:[NSString class]]) continue;
        NSString* k = key;
        m->entries[std::string([k UTF8String])] = nsToValue(d[k]);
    }
    return Value(m);
}

static Value nsArrayToArray(NSArray* a) {
    auto arr = gcNew<PraiaArray>();
    for (id elem in a) arr->elements.push_back(nsToValue(elem));
    return Value(arr);
}

static Value nsToValue(id v) {
    if (v == nil || v == [NSNull null]) return Value();
    if ([v isKindOfClass:[NSString class]]) {
        return Value(std::string([(NSString*)v UTF8String]));
    }
    if ([v isKindOfClass:[NSNumber class]]) {
        NSNumber* n = v;
        const char* t = [n objCType];
        // f, d → float/double; everything else → integer
        if (t && (t[0] == 'f' || t[0] == 'd')) return Value([n doubleValue]);
        return Value(static_cast<int64_t>([n longLongValue]));
    }
    if ([v isKindOfClass:[NSData class]]) {
        NSData* nsd = v;
        return Value(std::string(static_cast<const char*>(nsd.bytes), nsd.length));
    }
    if ([v isKindOfClass:[NSArray class]])      return nsArrayToArray(v);
    if ([v isKindOfClass:[NSDictionary class]]) return nsDictToMap(v);
    return Value(); // unknown type — drop
}

// ── Forward decls ─────────────────────────────────────────────────────────

@class PraiaBleScanner;
@class PraiaBleConn;

// ── Delegate / scanner object ──────────────────────────────────────────────

@interface PraiaBleScanner : NSObject <CBCentralManagerDelegate>
@property (readonly) CBCentralManager* manager;
- (instancetype)init;
- (BOOL)waitForPoweredOn:(int)timeoutMs error:(NSString**)err;
- (void)startScanAllowingDuplicates:(BOOL)allowDup;
- (void)stopScan;
- (NSDictionary*)dequeueWithSliceMs:(int)ms;
- (CBPeripheral*)peripheralForUUID:(NSString*)uuid;
// Connection lifecycle — invoked by PraiaBleConn via the central manager.
- (void)attachConn:(PraiaBleConn*)conn forPeripheral:(CBPeripheral*)p;
- (void)detachConnForPeripheral:(CBPeripheral*)p;
@end

// ── PraiaBleConn (per-connection state + CBPeripheralDelegate) ────────────
//
// One instance per active connection. Owns a reference to the CBPeripheral
// and exposes synchronous wrappers around CB's async GATT API: each method
// posts a request to the manager's dispatch queue, then waits on an
// NSCondition for the matching delegate callback to fire.

@interface PraiaBleConn : NSObject <CBPeripheralDelegate>
- (instancetype)initWithPeripheral:(CBPeripheral*)p scanner:(PraiaBleScanner*)s;
- (BOOL)connectWithTimeoutMs:(int)timeoutMs error:(NSString**)err;
- (void)disconnect;
- (NSArray<CBService*>*)discoverServicesWithTimeoutMs:(int)timeoutMs error:(NSString**)err;
- (NSArray<CBCharacteristic*>*)discoverCharacteristicsForService:(CBService*)svc
                                                      timeoutMs:(int)timeoutMs
                                                          error:(NSString**)err;
- (CBService*)serviceByStartHandle:(uint16_t)startHandle endHandle:(uint16_t)endHandle;
- (CBCharacteristic*)characteristicByValueHandle:(uint16_t)vh;
- (NSData*)readValueForCharacteristic:(CBCharacteristic*)ch
                            timeoutMs:(int)timeoutMs
                                error:(NSString**)err;
- (BOOL)writeValue:(NSData*)data
 forCharacteristic:(CBCharacteristic*)ch
      withResponse:(BOOL)withResp
         timeoutMs:(int)timeoutMs
             error:(NSString**)err;
- (BOOL)setNotify:(BOOL)enable
forCharacteristic:(CBCharacteristic*)ch
        timeoutMs:(int)timeoutMs
            error:(NSString**)err;
- (NSDictionary*)nextNotificationWithSliceMs:(int)ms;

// Internal callback hooks invoked by PraiaBleScanner.
- (void)_connectSucceeded;
- (void)_connectFailedWithError:(NSError*)error;
- (void)_disconnectedWithError:(NSError*)error;
@end

@implementation PraiaBleScanner {
    CBCentralManager*           _manager;
    dispatch_queue_t            _queue;
    NSMutableArray<NSDictionary*>* _pending;
    NSCondition*                _cv;
    BOOL                        _poweredOn;
    NSString*                   _stateError;
    NSMutableDictionary<NSString*, CBPeripheral*>* _peripheralCache;
    // Map peripheral.identifier.UUIDString → PraiaBleConn (weak via NSValue).
    // Used to route central-manager-level connect/disconnect callbacks to
    // the right Conn object.
    NSMutableDictionary<NSString*, NSValue*>* _connByPeripheral;
}

@synthesize manager = _manager;

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _queue            = dispatch_queue_create("sh.praia.ble", DISPATCH_QUEUE_SERIAL);
    _pending          = [NSMutableArray array];
    _cv               = [[NSCondition alloc] init];
    _peripheralCache  = [NSMutableDictionary dictionary];
    _connByPeripheral = [NSMutableDictionary dictionary];
    _manager = [[CBCentralManager alloc] initWithDelegate:self queue:_queue];
    return self;
}

- (CBPeripheral*)peripheralForUUID:(NSString*)uuid {
    [_cv lock];
    CBPeripheral* p = _peripheralCache[uuid];
    [_cv unlock];
    return p;
}

- (void)attachConn:(PraiaBleConn*)conn forPeripheral:(CBPeripheral*)p {
    [_cv lock];
    _connByPeripheral[p.identifier.UUIDString] = [NSValue valueWithNonretainedObject:conn];
    [_cv unlock];
}

- (void)detachConnForPeripheral:(CBPeripheral*)p {
    [_cv lock];
    [_connByPeripheral removeObjectForKey:p.identifier.UUIDString];
    [_cv unlock];
}

- (void)centralManagerDidUpdateState:(CBCentralManager*)central {
    [_cv lock];
    switch (central.state) {
        case CBManagerStatePoweredOn:
            _poweredOn = YES; _stateError = nil; break;
        case CBManagerStatePoweredOff:
            _stateError = @"Bluetooth is powered off"; break;
        case CBManagerStateUnauthorized:
            _stateError = @"Bluetooth permission denied — grant access in "
                          @"System Settings → Privacy & Security → Bluetooth";
            break;
        case CBManagerStateUnsupported:
            _stateError = @"Bluetooth not supported on this device"; break;
        case CBManagerStateResetting:
            _stateError = @"Bluetooth is resetting"; break;
        case CBManagerStateUnknown:
        default:
            break; // transient — keep waiting
    }
    [_cv broadcast];
    [_cv unlock];
}

- (BOOL)waitForPoweredOn:(int)timeoutMs error:(NSString**)err {
    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while (!_poweredOn && _stateError == nil) {
        if (![_cv waitUntilDate:deadline]) {
            *err = @"Timed out waiting for Bluetooth to power on";
            [_cv unlock];
            return NO;
        }
    }
    if (_stateError) { *err = _stateError; [_cv unlock]; return NO; }
    [_cv unlock];
    return YES;
}

- (void)startScanAllowingDuplicates:(BOOL)allowDup {
    NSDictionary* opts = allowDup
        ? @{CBCentralManagerScanOptionAllowDuplicatesKey: @YES}
        : nil;
    [_manager scanForPeripheralsWithServices:nil options:opts];
}

- (void)stopScan {
    [_manager stopScan];
}

// CB delegate — runs on _queue, not the Praia thread.
- (void)centralManager:(CBCentralManager*)central
   didDiscoverPeripheral:(CBPeripheral*)peripheral
       advertisementData:(NSDictionary<NSString*, id>*)d
                    RSSI:(NSNumber*)rssi {
    // Cache the peripheral so ble.connect can find it later by UUID.
    [_cv lock];
    _peripheralCache[peripheral.identifier.UUIDString] = peripheral;
    [_cv unlock];

    BOOL connectable = NO;
    NSNumber* connNum = d[CBAdvertisementDataIsConnectable];
    if ([connNum isKindOfClass:[NSNumber class]]) connectable = [connNum boolValue];

    NSMutableDictionary* event = [NSMutableDictionary dictionary];
    event[@"address"]     = peripheral.identifier.UUIDString;
    event[@"addressType"] = @"anonymized"; // CB hides the real type
    event[@"rssi"]        = rssi;
    event[@"timestamp"]   = @([[NSDate date] timeIntervalSince1970]);
    event[@"advType"]     = connectable ? @"ind" : @"nonconn-ind";
    event[@"data"]        = @""; // CB does not expose raw advertising bytes

    // Pre-populate the same parsed fields that ble_parser produces on Linux
    // from the raw bytes. This keeps the surface uniform for callers.
    NSString* name = d[CBAdvertisementDataLocalNameKey];
    if ([name isKindOfClass:[NSString class]]) event[@"name"] = name;

    NSNumber* tx = d[CBAdvertisementDataTxPowerLevelKey];
    if ([tx isKindOfClass:[NSNumber class]]) event[@"txPower"] = tx;

    NSArray* svcUUIDs = d[CBAdvertisementDataServiceUUIDsKey];
    if ([svcUUIDs isKindOfClass:[NSArray class]] && svcUUIDs.count > 0) {
        NSMutableArray* out = [NSMutableArray arrayWithCapacity:svcUUIDs.count];
        for (CBUUID* u in svcUUIDs) [out addObject:u.UUIDString];
        event[@"services"] = out;
    }

    NSData* mfg = d[CBAdvertisementDataManufacturerDataKey];
    if ([mfg isKindOfClass:[NSData class]] && mfg.length >= 2) {
        const uint8_t* b = static_cast<const uint8_t*>(mfg.bytes);
        uint16_t cid = static_cast<uint16_t>(b[0] | (b[1] << 8));
        event[@"manufacturerData"] = @{
            @"companyId": @(cid),
            @"data": [NSData dataWithBytes:b + 2 length:mfg.length - 2],
        };
    }

    NSDictionary<CBUUID*, NSData*>* svcData = d[CBAdvertisementDataServiceDataKey];
    if ([svcData isKindOfClass:[NSDictionary class]] && svcData.count > 0) {
        // Match Linux behaviour: surface a single serviceData entry. If a
        // device advertises multiple service-data records, callers can read
        // the raw CB dict via a future API.
        for (CBUUID* u in svcData) {
            NSData* val = svcData[u];
            event[@"serviceData"] = @{
                @"uuid": u.UUIDString,
                @"data": val,
            };
            break;
        }
    }

    [_cv lock];
    [_pending addObject:event];
    [_cv broadcast];
    [_cv unlock];
}

- (NSDictionary*)dequeueWithSliceMs:(int)ms {
    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:ms / 1000.0];
    [_cv lock];
    while (_pending.count == 0) {
        if (![_cv waitUntilDate:deadline]) { [_cv unlock]; return nil; }
    }
    NSDictionary* d = _pending.firstObject;
    [_pending removeObjectAtIndex:0];
    [_cv unlock];
    return d;
}

// ── Connect-state callbacks (forwarded to the matching PraiaBleConn) ──────
// Forward declarations of the methods we call on PraiaBleConn live below;
// this section just routes events from the central manager to the right Conn.

- (PraiaBleConn*)_connForPeripheral:(CBPeripheral*)p {
    [_cv lock];
    NSValue* v = _connByPeripheral[p.identifier.UUIDString];
    [_cv unlock];
    return v ? (PraiaBleConn*)[v nonretainedObjectValue] : nil;
}

- (void)centralManager:(CBCentralManager*)central
    didConnectPeripheral:(CBPeripheral*)peripheral {
    PraiaBleConn* c = [self _connForPeripheral:peripheral];
    if (c) [c _connectSucceeded];
}

- (void)centralManager:(CBCentralManager*)central
    didFailToConnectPeripheral:(CBPeripheral*)peripheral
                         error:(NSError*)error {
    PraiaBleConn* c = [self _connForPeripheral:peripheral];
    if (c) [c _connectFailedWithError:error];
}

- (void)centralManager:(CBCentralManager*)central
    didDisconnectPeripheral:(CBPeripheral*)peripheral
                      error:(NSError*)error {
    PraiaBleConn* c = [self _connForPeripheral:peripheral];
    if (c) [c _disconnectedWithError:error];
}

@end

@implementation PraiaBleConn {
    CBPeripheral*  _peripheral;
    __weak PraiaBleScanner* _scanner; // owns the central manager
    NSCondition*   _cv;

    // Connection state
    BOOL           _connected;
    BOOL           _connectFinished;
    NSError*       _connectError;
    BOOL           _disconnected;

    // Per-call state (single-threaded from the Praia side, so a flat slot
    // per kind of call is enough)
    BOOL           _svcDiscoveryDone;
    NSError*       _svcDiscoveryError;

    NSMutableSet<CBService*>* _charDiscoveryPending;
    NSError*       _charDiscoveryError;

    // Read result keyed by char UUID string. Each key is set when a value
    // arrives via didUpdateValue: while we're waiting for a read.
    NSMutableDictionary<NSString*, NSData*>* _readResults;
    NSMutableDictionary<NSString*, NSError*>* _readErrors;
    // True for chars whose value should be treated as a read-response on the
    // next didUpdateValue: callback. Otherwise, treat as notification.
    NSMutableSet<NSString*>* _pendingReads;

    NSMutableDictionary<NSString*, NSError*>* _writeErrors;
    NSMutableSet<NSString*>* _pendingWrites;

    NSMutableDictionary<NSString*, NSError*>* _notifyErrors;
    NSMutableSet<NSString*>* _pendingNotifyToggles;

    NSMutableArray<NSDictionary*>* _notifications; // {valueHandle, data}
}

- (instancetype)initWithPeripheral:(CBPeripheral*)p scanner:(PraiaBleScanner*)s {
    self = [super init];
    if (!self) return nil;
    _peripheral = p;
    _scanner = s;
    _cv = [[NSCondition alloc] init];
    _readResults  = [NSMutableDictionary dictionary];
    _readErrors   = [NSMutableDictionary dictionary];
    _pendingReads = [NSMutableSet set];
    _writeErrors  = [NSMutableDictionary dictionary];
    _pendingWrites = [NSMutableSet set];
    _notifyErrors = [NSMutableDictionary dictionary];
    _pendingNotifyToggles = [NSMutableSet set];
    _charDiscoveryPending = [NSMutableSet set];
    _notifications = [NSMutableArray array];
    _peripheral.delegate = self;
    return self;
}

// CB doesn't expose ATT handle ranges on CBService/CBCharacteristic in older
// SDKs; modern CB exposes a private property. Best practical lookup is by
// stable index in the discovered list. We expose helpers that walk
// peripheral.services / service.characteristics matching by an opaque
// "handle" we synthesise at discovery time.
//
// Strategy: handle == index in flattened (service, char-in-service) order +
// 1. We give callers `service.startHandle` = first index covering the
// service, `endHandle` = last. valueHandle == characteristic-index + 1.
// On macOS this index is stable across calls within a single connection, so
// it's a safe pseudo-handle for cross-platform parity with Linux's real ATT
// handles. Documented as "platform-specific opaque index" in main.praia.
- (NSDictionary*)_handleMap {
    NSMutableDictionary* m = [NSMutableDictionary dictionary];
    NSMutableArray* svcEntries = [NSMutableArray array];
    NSMutableArray* charEntries = [NSMutableArray array];
    uint16_t h = 1;
    for (CBService* s in _peripheral.services) {
        uint16_t sStart = h;
        h++;
        for (CBCharacteristic* c in s.characteristics) {
            // h is the declaration handle; valueHandle = declaration + 1.
            // Two-handles-per-char matches the layout the `characteristics`
            // registration synthesises, so lookups round-trip correctly.
            [charEntries addObject:@{
                @"valueHandle": @(static_cast<uint16_t>(h + 1)),
                @"char": c,
            }];
            h = static_cast<uint16_t>(h + 2);
        }
        uint16_t sEnd = static_cast<uint16_t>(h - 1);
        [svcEntries addObject:@{
            @"startHandle": @(sStart),
            @"endHandle":   @(sEnd),
            @"svc":         s,
        }];
    }
    m[@"services"] = svcEntries;
    m[@"characteristics"] = charEntries;
    return m;
}

- (CBService*)serviceByStartHandle:(uint16_t)startHandle endHandle:(uint16_t)endHandle {
    for (NSDictionary* e in [self _handleMap][@"services"]) {
        if ([e[@"startHandle"] unsignedShortValue] == startHandle) return e[@"svc"];
    }
    return nil;
}

- (CBCharacteristic*)characteristicByValueHandle:(uint16_t)vh {
    for (NSDictionary* e in [self _handleMap][@"characteristics"]) {
        if ([e[@"valueHandle"] unsignedShortValue] == vh) return e[@"char"];
    }
    return nil;
}

// ── Connect / Disconnect ─────────────────────────────────────────────────

- (BOOL)connectWithTimeoutMs:(int)timeoutMs error:(NSString**)err {
    PraiaBleScanner* s = _scanner;
    if (!s) { *err = @"scanner is no longer alive"; return NO; }
    [s attachConn:self forPeripheral:_peripheral];
    [_cv lock];
    _connectFinished = NO;
    _connectError = nil;
    [_cv unlock];
    [s.manager connectPeripheral:_peripheral options:nil];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while (!_connectFinished) {
        if (![_cv waitUntilDate:deadline]) {
            [_cv unlock];
            [s.manager cancelPeripheralConnection:_peripheral];
            [s detachConnForPeripheral:_peripheral];
            *err = @"connect timed out";
            return NO;
        }
    }
    BOOL ok = _connected;
    NSError* connErr = _connectError;
    [_cv unlock];
    if (!ok) {
        [s detachConnForPeripheral:_peripheral];
        *err = connErr ? connErr.localizedDescription : @"connect failed";
        return NO;
    }
    return YES;
}

- (void)disconnect {
    PraiaBleScanner* s = _scanner;
    if (s && _peripheral) {
        [s.manager cancelPeripheralConnection:_peripheral];
        [s detachConnForPeripheral:_peripheral];
    }
}

- (void)_connectSucceeded {
    [_cv lock];
    _connected = YES;
    _connectFinished = YES;
    [_cv broadcast];
    [_cv unlock];
}

- (void)_connectFailedWithError:(NSError*)error {
    [_cv lock];
    _connected = NO;
    _connectError = error;
    _connectFinished = YES;
    [_cv broadcast];
    [_cv unlock];
}

- (void)_disconnectedWithError:(NSError*)error {
    [_cv lock];
    _disconnected = YES;
    [_cv broadcast];
    [_cv unlock];
}

// ── Service discovery ─────────────────────────────────────────────────────

- (NSArray<CBService*>*)discoverServicesWithTimeoutMs:(int)timeoutMs error:(NSString**)err {
    [_cv lock];
    _svcDiscoveryDone = NO;
    _svcDiscoveryError = nil;
    [_cv unlock];
    [_peripheral discoverServices:nil];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while (!_svcDiscoveryDone) {
        if (![_cv waitUntilDate:deadline]) {
            [_cv unlock]; *err = @"discoverServices timed out"; return nil;
        }
    }
    NSError* e = _svcDiscoveryError;
    [_cv unlock];
    if (e) { *err = e.localizedDescription; return nil; }
    return _peripheral.services ?: @[];
}

- (void)peripheral:(CBPeripheral*)peripheral didDiscoverServices:(NSError*)error {
    [_cv lock];
    _svcDiscoveryError = error;
    _svcDiscoveryDone = YES;
    [_cv broadcast];
    [_cv unlock];
}

// ── Characteristic discovery ─────────────────────────────────────────────

- (NSArray<CBCharacteristic*>*)discoverCharacteristicsForService:(CBService*)svc
                                                      timeoutMs:(int)timeoutMs
                                                          error:(NSString**)err {
    [_cv lock];
    [_charDiscoveryPending addObject:svc];
    _charDiscoveryError = nil;
    [_cv unlock];
    [_peripheral discoverCharacteristics:nil forService:svc];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while ([_charDiscoveryPending containsObject:svc]) {
        if (![_cv waitUntilDate:deadline]) {
            [_charDiscoveryPending removeObject:svc];
            [_cv unlock]; *err = @"discoverCharacteristics timed out"; return nil;
        }
    }
    NSError* e = _charDiscoveryError;
    [_cv unlock];
    if (e) { *err = e.localizedDescription; return nil; }
    return svc.characteristics ?: @[];
}

- (void)peripheral:(CBPeripheral*)peripheral
    didDiscoverCharacteristicsForService:(CBService*)service
                                   error:(NSError*)error {
    [_cv lock];
    [_charDiscoveryPending removeObject:service];
    _charDiscoveryError = error;
    [_cv broadcast];
    [_cv unlock];
}

// ── Read ─────────────────────────────────────────────────────────────────

- (NSData*)readValueForCharacteristic:(CBCharacteristic*)ch
                            timeoutMs:(int)timeoutMs
                                error:(NSString**)err {
    NSString* key = ch.UUID.UUIDString;
    [_cv lock];
    [_pendingReads addObject:key];
    [_readResults removeObjectForKey:key];
    [_readErrors removeObjectForKey:key];
    [_cv unlock];

    [_peripheral readValueForCharacteristic:ch];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while ([_pendingReads containsObject:key]) {
        if (![_cv waitUntilDate:deadline]) {
            [_pendingReads removeObject:key];
            [_cv unlock]; *err = @"read timed out"; return nil;
        }
    }
    NSData* d = _readResults[key];
    NSError* e = _readErrors[key];
    [_readResults removeObjectForKey:key];
    [_readErrors removeObjectForKey:key];
    [_cv unlock];
    if (e) { *err = e.localizedDescription; return nil; }
    return d ?: [NSData data];
}

- (void)peripheral:(CBPeripheral*)peripheral
    didUpdateValueForCharacteristic:(CBCharacteristic*)ch
                              error:(NSError*)error {
    NSString* key = ch.UUID.UUIDString;
    [_cv lock];
    if ([_pendingReads containsObject:key]) {
        // Response to a pending read
        if (error) _readErrors[key] = error;
        else if (ch.value) _readResults[key] = ch.value;
        else _readResults[key] = [NSData data];
        [_pendingReads removeObject:key];
        [_cv broadcast];
    } else {
        // Notification (or indication — CB merges them)
        // Look up valueHandle for this char from our pseudo-handle map.
        uint16_t vh = 0;
        for (NSDictionary* e in [self _handleMap][@"characteristics"]) {
            if ([(CBCharacteristic*)e[@"char"] isEqual:ch]) {
                vh = [e[@"valueHandle"] unsignedShortValue];
                break;
            }
        }
        NSDictionary* note = @{
            @"valueHandle": @(vh),
            @"data": ch.value ?: [NSData data],
        };
        [_notifications addObject:note];
        [_cv broadcast];
    }
    [_cv unlock];
}

// ── Write ────────────────────────────────────────────────────────────────

- (BOOL)writeValue:(NSData*)data
 forCharacteristic:(CBCharacteristic*)ch
      withResponse:(BOOL)withResp
         timeoutMs:(int)timeoutMs
             error:(NSString**)err {
    if (!withResp) {
        [_peripheral writeValue:data forCharacteristic:ch
                           type:CBCharacteristicWriteWithoutResponse];
        return YES;
    }
    NSString* key = ch.UUID.UUIDString;
    [_cv lock];
    [_pendingWrites addObject:key];
    [_writeErrors removeObjectForKey:key];
    [_cv unlock];
    [_peripheral writeValue:data forCharacteristic:ch
                       type:CBCharacteristicWriteWithResponse];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while ([_pendingWrites containsObject:key]) {
        if (![_cv waitUntilDate:deadline]) {
            [_pendingWrites removeObject:key];
            [_cv unlock]; *err = @"write timed out"; return NO;
        }
    }
    NSError* e = _writeErrors[key];
    [_writeErrors removeObjectForKey:key];
    [_cv unlock];
    if (e) { *err = e.localizedDescription; return NO; }
    return YES;
}

- (void)peripheral:(CBPeripheral*)peripheral
    didWriteValueForCharacteristic:(CBCharacteristic*)ch
                             error:(NSError*)error {
    NSString* key = ch.UUID.UUIDString;
    [_cv lock];
    if (error) _writeErrors[key] = error;
    [_pendingWrites removeObject:key];
    [_cv broadcast];
    [_cv unlock];
}

// ── Notify (subscribe) ───────────────────────────────────────────────────

- (BOOL)setNotify:(BOOL)enable
forCharacteristic:(CBCharacteristic*)ch
        timeoutMs:(int)timeoutMs
            error:(NSString**)err {
    NSString* key = ch.UUID.UUIDString;
    [_cv lock];
    [_pendingNotifyToggles addObject:key];
    [_notifyErrors removeObjectForKey:key];
    [_cv unlock];
    [_peripheral setNotifyValue:enable forCharacteristic:ch];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutMs / 1000.0];
    [_cv lock];
    while ([_pendingNotifyToggles containsObject:key]) {
        if (![_cv waitUntilDate:deadline]) {
            [_pendingNotifyToggles removeObject:key];
            [_cv unlock]; *err = @"setNotify timed out"; return NO;
        }
    }
    NSError* e = _notifyErrors[key];
    [_notifyErrors removeObjectForKey:key];
    [_cv unlock];
    if (e) { *err = e.localizedDescription; return NO; }
    return YES;
}

- (void)peripheral:(CBPeripheral*)peripheral
    didUpdateNotificationStateForCharacteristic:(CBCharacteristic*)ch
                                          error:(NSError*)error {
    NSString* key = ch.UUID.UUIDString;
    [_cv lock];
    if (error) _notifyErrors[key] = error;
    [_pendingNotifyToggles removeObject:key];
    [_cv broadcast];
    [_cv unlock];
}

- (NSDictionary*)nextNotificationWithSliceMs:(int)ms {
    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:ms / 1000.0];
    [_cv lock];
    while (_notifications.count == 0) {
        if (![_cv waitUntilDate:deadline]) { [_cv unlock]; return nil; }
    }
    NSDictionary* d = _notifications.firstObject;
    [_notifications removeObjectAtIndex:0];
    [_cv unlock];
    return d;
}

@end

// ── Handle tables ─────────────────────────────────────────────────────────

struct MacBleHandle {
    void* scanner;   // (__bridge_retained PraiaBleScanner*)
    bool  scanning;
};

struct MacGattHandle {
    void* conn;      // (__bridge_retained PraiaBleConn*)
};

static std::unordered_map<int64_t, MacBleHandle> handles;
static std::unordered_map<int64_t, MacGattHandle> gattHandles;
static int64_t nextId = 1;
static int64_t nextGattId = 1;

// Process-exit hook — stop scans and release the __bridge_retained
// scanner / connection ObjC pointers so CoreBluetooth tears down
// cleanly and the next process doesn't inherit a half-initialised
// central manager. Releasing the retained reference drops the ARC
// hold; CoreBluetooth's own callback registrations expire with the
// scanner.
extern "C" void praia_at_exit(void) {
    @autoreleasepool {
        for (auto& [id, h] : handles) {
            if (h.scanner) {
                PraiaBleScanner* s = (__bridge_transfer PraiaBleScanner*)h.scanner;
                if (h.scanning) [s stopScan];
                (void)s; // ARC releases at autoreleasepool end
                h.scanner = nullptr;
            }
        }
        for (auto& [id, g] : gattHandles) {
            if (g.conn) {
                PraiaBleConn* c = (__bridge_transfer PraiaBleConn*)g.conn;
                (void)c;
                g.conn = nullptr;
            }
        }
    }
    handles.clear();
    gattHandles.clear();
}

// Find a peripheral with the given UUID across all open scanners. Returns
// (peripheral, scanner) on success, both nil otherwise. Used by ble.connect
// to bridge between the scan side (which discovered the peripheral) and the
// GATT side (which needs the peripheral + the scanner's central manager).
static std::pair<CBPeripheral*, PraiaBleScanner*> lookupPeripheral(NSString* uuid) {
    for (auto& kv : handles) {
        PraiaBleScanner* s = (__bridge PraiaBleScanner*)kv.second.scanner;
        CBPeripheral* p = [s peripheralForUUID:uuid];
        if (p) return {p, s};
    }
    return {nil, nil};
}

// ── Plugin registration ────────────────────────────────────────────────────

extern "C" void praia_register(PraiaMap* module) {
    // ble.open(adapterIndex?, opts?) -> handle
    // adapterIndex is ignored on macOS (CoreBluetooth uses the system default
    // adapter). opts.exclusive is also ignored — CoreBluetooth doesn't have
    // a non-exclusive concept.
    module->entries["open"] = Value(makeNative("ble.open", -1,
        [](const std::vector<Value>&) -> Value {
            @autoreleasepool {
                PraiaBleScanner* s = [[PraiaBleScanner alloc] init];
                NSString* err = nil;
                if (![s waitForPoweredOn:5000 error:&err]) {
                    throw RuntimeError(std::string("ble.open(): ") +
                        (err ? [err UTF8String] : "init failed"), 0);
                }
                int64_t id = nextId++;
                handles[id] = MacBleHandle{(__bridge_retained void*)s, false};
                return Value(id);
            }
        }));

    // ble.startScan(handle, opts?) -> nil
    // opts: {filterDup: bool}. Other Linux opts (active, intervalMs, windowMs)
    // are ignored — CoreBluetooth controls those internally.
    module->entries["startScan"] = Value(makeNative("ble.startScan", -1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (args.empty() || !args[0].isInt())
                    throw RuntimeError("ble.startScan() requires handle", 0);
                auto it = handles.find(args[0].asInt());
                if (it == handles.end())
                    throw RuntimeError("ble.startScan(): invalid handle", 0);

                bool filterDup = false;
                if (args.size() > 1 && args[1].isMap()) {
                    auto opts = args[1].asMap();
                    auto k = opts->entries.find(Value(std::string("filterDup")));
                    if (k != opts->entries.end() && k->second.isBool())
                        filterDup = k->second.asBool();
                }

                PraiaBleScanner* s = (__bridge PraiaBleScanner*)it->second.scanner;
                [s startScanAllowingDuplicates:filterDup ? NO : YES];
                it->second.scanning = true;
                return Value();
            }
        }));

    // ble.nextEvent(handle, timeoutMs?) -> map | nil
    // Returns the next discovery event, blocking up to timeoutMs (default
    // 1000). Returns nil on timeout. Throws "Interrupted" on Ctrl+C.
    // Polls in 200ms slices so SIGINT can interrupt within that window.
    module->entries["nextEvent"] = Value(makeNative("ble.nextEvent", -1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (args.empty() || !args[0].isInt())
                    throw RuntimeError("ble.nextEvent() requires handle", 0);
                auto it = handles.find(args[0].asInt());
                if (it == handles.end())
                    throw RuntimeError("ble.nextEvent(): invalid handle", 0);
                int timeoutMs = 1000;
                if (args.size() > 1 && args[1].isNumber())
                    timeoutMs = static_cast<int>(args[1].asNumber());

                PraiaBleScanner* s = (__bridge PraiaBleScanner*)it->second.scanner;

                auto deadline = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(timeoutMs);
                while (true) {
                    checkInterrupted();
                    // Cooperative cancellation — inside a withCancel
                    // scope, treat token-cancelled as an early
                    // timeout so the surrounding loop can poll and
                    // bail. Symmetric with the SIGINT check above.
                    auto cancelled = praia::shouldCancel();
                    if (cancelled && *cancelled) return Value();
                    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now()).count();
                    if (rem <= 0) return Value();
                    int slice = static_cast<int>(std::min<int64_t>(rem, 200));
                    NSDictionary* d = [s dequeueWithSliceMs:slice];
                    if (d) return nsDictToMap(d);
                }
            }
        }));

    // ble.stopScan(handle) -> nil
    module->entries["stopScan"] = Value(makeNative("ble.stopScan", 1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt())
                    throw RuntimeError("ble.stopScan() requires handle", 0);
                auto it = handles.find(args[0].asInt());
                if (it == handles.end()) return Value();
                if (it->second.scanning) {
                    PraiaBleScanner* s = (__bridge PraiaBleScanner*)it->second.scanner;
                    [s stopScan];
                    it->second.scanning = false;
                }
                return Value();
            }
        }));

    // ble.close(handle) -> nil
    module->entries["close"] = Value(makeNative("ble.close", 1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt())
                    throw RuntimeError("ble.close() requires handle", 0);
                auto it = handles.find(args[0].asInt());
                if (it == handles.end()) return Value();
                if (it->second.scanning) {
                    PraiaBleScanner* s = (__bridge PraiaBleScanner*)it->second.scanner;
                    [s stopScan];
                    it->second.scanning = false;
                }
                // Transfer ownership back to ARC so the scanner is released
                // when the @autoreleasepool drains.
                __unused PraiaBleScanner* released =
                    (__bridge_transfer PraiaBleScanner*)it->second.scanner;
                handles.erase(it);
                return Value();
            }
        }));

    // ble.parseAd(bytes) -> map
    // Available on macOS too even though CoreBluetooth doesn't give us raw
    // bytes — useful if a caller has AD bytes from elsewhere.
    module->entries["parseAd"] = Value(makeNative("ble.parseAd", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isString())
                throw RuntimeError("ble.parseAd() requires data", 0);
            const auto& s = args[0].asString();
            return ble_parseAdImpl(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        }));

    // ble.capabilities() -> map describing what the platform supports
    module->entries["capabilities"] = Value(makeNative("ble.capabilities", 0,
        [](const std::vector<Value>&) -> Value {
            auto m = gcNew<PraiaMap>();
            m->entries["platform"]      = Value(std::string("darwin"));
            m->entries["realAddress"]   = Value(false); // anonymized NSUUID
            m->entries["rawPackets"]    = Value(false); // CB hides raw bytes
            m->entries["selectAdapter"] = Value(false); // CB picks default
            m->entries["activeScan"]    = Value(false); // CB controls scan params
            m->entries["gatt"]          = Value(true);  // CB GATT (connect/r/w/n)
            return Value(m);
        }));

    // ── GATT (Phase 3) ─────────────────────────────────────────────────────
    // Connect requires that ble.open() has been called and a recent scan has
    // populated the peripheral cache (or that the peripheral is already
    // connected/known to the system). The session handle isn't passed
    // explicitly — connect walks all open scanners' caches looking for the
    // address.
    //
    // Pseudo-handles: macOS's CB does not expose ATT handles. For
    // cross-platform parity we synthesise stable per-connection indices for
    // services and characteristics. They're integers like Linux handles, but
    // are NOT real ATT handles — they index into peripheral.services and
    // service.characteristics in discovery order.

    module->entries["connect"] = Value(makeNative("ble.connect", -1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (args.empty() || !args[0].isString())
                    throw RuntimeError("ble.connect(address, opts?) requires address string", 0);
                int timeoutMs = 10000;
                if (args.size() > 1 && args[1].isMap()) {
                    auto opts = args[1].asMap();
                    auto k = opts->entries.find(Value(std::string("timeoutMs")));
                    if (k != opts->entries.end() && k->second.isNumber())
                        timeoutMs = static_cast<int>(k->second.asNumber());
                }
                NSString* uuid = [NSString stringWithUTF8String:args[0].asString().c_str()];
                auto [p, s] = lookupPeripheral(uuid);
                if (!p) throw RuntimeError(
                    std::string("ble.connect(): no peripheral with UUID ") +
                    args[0].asString() +
                    " in any open scanner cache (call ble.open() and scan first)", 0);

                PraiaBleConn* c = [[PraiaBleConn alloc] initWithPeripheral:p scanner:s];
                NSString* err = nil;
                if (![c connectWithTimeoutMs:timeoutMs error:&err])
                    throw RuntimeError(std::string("ble.connect(): ") +
                        (err ? [err UTF8String] : "failed"), 0);

                int64_t id = nextGattId++;
                gattHandles[id] = MacGattHandle{(__bridge_retained void*)c};
                return Value(id);
            }
        }));

    module->entries["disconnect"] = Value(makeNative("ble.disconnect", 1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt())
                    throw RuntimeError("ble.disconnect() requires conn handle", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end()) return Value();
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                [c disconnect];
                __unused PraiaBleConn* released =
                    (__bridge_transfer PraiaBleConn*)it->second.conn;
                gattHandles.erase(it);
                return Value();
            }
        }));

    module->entries["services"] = Value(makeNative("ble.services", 1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt())
                    throw RuntimeError("ble.services() requires conn handle", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.services(): invalid conn handle", 0);
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                NSString* err = nil;
                NSArray<CBService*>* svcs = [c discoverServicesWithTimeoutMs:5000 error:&err];
                if (err) throw RuntimeError(std::string("ble.services(): ") + [err UTF8String], 0);

                auto arr = gcNew<PraiaArray>();
                uint16_t h = 1;
                for (CBService* s in svcs) {
                    uint16_t sStart = h;
                    h++;
                    // Pre-discover characteristics so endHandle is meaningful;
                    // CB requires explicit discoverCharacteristics anyway.
                    [c discoverCharacteristicsForService:s timeoutMs:5000 error:&err];
                    if (err) throw RuntimeError(std::string("ble.services(): ") + [err UTF8String], 0);
                    h += static_cast<uint16_t>(s.characteristics.count * 2);
                    uint16_t sEnd = static_cast<uint16_t>(h - 1);
                    auto m = gcNew<PraiaMap>();
                    m->entries["uuid"]        = Value(std::string([s.UUID.UUIDString UTF8String]));
                    m->entries["startHandle"] = Value(static_cast<int64_t>(sStart));
                    m->entries["endHandle"]   = Value(static_cast<int64_t>(sEnd));
                    arr->elements.push_back(Value(m));
                }
                return Value(arr);
            }
        }));

    module->entries["characteristics"] = Value(makeNative("ble.characteristics", 3,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt() || !args[1].isInt() || !args[2].isInt())
                    throw RuntimeError("ble.characteristics(conn, startHandle, endHandle)", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.characteristics(): invalid conn handle", 0);
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                CBService* svc = [c serviceByStartHandle:(uint16_t)args[1].asInt()
                                              endHandle:(uint16_t)args[2].asInt()];
                if (!svc) throw RuntimeError("ble.characteristics(): no service at those handles", 0);

                auto arr = gcNew<PraiaArray>();
                // Walk service characteristics in stable order. valueHandle
                // synthesised matches what serviceByStartHandle produced.
                uint16_t startH = (uint16_t)args[1].asInt();
                uint16_t cur = static_cast<uint16_t>(startH + 1);
                for (CBCharacteristic* ch in svc.characteristics) {
                    uint16_t decl = cur;
                    uint16_t vh   = static_cast<uint16_t>(cur + 1);
                    cur = static_cast<uint16_t>(cur + 2);
                    auto m = gcNew<PraiaMap>();
                    m->entries["uuid"]        = Value(std::string([ch.UUID.UUIDString UTF8String]));
                    m->entries["handle"]      = Value(static_cast<int64_t>(decl));
                    m->entries["valueHandle"] = Value(static_cast<int64_t>(vh));
                    auto props = gcNew<PraiaMap>();
                    CBCharacteristicProperties p = ch.properties;
                    props->entries["broadcast"]   = Value((bool)(p & CBCharacteristicPropertyBroadcast));
                    props->entries["read"]        = Value((bool)(p & CBCharacteristicPropertyRead));
                    props->entries["writeNoResp"] = Value((bool)(p & CBCharacteristicPropertyWriteWithoutResponse));
                    props->entries["write"]       = Value((bool)(p & CBCharacteristicPropertyWrite));
                    props->entries["notify"]      = Value((bool)(p & CBCharacteristicPropertyNotify));
                    props->entries["indicate"]    = Value((bool)(p & CBCharacteristicPropertyIndicate));
                    props->entries["signedWrite"] = Value((bool)(p & CBCharacteristicPropertyAuthenticatedSignedWrites));
                    m->entries["props"] = Value(props);
                    arr->elements.push_back(Value(m));
                }
                return Value(arr);
            }
        }));

    module->entries["read"] = Value(makeNative("ble.read", 2,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt() || !args[1].isInt())
                    throw RuntimeError("ble.read(conn, valueHandle)", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.read(): invalid conn handle", 0);
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                CBCharacteristic* ch = [c characteristicByValueHandle:(uint16_t)args[1].asInt()];
                if (!ch) throw RuntimeError("ble.read(): no characteristic at that valueHandle", 0);
                NSString* err = nil;
                NSData* d = [c readValueForCharacteristic:ch timeoutMs:5000 error:&err];
                if (err) throw RuntimeError(std::string("ble.read(): ") + [err UTF8String], 0);
                return Value(std::string(static_cast<const char*>(d.bytes), d.length));
            }
        }));

    module->entries["write"] = Value(makeNative("ble.write", -1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (args.size() < 3 || !args[0].isInt() || !args[1].isInt() || !args[2].isString())
                    throw RuntimeError("ble.write(conn, valueHandle, data, withResponse?)", 0);
                bool withResp = true;
                if (args.size() > 3 && args[3].isBool()) withResp = args[3].asBool();
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.write(): invalid conn handle", 0);
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                CBCharacteristic* ch = [c characteristicByValueHandle:(uint16_t)args[1].asInt()];
                if (!ch) throw RuntimeError("ble.write(): no characteristic at that valueHandle", 0);
                const auto& s = args[2].asString();
                NSData* data = [NSData dataWithBytes:s.data() length:s.size()];
                NSString* err = nil;
                if (![c writeValue:data forCharacteristic:ch withResponse:withResp
                         timeoutMs:5000 error:&err]) {
                    throw RuntimeError(std::string("ble.write(): ") +
                        (err ? [err UTF8String] : "failed"), 0);
                }
                return Value();
            }
        }));

    // ble.subscribe(conn, valueHandle, scanEndHandle?) -> 0 (CCCD handle is
    // not used on macOS — CB manages it internally — but the function exists
    // for cross-platform parity and returns the value handle as a stand-in.)
    module->entries["subscribe"] = Value(makeNative("ble.subscribe", -1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (args.size() < 2 || !args[0].isInt() || !args[1].isInt())
                    throw RuntimeError("ble.subscribe(conn, valueHandle, scanEndHandle?)", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.subscribe(): invalid conn handle", 0);
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                CBCharacteristic* ch = [c characteristicByValueHandle:(uint16_t)args[1].asInt()];
                if (!ch) throw RuntimeError("ble.subscribe(): no characteristic at that valueHandle", 0);
                NSString* err = nil;
                if (![c setNotify:YES forCharacteristic:ch timeoutMs:5000 error:&err])
                    throw RuntimeError(std::string("ble.subscribe(): ") +
                        (err ? [err UTF8String] : "failed"), 0);
                return Value(args[1].asInt()); // pseudo-CCCD handle == valueHandle
            }
        }));

    module->entries["unsubscribe"] = Value(makeNative("ble.unsubscribe", 2,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (!args[0].isInt() || !args[1].isInt())
                    throw RuntimeError("ble.unsubscribe(conn, cccdHandle)", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.unsubscribe(): invalid conn handle", 0);
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;
                // On macOS the cccdHandle slot was the valueHandle (see
                // subscribe), so we just disable notify on the same char.
                CBCharacteristic* ch = [c characteristicByValueHandle:(uint16_t)args[1].asInt()];
                if (!ch) return Value();
                NSString* err = nil;
                [c setNotify:NO forCharacteristic:ch timeoutMs:5000 error:&err];
                return Value();
            }
        }));

    module->entries["nextNotification"] = Value(makeNative("ble.nextNotification", -1,
        [](const std::vector<Value>& args) -> Value {
            @autoreleasepool {
                if (args.empty() || !args[0].isInt())
                    throw RuntimeError("ble.nextNotification(conn, timeoutMs?)", 0);
                auto it = gattHandles.find(args[0].asInt());
                if (it == gattHandles.end())
                    throw RuntimeError("ble.nextNotification(): invalid conn handle", 0);
                int timeoutMs = 1000;
                if (args.size() > 1 && args[1].isNumber())
                    timeoutMs = static_cast<int>(args[1].asNumber());
                PraiaBleConn* c = (__bridge PraiaBleConn*)it->second.conn;

                auto deadline = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(timeoutMs);
                while (true) {
                    checkInterrupted();
                    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now()).count();
                    if (rem <= 0) return Value();
                    int slice = static_cast<int>(std::min<int64_t>(rem, 200));
                    NSDictionary* d = [c nextNotificationWithSliceMs:slice];
                    if (d) return nsDictToMap(d);
                }
            }
        }));
}
