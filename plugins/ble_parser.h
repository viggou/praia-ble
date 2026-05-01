// AD-record parser shared between the Linux (raw HCI) and macOS
// (CoreBluetooth) backends. Per Core Spec Vol 3 Part C §11.
//
// Header-only with static inline functions: each plugin compilation unit
// gets its own copy, but only one plugin is built per platform, so there's
// no ODR concern.

#pragma once

#include "praia_plugin.h"

#include <cstdint>
#include <cstdio>
#include <string>

static inline std::string ble_uuidFromLE(const uint8_t* b, size_t len) {
    char buf[64];
    if (len == 2) {
        snprintf(buf, sizeof(buf), "%04X", b[0] | (b[1] << 8));
    } else if (len == 4) {
        snprintf(buf, sizeof(buf), "%08X",
                 static_cast<unsigned>(b[0]) | (static_cast<unsigned>(b[1]) << 8) |
                 (static_cast<unsigned>(b[2]) << 16) | (static_cast<unsigned>(b[3]) << 24));
    } else if (len == 16) {
        snprintf(buf, sizeof(buf),
                 "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 b[15], b[14], b[13], b[12],
                 b[11], b[10], b[9], b[8],
                 b[7], b[6],
                 b[5], b[4], b[3], b[2], b[1], b[0]);
    } else {
        snprintf(buf, sizeof(buf), "<bad-uuid-len=%zu>", len);
    }
    return std::string(buf);
}

static inline Value ble_parseAdImpl(const uint8_t* data, size_t len) {
    auto m = gcNew<PraiaMap>();
    auto services = gcNew<PraiaArray>();

    size_t pos = 0;
    while (pos < len) {
        uint8_t adLen = data[pos++];
        if (adLen == 0) continue; // padding
        if (pos + adLen > len) break;
        uint8_t adType = data[pos];
        const uint8_t* adData = data + pos + 1;
        size_t adDataLen = adLen - 1;
        pos += adLen;

        switch (adType) {
            case 0x01: // Flags
                if (adDataLen >= 1)
                    m->entries["flags"] = Value(static_cast<int64_t>(adData[0]));
                break;
            case 0x02: case 0x03: // Incomplete/Complete 16-bit Service UUIDs
                for (size_t i = 0; i + 2 <= adDataLen; i += 2)
                    services->elements.push_back(Value(ble_uuidFromLE(adData + i, 2)));
                break;
            case 0x04: case 0x05: // 32-bit
                for (size_t i = 0; i + 4 <= adDataLen; i += 4)
                    services->elements.push_back(Value(ble_uuidFromLE(adData + i, 4)));
                break;
            case 0x06: case 0x07: // 128-bit
                for (size_t i = 0; i + 16 <= adDataLen; i += 16)
                    services->elements.push_back(Value(ble_uuidFromLE(adData + i, 16)));
                break;
            case 0x08: case 0x09: // Shortened/Complete Local Name
                m->entries["name"] = Value(std::string(
                    reinterpret_cast<const char*>(adData), adDataLen));
                break;
            case 0x0A: // TX Power Level
                if (adDataLen >= 1)
                    m->entries["txPower"] = Value(static_cast<int64_t>(static_cast<int8_t>(adData[0])));
                break;
            case 0x16: { // Service Data — 16-bit UUID
                if (adDataLen >= 2) {
                    auto sd = gcNew<PraiaMap>();
                    sd->entries["uuid"] = Value(ble_uuidFromLE(adData, 2));
                    sd->entries["data"] = Value(std::string(
                        reinterpret_cast<const char*>(adData + 2), adDataLen - 2));
                    m->entries["serviceData"] = Value(sd);
                }
                break;
            }
            case 0x19: // Appearance
                if (adDataLen >= 2)
                    m->entries["appearance"] = Value(static_cast<int64_t>(adData[0] | (adData[1] << 8)));
                break;
            case 0xFF: { // Manufacturer Specific Data
                if (adDataLen >= 2) {
                    auto md = gcNew<PraiaMap>();
                    md->entries["companyId"] = Value(static_cast<int64_t>(adData[0] | (adData[1] << 8)));
                    md->entries["data"] = Value(std::string(
                        reinterpret_cast<const char*>(adData + 2), adDataLen - 2));
                    m->entries["manufacturerData"] = Value(md);
                }
                break;
            }
            default:
                break;
        }
    }
    if (!services->elements.empty())
        m->entries["services"] = Value(services);
    return Value(m);
}
