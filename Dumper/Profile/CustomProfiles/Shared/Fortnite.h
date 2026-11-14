// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
// Fortnite Mobile — Android v43.10.0-60118918
// libUnreal.so (IDA analysis)
//
// GUObjectArray  : offset 0x19EEE6E8
// GObjects ptr   : encrypted at GUObjectArray+0x89148 (qword_1A077730)
//   decrypt      : (0x014A7AF1 ^ ROR64(raw, 38)) * 0xFCF860ABC8EC0E17
// NumElements    : encrypted at GUObjectArray+0x89150 (dword_1A077738)
//   decrypt      : (0x1130A328 ^ ROR32(raw, 5)) * 0x6977DD63 + 0xFC3B1B46
// ObjectItemSize : 0x18
// NamePool       : offset 0x19F34600
//   Blocks offset: 0xAB80
//   Len          : (header >> 6) ^ 0x3CB
//   Wide         : header & 1
//   String       : NameEntry + 2, stride 2
//
// NOTE: re-derive EOR constants and offsets after every Fortnite update.

#pragma once
#include "../../IProfile.h"

class FortniteProfile : public IProfile
{
public:
    FortniteProfile() = default;

    std::vector<std::string> GetSupportedGames() const override
    {
        return {"com.epicgames.fortnite"};
    }

    // GUObjectArray — "unable to add more objects" is stripped; hand it directly.
    uintptr_t GetGObjects() const override
    {
        return MD7::Globals::GMemory->GetUnrealModule().GetBase() + 0x19EEE6E8;
    }

    // NamePool — normal anchors stripped; hand it directly.
    uintptr_t GetGNames() const override
    {
        return MD7::Globals::GMemory->GetUnrealModule().GetBase() + 0x19F34600;
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // Objects chunk pointer decrypt
        // EOR X8, 0x014A7AF1, X8,ROR#38  then MUL by 0xFCF860ABC8EC0E17
        // from VERIFYGC @ 0xC67F0DC / 0xC67F0F0
        Callbacks.ChunkedObjects.Objects = [](const FDecryptContext<uintptr_t>& Ctx) -> uintptr_t
        {
            uint64_t v = static_cast<uint64_t>(Ctx.Value);
            v = (v >> 38) | (v << (64 - 38));  // ROR64(v, 38)
            return static_cast<uintptr_t>((0x014A7AF1ULL ^ v) * 0xFCF860ABC8EC0E17ULL);
        };

        // NumElements decrypt
        // EOR W8, 0x1130A328, W8,ROR#5  then MADD W8, W8, 0x6977DD63, 0xFC3B1B46
        // from VERIFYGC @ 0xC67F094 / 0xC67F0A8
        Callbacks.ChunkedObjects.NumElements = [](const FDecryptContext<int32_t>& Ctx) -> int32_t
        {
            uint32_t v = static_cast<uint32_t>(Ctx.Value);
            v = (v >> 5) | (v << (32 - 5));    // ROR32(v, 5)
            v = (0x1130A328u ^ v) * 0x6977DD63u + 0xFC3B1B46u;
            return static_cast<int32_t>(v);
        };
    }
};
