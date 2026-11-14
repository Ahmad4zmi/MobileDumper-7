// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
// Fortnite Mobile — Android v43.10.0-60118918
// libUnreal.so (IDA analysis)
//
// GUObjectArray  : offset 0x19EEE6E8  (qword_19EEE6E8, `this` in VERIFYGC @ 0xC67F02C)
// GObjects ptr   : encrypted at GUObjectArray+0x89148 (qword_1A077730)
//   decrypt      : (0x014A7AF1 ^ ROR64(raw, 38)) * 0xFCF860ABC8EC0E17
// NumElements    : encrypted at GUObjectArray+0x89150 (dword_1A077738)
//   decrypt      : (0x1130A328 ^ ROR32(raw, 5)) * 0x6977DD63 + 0xFC3B1B46
// ObjectItemSize : 0x18
// NamePool       : offset 0x19F34600  (dword_19F34600, ADRL X20 @ 0x66B2398)
//   Blocks offset: 0xAB80  (MOV W9, #0xAB80 @ 0x66B23C0)
//   Len          : (header >> 6) ^ 0x3CB
//   Wide         : header & 1
//   String       : NameEntry + 2, stride 2
//
// NOTE: Epic re-keys obfuscation constants every update. After any patch
//       re-derive the EOR constants and global offsets before rebuilding.

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

    // -------------------------------------------------------------------------
    // GUObjectArray — stripped "unable to add more objects", hand it directly.
    // GetGObjects() must return the absolute runtime address of the array struct.
    // -------------------------------------------------------------------------
    uintptr_t GetGObjects() const override
    {
        return GMemory->GetUnrealModule().GetBase() + 0x19EEE6E8;
    }

    // Decrypt the Objects chunk-array pointer.
    // Pattern from VERIFYGC @ 0xC67F0DC:
    //   EOR X8, 0x014A7AF1, X8,ROR#38
    //   MUL X8, X8, 0xFCF860ABC8EC0E17
    void DecryptGObjects(uintptr_t& Value) const override
    {
        uint64_t v = static_cast<uint64_t>(Value);
        v = (v >> 38) | (v << (64 - 38));          // ROR64(v, 38)
        Value = static_cast<uintptr_t>((0x014A7AF1ULL ^ v) * 0xFCF860ABC8EC0E17ULL);
    }

    // -------------------------------------------------------------------------
    // NamePool — stripped normal anchors, hand it directly.
    // -------------------------------------------------------------------------
    uintptr_t GetGNames() const override
    {
        return GMemory->GetUnrealModule().GetBase() + 0x19F34600;
    }

    // OverrideDecryptCallbacks — NumElements encryption lives here.
    // Pattern from VERIFYGC @ 0xC67F094 / 0xC67F0A8:
    //   EOR W8, 0x1130A328, W8,ROR#5
    //   MADD W8, W8, 0x6977DD63, 0xFC3B1B46
    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        Callbacks.ChunkedObjects.NumElements = [](int32_t Value, uintptr_t) -> int32_t
        {
            uint32_t v = static_cast<uint32_t>(Value);
            v = (v >> 5) | (v << (32 - 5));        // ROR32(v, 5)
            v = (0x1130A328u ^ v) * 0x6977DD63u + 0xFC3B1B46u;
            return static_cast<int32_t>(v);
        };

        // Objects pointer decrypt is already in DecryptGObjects above;
        // only needed here if the auto-path calls this callback instead.
        // Uncomment if names or objects come back empty:
        //
        // Callbacks.ChunkedObjects.Objects = [](uintptr_t Value, uintptr_t) -> uintptr_t
        // {
        //     uint64_t v = static_cast<uint64_t>(Value);
        //     v = (v >> 38) | (v << (64 - 38));
        //     return static_cast<uintptr_t>((0x014A7AF1ULL ^ v) * 0xFCF860ABC8EC0E17ULL);
        // };
    }
};
