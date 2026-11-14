// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
// Fortnite Mobile — Android v43.10.0-60118918
// libUnreal.so (IDA analysis)
//
// GUObjectArray  : base + 0x19EEE6E8
// Objects ptr    : encrypted qword at GUObjectArray + 0x189048 (qword_1A077730)
//   decrypt      : (0x014A7AF1 ^ ROR64(raw, 38)) * 0xFCF860ABC8EC0E17
//   then walk    : chunk_ptr = [result + (chunk_idx*8) + 0x7A4BC24E320683F0]
//   item         : UMADDL: chunk_ptr + (slot * 0x18)
// NumElements    : encrypted dword at GUObjectArray + 0x189050 (dword_1A077738)
//   decrypt      : (0x1130A328 ^ ROR32(raw, 5)) * 0x6977DD63 + 0xFC3B1B46
// NamePool       : base + 0x19F34600
//   Blocks offset: 0xAB80
//   Len          : (header >> 6) ^ 0x3CB
//   Wide         : header & 1
//   String       : NameEntry + 2, stride 2
//
// NOTE: re-derive constants after every update. The chunk displacement
//       0x7A4BC24E320683F0 is also version-specific — verify from VERIFYGC.

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

    // Read and decrypt the Objects pointer at runtime, return it directly.
    // This bypasses the auto-layout scanner which can't see through the encryption.
    uintptr_t GetGObjects() const override
    {
        uintptr_t base       = MD7::Globals::GMemory->GetUnrealModule().GetBase();
        uintptr_t array_base = base + 0x19EEE6E8;

        // Read encrypted Objects qword at GUObjectArray + 0x189048
        uintptr_t raw = MD7::Globals::GMemory->Read<uintptr_t>(array_base + 0x189048);

        // Decrypt: EOR X8, 0x014A7AF1, X8,ROR#38 / MUL 0xFCF860ABC8EC0E17
        uint64_t v = static_cast<uint64_t>(raw);
        v = (v >> 38) | (v << (64 - 38));
        return static_cast<uintptr_t>((0x014A7AF1ULL ^ v) * 0xFCF860ABC8EC0E17ULL);
    }

    // NamePool — normal anchors stripped; hand it directly.
    uintptr_t GetGNames() const override
    {
        return MD7::Globals::GMemory->GetUnrealModule().GetBase() + 0x19F34600;
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // NumElements — EOR W8, 0x1130A328, W8,ROR#5 / MADD 0x6977DD63, 0xFC3B1B46
        // from VERIFYGC @ 0xC67F094 / 0xC67F0A8
        Callbacks.ChunkedObjects.NumElements = [](const FDecryptContext<int32_t>& Ctx) -> int32_t
        {
            uint32_t v = static_cast<uint32_t>(Ctx.RawValue);
            v = (v >> 5) | (v << (32 - 5));
            v = (0x1130A328u ^ v) * 0x6977DD63u + 0xFC3B1B46u;
            return static_cast<int32_t>(v);
        };

        // Chunk pointer displacement — each chunk ptr is stored at
        // [chunk_table + (index*8) + 0x7A4BC24E320683F0]
        // LDR X8, [X8, X10] where X10 = 0x7A4BC24E320683F0 in VERIFYGC @ 0xC67F110
        // This is an additive displacement on the chunk table walk address.
        // If MobileDumper-7 exposes a chunk pointer decrypt callback, hook it here:
        //
        // Callbacks.ChunkedObjects.ChunkPtr = [](const FDecryptContext<uintptr_t>& Ctx) -> uintptr_t
        // {
        //     // Ctx.RawValue = chunk_table_entry_address (before dereference)
        //     // The LDR uses [base + 0x7A4BC24E320683F0] as effective address
        //     // so the stored chunk ptr is displaced — read from displaced address:
        //     uintptr_t displaced = Ctx.Address + 0x7A4BC24E320683F0ULL;
        //     return MD7::Globals::GMemory->Read<uintptr_t>(displaced);
        // };
    }
};
