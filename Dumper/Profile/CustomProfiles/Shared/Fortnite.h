// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
// Fortnite Mobile — Android v43.10.0-60118918
// libUnreal.so
//
//  GUObjectArray : base + 0x19EEE6E8
//  GObjects ptr  : GUObjectArray + 0x89148  (encrypted, ChunkedObjects.Objects)
//  NumElements   : GUObjectArray + 0x89150  (encrypted, ChunkedObjects.NumElements)
//  NamePool      : base + 0x19F34600
//
// NOTE: Epic rotates obfuscation keys every minor update. Re-derive the
//       EOR/MUL constants from VERIFYGC (0xC67F02C) each patch.

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

    // Fixed GObjects base (GUObjectArray struct address).
    // MobileDumper reads Objects/NumElements from inside it via
    // ResolveGObjectsLayout + the ChunkedObjects decrypt hooks.
    uintptr_t GetGObjects() const override
    {
        // NOTE: match the memory-access idiom used by the other profiles in
        // this repo (e.g. `GMemory->GetBase()`, `Mem->GetBase()`, ...).
        return GMemory->GetBase() + 0x19EEE6E8;
    }

    uintptr_t GetGNames() const override
    {
        return GMemory->GetBase() + 0x19F34600;
    }

    // -------------------------------------------------------------------------
    // Decryption hooks — matches the current FDecryptCallbacks signatures:
    //   ChunkedObjects.Objects     : (uintptr_t Value, uintptr_t Address) -> uintptr_t
    //   ChunkedObjects.NumElements : (int32     Value, uintptr_t Address) -> int32
    // -------------------------------------------------------------------------
    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // ---- VARIANT A: exact EOR+rotate+MUL from your IDA notes -------------
        // Use this if VERIFYGC really does `EOR K1, V,ROR#38` before the MUL.
        // Requires a rotate helper from Utils (names may differ per repo:
        //   Utils::Memory::Ror64 / RotateRight64 / ror64 / ...).
        Callbacks.ChunkedObjects.Objects = [](uintptr_t Value, uintptr_t /*Addr*/)
        {
            // (0x014A7AF1 ^ ROR64(Value, 38)) * 0xFCF860ABC8EC0E17
            const uint64_t ror38 = (Value >> 38) | (Value << (64 - 38));
            return (0x014A7AF1ULL ^ ror38) * 0xFCF860ABC8EC0E17ULL;
        };

        Callbacks.ChunkedObjects.NumElements = [](int32 Value, uintptr_t /*Addr*/)
        {
            // (0x1130A328 ^ ROR32(Value, 5)) * 0x6977DD63 + 0xFC3B1B46
            const uint32_t v    = static_cast<uint32_t>(Value);
            const uint32_t ror5 = (v >> 5) | (v << (32 - 5));
            const uint32_t r    = (0x1130A328u ^ ror5) * 0x6977DD63u + 0xFC3B1B46u;
            return static_cast<int32>(r);
        };

        // ---- VARIANT B: linear A*V - B shape (like the old example) ----------
        // Use this ONLY after re-deriving A/B from the current VERIFYGC.
        // The constants below are placeholders — they will NOT work.
        //
        // Callbacks.ChunkedObjects.Objects = [](uintptr_t Value, uintptr_t)
        // {
        //     return (0xAAAAAAAAAAAAAAAAULL * Value - 0xBBBBBBBBBBBBBBBBULL);
        // };
        // Callbacks.ChunkedObjects.NumElements = [](int32 Value, uintptr_t)
        // {
        //     return static_cast<int32>(0xCCCCCCCC * static_cast<uint32_t>(Value)
        //                               - 0xDDDDDDDD);
        // };
    }
};
