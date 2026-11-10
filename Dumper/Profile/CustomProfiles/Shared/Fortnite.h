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

    // Hardcode the GObjects offset you found in IDA
    uintptr_t GetGObjects() const override
    {
        return 0x19747748; 
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // ====================================================================
        // 1. GObjects Pointer (Chunked Objects) - Based on YOUR IDA for v43
        // From IDA: __builtin_bswap64(qword_19747748 ^ 0xF89E367B00000000LL)
        // ====================================================================
        Callbacks.ChunkedObjects.Objects = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            // Context.RawValue is the encrypted pointer read from the offset
            uintptr_t Decrypted = Context.RawValue ^ 0xF89E367B00000000ULL;
            return __builtin_bswap64(Decrypted);
        };

        // ====================================================================
        // 2. NumElements - We use the dev's formula, but if it crashes, 
        // we might need to find the v43 replacement.
        // ====================================================================
        Callbacks.ChunkedObjects.NumElements = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            // The dev's v42 formula
            return -1225621317 * Context.RawValue - 106502534;
        };

        // ====================================================================
        // 3. UObject Index - Based on YOUR IDA for v43
        // From IDA: __builtin_bswap32(*(_DWORD *)(v207 + 12) ^ 0x7C85CAEA)
        // ====================================================================
        Callbacks.UObject.Index = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            uint32_t RawIndex = MD7::Globals::GMemory->Read<uint32_t>(Context.Address);
            uint32_t Decrypted = RawIndex ^ 0x7C85CAEA;
            return static_cast<int32_t>(__builtin_bswap32(Decrypted));
        };
    }
};
