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

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // 1. GObjects Decryption
        // Based on IDA: __builtin_bswap64(qword_19747748 ^ 0xF89E367B00000000LL)
        Callbacks.Statics.GObjects = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            uintptr_t Decrypted = Context.RawValue ^ 0xF89E367B00000000ULL;
            return __builtin_bswap64(Decrypted);
        };

        // 2. UObject Index Decryption
        // Based on IDA: __builtin_bswap32(*(_DWORD *)(v207 + 12) ^ 0x7C85CAEA)
        Callbacks.UObject.Index = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            // Read raw, XOR, then Bswap
            uint32_t RawIndex = MD7::Globals::GMemory->Read<uint32_t>(Context.Address);
            uint32_t Decrypted = RawIndex ^ 0x7C85CAEA;
            return static_cast<int32_t>(__builtin_bswap32(Decrypted));
        };
        
        // 3. GNames (just in case)
        // If GNames is not encrypted, we leave it as the default (RawValue).
        // If Fortnite encrypts GNames later, the hook goes here.
    }
};
