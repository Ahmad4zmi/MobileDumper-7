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

    // Force the dumper to use the offset we found in IDA
    uintptr_t GetGObjects() const override
    {
        return 0x19747748; 
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        Callbacks.Statics.GObjects = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            // Context.RawValue is the address of the global (e.g., libUnreal.so + 0x19747748)
            // We need to read the 8 bytes AT that address
            uintptr_t EncryptedPtr = MD7::Globals::GMemory->Read<uintptr_t>(Context.RawValue);
            
            // Apply XOR and ByteSwap
            uintptr_t Decrypted = EncryptedPtr ^ 0xF89E367B00000000ULL;
            return __builtin_bswap64(Decrypted);
        };

        Callbacks.UObject.Index = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            uint32_t RawIndex = MD7::Globals::GMemory->Read<uint32_t>(Context.Address);
            uint32_t Decrypted = RawIndex ^ 0x7C85CAEA;
            return static_cast<int32_t>(__builtin_bswap32(Decrypted));
        };
    }
};
