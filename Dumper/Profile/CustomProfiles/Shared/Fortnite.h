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

    // FORCE the dumper to use the offset we found in IDA
    uintptr_t GetGObjects() const override
    {
        // You found qword_19747748 in IDA. 
        // This is the offset from libUnreal.so base.
        return 0x19747748; 
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // The dumper will read the 8 bytes at (libUnreal.so + 0x19747748).
        // We need to decrypt that value.
        Callbacks.Statics.GObjects = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            // Context.RawValue is the encrypted value stored at 0x19747748
            uintptr_t Decrypted = Context.RawValue ^ 0xF89E367B00000000ULL;
            return __builtin_bswap64(Decrypted);
        };

        // UObject Index Decryption (unchanged, this is correct)
        Callbacks.UObject.Index = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            uint32_t RawIndex = MD7::Globals::GMemory->Read<uint32_t>(Context.Address);
            uint32_t Decrypted = RawIndex ^ 0x7C85CAEA;
            return static_cast<int32_t>(__builtin_bswap32(Decrypted));
        };
    }
};
