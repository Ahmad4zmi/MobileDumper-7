// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
#pragma once
#include "../../IProfile.h"

class FortniteProfile : public IProfile
{
public:
    std::vector<std::string> GetSupportedGames() const override
    {
        return { "com.epicgames.fortnite" };
    }

    uintptr_t GetGNames() const override
    {
        uintptr_t Base = MD7::Globals::GMemory->GetModuleInfo("libUnreal.so").GetBase();
        return Base + 0x19604640;
    }

    uintptr_t GetGObjects() const override
    {
        uintptr_t Base = MD7::Globals::GMemory->GetModuleInfo("libUnreal.so").GetBase();
        // qword_19747748 is the chunks base pointer, subtract to get FUObjectArray struct base
        return Base + 0x19747748 - 0xD8;
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // NumElements is bswap-obfuscated with XOR key 0xB62DEEC3
        Callbacks.ChunkedObjects.NumElements = [](int32 Value, uintptr_t) -> int32
        {
            return (int32)__builtin_bswap32((uint32_t)Value ^ 0xB62DEEC3u);
        };
    }
};
