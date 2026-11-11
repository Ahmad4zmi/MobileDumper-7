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
        return Base + 0x19747748;
    }
};
