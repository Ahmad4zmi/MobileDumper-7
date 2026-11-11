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
        // FNamePool instance at 0x19604640 (lazy-init guard at 0x19604618)
        // Verified via sub_B2E5390 (FName::Init) xref
        uintptr_t Base = MD7::Globals::GMemory->GetLibBase("libUnreal.so");
        return Base + 0x19604640;
    }

    uintptr_t GetGObjects() const override
    {
        // FUObjectArray chunk pointer at 0x19747748
        // XOR-obfuscated in binary code but plain after runtime init
        // Verified via sub_672D7A8 (CreateExport) xref + bswap/XOR pattern
        uintptr_t Base = MD7::Globals::GMemory->GetLibBase("libUnreal.so");
        return Base + 0x19747748;
    }
};
