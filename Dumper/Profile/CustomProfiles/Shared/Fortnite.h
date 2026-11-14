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
        return Base + 0x19F34600;
    }

    uintptr_t GetGObjects() const override
    {
        uintptr_t Base = MD7::Globals::GMemory->GetModuleInfo("libUnreal.so").GetBase();
        return Base + 0x1A077730;
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        Callbacks.ChunkedObjects.Objects = [](const FDecryptContext<uintptr_t>& Ctx) -> uintptr_t
        {
            uint64_t r = __builtin_rotateright64(Ctx.RawValue, 38) ^ 0x14A7AF1ULL;
            return 0xFCF860ABC8EC0E17ULL * r + 0x7A4BC24E320683F0ULL;
        };

        Callbacks.ChunkedObjects.NumElements = [](const FDecryptContext<int32>& Ctx) -> int32
        {
            uint32_t r = __builtin_rotateright32((uint32_t)Ctx.RawValue, 5) ^ 0x113A328u;
            return (int32)(1769463139u * r) - 63235258;
        };

        Callbacks.ChunkedObjects.MaxElements = [](const FDecryptContext<int32>& Ctx) -> int32
        {
            uint32_t r = __builtin_rotateright32((uint32_t)Ctx.RawValue, 5) ^ 0x113A328u;
            return (int32)(1769463139u * r) - 1314885808;
        };

        Callbacks.ChunkedObjects.FUObjectItem.Object = [](const FDecryptContext<uintptr_t>& Ctx) -> uintptr_t
        {
            return Ctx.RawValue & ~0x3FFF00000000ULL;
        };
    }
};
