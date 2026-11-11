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

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // Object pointer has flag bits packed in upper bits — mask them off
        Callbacks.ChunkedObjects.FUObjectItem.Object = [](const FDecryptContext<uintptr_t>& Ctx) -> uintptr_t
        {
            return Ctx.RawValue & ~0x3FFF00000000ULL;
        };

        // NumElements XOR-obfuscated with bswap
        Callbacks.ChunkedObjects.NumElements = [](const FDecryptContext<int32>& Ctx) -> int32
        {
            return (int32)__builtin_bswap32((uint32_t)Ctx.RawValue ^ 0xB62DEEC3u);
        };

        // MaxElements same obfuscation pattern
        Callbacks.ChunkedObjects.MaxElements = [](const FDecryptContext<int32>& Ctx) -> int32
        {
            return (int32)__builtin_bswap32((uint32_t)Ctx.RawValue ^ 0xF78656Bu);
        };

        // Chunks pointer XOR-obfuscated with bswap64
        Callbacks.ChunkedObjects.Objects = [](const FDecryptContext<uintptr_t>& Ctx) -> uintptr_t
        {
            return __builtin_bswap64(Ctx.RawValue ^ 0xF89E367B00000000ULL);
        };
    }
};
