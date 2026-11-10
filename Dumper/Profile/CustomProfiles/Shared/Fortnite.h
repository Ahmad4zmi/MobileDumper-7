#pragma once
#include "../../IProfile.h"
#include "../../Engine/OffsetFinder/DecryptCallbacks.h"

class FortniteProfile : public IProfile
{
public:
    std::vector<std::string> GetSupportedGames() const override
    {
        // Standard package name for Fortnite Mobile
        return {"com.epicgames.fortnite"};
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // ---------------------------------------------------------
        // 1. GObjects Decryption
        // From IDA: __builtin_bswap64(qword_19747748 ^ 0xF89E367B00000000LL)
        // ---------------------------------------------------------
        Callbacks.Statics.GObjects = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            // XOR the raw pointer, then ByteSwap (Bswap) it
            uintptr_t Decrypted = Context.RawValue ^ 0xF89E367B00000000ULL;
            return __builtin_bswap64(Decrypted);
        };

        // ---------------------------------------------------------
        // 2. UObject Index Decryption
        // From IDA: __builtin_bswap32(*(_DWORD *)(v207 + 12) ^ 0x7C85CAEA)
        // ---------------------------------------------------------
        Callbacks.UObject.Index = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            // Read the 32-bit integer at the address, XOR it, then Bswap it
            uint32_t RawIndex = GMemory->Read<uint32_t>(Context.Address);
            uint32_t Decrypted = RawIndex ^ 0x7C85CAEA;
            return static_cast<uintptr_t>(__builtin_bswap32(Decrypted));
        };

        // ---------------------------------------------------------
        // 3. MaxObjects Decryption (Optional but recommended)
        // From IDA: __builtin_bswap32(dword_19747760 ^ 0xF78656B)
        // ---------------------------------------------------------
        // If the MaxObjects value is also encrypted, you can use the
        // layout decryption hooks if provided, or rely on the chunked layout.
        // For now, we assume the default ChunkedFixedUObjectArray layout works.
    }
};
