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

    // Leave this as 0! 
    // This forces the dumper to dynamically scan for the GObjects global pointer.
    // Returning 0x19747748 directly failed because the dumper read it as a literal address.
    uintptr_t GetGObjects() const override
    {
        return 0; 
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
    {
        // ====================================================================
        // 1. GObjects Pointer (Chunked Objects)
        // ====================================================================
        Callbacks.ChunkedObjects.Objects = [](const FDecryptContext<uintptr_t>& Context) -> uintptr_t
        {
            // VERSION 1: Based on your IDA (XOR + BSwap)
            uintptr_t Decrypted = Context.RawValue ^ 0xF89E367B00000000ULL;
            return __builtin_bswap64(Decrypted);

            // VERSION 2: Based on dev's v42 snippet (Uncomment if Version 1 fails)
            // return (0xDC1F96F8C0C17AA5LL * Context.RawValue) - 0x70D8A3D87E4765FCLL;
        };

        // ====================================================================
        // 2. NumElements
        // ====================================================================
        Callbacks.ChunkedObjects.NumElements = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            // Dev's v42 formula
            return -1225621317 * Context.RawValue - 106502534;
            
            // If this gives negative numbers, try returning Context.RawValue directly
            // return Context.RawValue;
        };

        // ====================================================================
        // 3. UObject Index (From your IDA)
        // ====================================================================
        Callbacks.UObject.Index = [](const FDecryptContext<int32_t>& Context) -> int32_t
        {
            // Read raw 32-bit, XOR, then Bswap
            uint32_t RawIndex = MD7::Globals::GMemory->Read<uint32_t>(Context.Address);
            uint32_t Decrypted = RawIndex ^ 0x7C85CAEA;
            return static_cast<int32_t>(__builtin_bswap32(Decrypted));
        };
    }
};
