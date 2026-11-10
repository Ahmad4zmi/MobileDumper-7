#pragma once
#include "../../IProfile.h"
#include "../../../Engine/OffsetFinder/Layouts.h"
#include <memory>
#include <string>
#include <vector>

// Custom layout for Fortnite's obfuscated Chunked Fixed UObject Array
class FFNChunkedFixedUObjectArrayLayout : public IObjectsLayout
{
public:
    // Based on your IDA findings:
    // MaxObjects (dword_19747760) was compared right before the array access.
    // The chunk array pointer (qword_19747748) was loaded right after.
    uint32_t Objects = 0x00;       // The pointer to the array of chunks
    uint32_t MaxElements = 0x18;   // Adjust this if MaxObjects was at a different offset
    uint32_t NumElements = 0x1C;
    uint32_t MaxChunks = 0x20;
    uint32_t NumChunks = 0x24;
    
    // Default constructor sets the layout
    FFNChunkedFixedUObjectArrayLayout() = default;
};

class FortniteProfile : public IProfile
{
public:
    std::vector<std::string> GetSupportedGames() const override
    {
        // Standard package name for Fortnite Mobile
        return {"com.epicgames.fortnite"};
    }

    // Override the layout resolver to use our custom chunked array layout
    bool ResolveGObjectsLayout(uintptr_t ObjectsPtr, std::unique_ptr<IObjectsLayout>& Out, std::string* OutError = nullptr) const override
    {
        Out = std::make_unique<FFNChunkedFixedUObjectArrayLayout>();
        return true;
    }

    // If MobileDumper-7 has a GObjects getter that can be overridden, use it here.
    // If the compiler complains that GetGObjects() is not a virtual function in IProfile, 
    // comment this entire function out and rely on the static offset.
    /*
    uintptr_t GetGObjects() const override
    {
        // If you need to hardcode the address, return it here.
        // However, the dumper usually finds it automatically via the "NewObject" string or signature.
        return 0; 
    }
    */
    
    // Override string decryption if Fortnite uses custom string obfuscation.
    // Based on your IDA screenshots, Fortnite uses standard FNamePool, so we leave this empty.
    
    // Override object index decryption (Fortnite XORs the index)
    // Based on your IDA: v208 = __builtin_bswap32(*(_DWORD *)(v207 + 12) ^ 0x7C85CAEA);
    /*
    uint32_t DecryptObjectIndex(uint32_t Index) const override
    {
        // Implementation depends on how the dumper passes the index.
        // Usually handled internally by the dumper if you provide the right layout.
    }
    */
};
