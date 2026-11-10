// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
#pragma once
#include "../../IProfile.h"

class FortniteProfile : public IProfile
{
public:
    // Automatically activate when Fortnite package name is detected
    std::vector<std::string> GetSupportedGames() const override
    {
        return {"com.epicgames.fortnite"};
    }

    // --- GNames (FNamePool) ---
    // You found GetNamePool and NamePoolData in IDA, which is the GNames address
    // If the automatic scan cannot find it, you need to override GetGNames
    // uintptr_t GetGNames() const override { return 0x19604640; } // Example offset

    // --- GObjects ---
    // You found the encrypted qword_19747748 in StaticAllocateObject
    // According to MobileDumper-7 specifications, if the pointer is encrypted, override DecryptGObjects
    void DecryptGObjects(uintptr_t& ObjPtr) const override
    {
        // Based on your previous analysis, GObjects has undergone obfuscation
        // The assembly you saw involves XOR and byte swapping (REV)
        // The actual decryption logic needs to restore this process
        // Example (pseudocode logic, actual implementation requires writing in C++):
        // ObjPtr = __builtin_bswap64(ObjPtr ^ 0xF89E367B00000000LL);
    }

    // --- GObjects Layout ---
    // Fortnite uses a chunked array (FChunkedFixedUObjectArray)
    // If automatic detection fails, manually specify the layout
    void ResolveGObjectsLayout(FGObjectsLayout& Layout) const override
    {
        Layout.ObjectsOffset = 0x00;       // Points to the array of chunk pointers
        Layout.MaxElementsOffset = 0x10;   // MaxObjects you saw in IDA is at +0x10
        Layout.NumElementsOffset = 0x14;   // Usually adjacent to MaxElements
        Layout.MaxChunksOffset = 0x18;
        Layout.NumChunksOffset = 0x1C;
    }
};
