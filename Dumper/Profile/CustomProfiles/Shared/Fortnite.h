// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
#pragma once
#include "../../IProfile.h"

class FortniteProfile : public IProfile
{
public:
    std::vector<std::string> GetSupportedGames() const override
    {
        // Fortnite Mobile package names for Android and iOS
        return {
            "com.epicgames.fortnite",
            "com.epicgames.FortniteGame"
        };
    }

    // ---------------------------------------------------------------
    // GObjects Override
    // ---------------------------------------------------------------
    // We confirmed GObject global pointer is at 0x1D977718, which
    // points to the FUObjectArray structure (0x19A89A88).
    // The dumper's auto-detection *should* find this, but if it fails,
    // we override it here.
    uintptr_t GetGObjects() const override
    {
        // Return the *global pointer address* that points to FUObjectArray
        // (This is the value the dumper needs to read to find the object array)
        return 0x1D977718; 
    }

    // ---------------------------------------------------------------
    // GNames Override
    // ---------------------------------------------------------------
    // We confirmed GName global pointer is at 0x1D835080, which
    // points to the FNamePool (0x172BF3C8).
    uintptr_t GetGNames() const override
    {
        // Return the *global pointer address* that points to FNamePool
        return 0x1D835080;
    }

    // ---------------------------------------------------------------
    // GWorld Override (Optional, but useful for SDK generation)
    // ---------------------------------------------------------------
    // While not part of the core interface, you may want to access
    // GWorld for other tools. The global pointer we found is:
    // GWorld = 0x1DE6A900
    // If you need to override a GetGWorld() method, you would return
    // the address 0x1DE6A900 here.
    // uintptr_t GetGWorld() const override { return 0x1DE6A900; }
};
