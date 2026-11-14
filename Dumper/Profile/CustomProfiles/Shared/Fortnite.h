// Dumper/Profile/CustomProfiles/Shared/Fortnite.h
// Fortnite Mobile — Android v43.10.0-60118918
// libUnreal.so
//
// Offsets derived from IDA analysis of com.epicgames.fortnite
//
//  GUObjectArray  : 0x19EEE6E8  (qword_19EEE6E8)
//                   loaded as `this` throughout VERIFYGC func @ 0xC67F02C
//
//  GObjects       : encrypted pointer stored at qword_1A077730
//    decrypt      : (0x014A7AF1 ^ (raw >> 38)) * 0xFCF860ABC8EC0E17
//                   then walk chunked blocks; ObjectItemSize = 0x18
//
//  NumElements    : encrypted value at dword_1A077738
//    decrypt      : (0x1130A328 ^ ROR32(raw, 5)) * 0x6977DD63 + 0xFC3B1B46
//                   (compare twin @ 0xC67F084 uses 0xB1A06F50 as partner — same algo)
//
//  NamePool       : 0x19F34600  (dword_19F34600)
//    GetNameEntryRecursive : 0x66B2380
//    AppendString          : 0xC217444
//    Blocks offset         : 0xAB80  (from ADRL X20 + ADD X8, X20, W8,UXTH#3 at 0x66B23C4)
//    Len                   : (header >> 6) ^ 0x3CB
//    Wide bit              : header & 1
//    NextEntryIndex        : 2
//    String                : NameEntry + 2
//    Stride                : 2
//
// NOTE: Epic ships new obfuscation keys with every minor update.
//       After an update, re-derive the EOR/multiply constants from the
//       VERIFYGC function (0xC67F02C pattern) and the ADRL to dword_1A077730/38.
//       Offsets for NamePool and the function addresses also shift per patch.

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

    // -------------------------------------------------------------------------
    // GUObjectArray — pointer lives at a fixed BSS address.
    // The auto-scanner won't find it because "unable to add more objects" is
    // stripped; we hand it directly.
    // -------------------------------------------------------------------------
    uintptr_t GetGObjects() const override
    {
        // Return the address of the GUObjectArray structure itself.
        // MobileDumper reads NumElements and Objects from offsets within it,
        // so hand back the base, then override the layout below.
        return Mem->GetBase() + 0x19EEE6E8;
    }

    // -------------------------------------------------------------------------
    // GObjects layout — chunked array, encrypted pointers.
    //
    //  Objects ptr  stored at GUObjectArray + (0x1A077730 - 0x19EEE6E8) = 0x89148
    //  NumElements  stored at GUObjectArray + (0x1A077738 - 0x19EEE6E8) = 0x89150
    //
    // Both offsets are relative to GUObjectArray base.
    // The decrypt lambdas match the EOR+MUL pattern at 0xC67F0C8 (Objects)
    // and 0xC67F078 (NumElements) in VERIFYGC.
    // -------------------------------------------------------------------------
    void ResolveGObjectsLayout(FUObjectArrayLayout& Layout) const override
    {
        // Chunked layout
        Layout.bIsChunked         = true;
        Layout.ObjectsOffset      = 0x89148;   // qword_1A077730 - GUObjectArray base
        Layout.NumElementsOffset  = 0x89150;   // dword_1A077738 - GUObjectArray base
        Layout.ObjectItemSize     = 0x18;
    }

    // Decrypt the Objects chunk-array pointer
    void DecryptGObjects(uintptr_t& Value) const override
    {
        // EOR X8, 0x014A7AF1, X8,ROR#38  then MUL by 0xFCF860ABC8EC0E17
        // from disasm @ 0xC67F0DC / 0xC67F0F0
        Value = (0x014A7AF1ULL ^ Memory::ROR64(Value, 38)) * 0xFCF860ABC8EC0E17ULL;
    }

    // Decrypt NumElements (int32 stored encrypted)
    // Pattern: EOR W8, 0x1130A328, W8,ROR#5  then MADD W8, W8, 0x6977DD63, 0xFC3B1B46
    // from disasm @ 0xC67F094 / 0xC67F0A8
    void DecryptObjectItem(uintptr_t& Value) const override
    {
        // Per-item pointer — no additional encryption beyond the chunk decrypt above.
        // Leave as identity; override if items turn out to be individually wrapped.
    }

    // -------------------------------------------------------------------------
    // GNames — NamePool layout
    // -------------------------------------------------------------------------
    uintptr_t GetGNames() const override
    {
        return Mem->GetBase() + 0x19F34600;
    }

    void ResolveGNamesLayout(FNamePoolLayout& Layout) const override
    {
        Layout.BlocksOffset    = 0xAB80;  // from ADRL+ADD at 0x66B23C4/0x66B23C8
        Layout.Len             = [](uint16_t Header) -> int32_t
        {
            return static_cast<int32_t>((Header >> 6) ^ 0x3CB);
        };
        Layout.bIsWide         = [](uint16_t Header) -> bool
        {
            return (Header & 1) != 0;
        };
        Layout.NextEntryIndex  = 2;
        Layout.StringOffset    = 2;   // NameEntry + 2
        Layout.Stride          = 2;
    }
};
