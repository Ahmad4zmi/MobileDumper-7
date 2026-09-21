#pragma once

#include "../../IProfile.h"

class DeltaForceProfile : public IProfile
{
public:
	DeltaForceProfile() = default;

	std::vector<std::string> GetSupportedGames() const override
	{
		return {"com.proxima.dfm", "com.garena.game.df", "com.tencent.tmgp.dfm"};
	}

	// Pattern scan for GObjects (patterns from the old AndUEDumper profile).
	// If this returns 0, MobileDumper-7 falls back to UEAnalyzerKitty.
	uintptr_t GetGObjects() const override
	{
		static const std::pair<const char*, int> patterns[] = {
			{"91 E1 03 14 AA ? ? ? 95 ? ? ? 36 ? ? ? B9", -7},
			{"91 F6 03 01 AA E1 03 14 AA ? ? ? 39", -7},
			{"91 E1 03 15 AA ? ? ? 95 ? ? ? 36 ? ? ? B9 ? ? ? 52 ? ? ? B0 ? ? ? F9 09 01 09 0B ? ? ? 71 ? ? ? 1A ? ? ? 13 ? ? ? 12 08 01 09 4B ? ? ? 52 ? ? ? F8 1F 20 03 D5 08 29 29 9B ? ? ? B9 ? ? ? 72 ? ? ? 54 ? ? ? F9", -7},
		};

		// Test knob: if the dumper rejects the result, try +0x10 or -0x10.
		constexpr intptr_t kAdjust = 0;

		PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

		for (const auto& p : patterns)
		{
			uintptr_t addr = Arm64::DecodeADRL(findIdaPattern(map_type, p.first, p.second));
			if (addr != 0)
				return addr + kAdjust;
		}
		return 0;
	}

	// https://github.com/MJx0/AndUEDumper/issues/66

	void DecryptUTF8(char* Data, int32_t Len) const override
	{
		if (!Data || Len == 0)
			return;

		uint32_t Key = 0;
		switch (Len % 9)
		{
		case 0u: Key = ((Len & 0x1F) + Len); break;
		case 1u: Key = ((Len ^ 0xDF) + Len); break;
		case 2u: Key = ((Len | 0xCF) + Len); break;
		case 3u: Key = (33 * Len); break;
		case 4u: Key = (Len + (Len >> 2)); break;
		case 5u: Key = (3 * Len + 5); break;
		case 6u: Key = (((4 * Len) | 5) + Len); break;
		case 7u: Key = (((Len >> 4) | 7) + Len); break;
		case 8u: Key = ((Len ^ 0xC) + Len); break;
		default: Key = ((Len ^ 0x40) + Len); break;
		}

		for (int32_t i = 0; i < Len; i++)
		{
			Data[i] = (Key & 0x80) ^ (uint8_t)(~Data[i]);
		}
	}

	void DecryptUTF16(char16_t* Data, int32_t Len) const override
	{
		if (!Data || Len == 0)
			return;

		uint32_t Key = 0;
		switch (Len % 9)
		{
		case 0u: Key = ((Len & 0x1F) + Len); break;
		case 1u: Key = ((Len ^ 0xDF) + Len); break;
		case 2u: Key = ((Len | 0xCF) + Len); break;
		case 3u: Key = (33 * Len); break;
		case 4u: Key = (Len + (Len >> 2)); break;
		case 5u: Key = (3 * Len + 5); break;
		case 6u: Key = (((4 * Len) | 5) + Len); break;
		case 7u: Key = (((Len >> 4) | 7) + Len); break;
		case 8u: Key = ((Len ^ 0xC) + Len); break;
		default: Key = ((Len ^ 0x40) + Len); break;
		}

		uint16_t FinalKey = (Key | 0x7F) + 0x80;
		for (int32_t i = 0; i < Len; i++)
		{
			Data[i] ^= FinalKey;
		}
	}

	/*void OverrideSettings(FSettings& Settings) const override
	{
	    Settings.EngineCore.bEnableEncryptedObjectPropertySupport = true;
	}*/
};
