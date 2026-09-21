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

	uintptr_t GetGObjects() const override
	{
		struct PatternInfo
		{
			const char* Pattern;
			int Step;
		};

		static constexpr PatternInfo Patterns[] = {
		    {"91 E1 03 14 AA ? ? ? 95 ? ? ? 36 ? ? ? B9", -7},
		    {"91 F6 03 01 AA E1 03 14 AA ? ? ? 39", -7},
		    {"91 E1 03 15 AA ? ? ? 95 ? ? ? 36 ? ? ? B9 ? ? ? 52 ? ? ? B0 ? ? ? F9 09 01 09 0B ? ? ? 71 ? ? ? 1A ? ? ? 13 ? ? ? 12 08 01 09 4B ? ? ? 52 ? ? ? F8 1F 20 03 D5 08 29 29 9B ? ? ? B9 ? ? ? 72 ? ? ? 54 ? ? ? F9", -7},
		};

		// The scan resolves to base + 0x2076B8F8; the other dumper used
		// base + 0x2076B908. Try +0x10 first. If it fails, try 0 and -0x10.
		constexpr intptr_t kAdjust = 0x10;

		for (const auto& P : Patterns)
		{
			std::vector<uintptr_t> Matches;

			for (const auto& Segment : GMemory->GetUnrealModule().GetSegments())
			{
				if (!Segment.IsValid() || !Segment.IsReadable() || !Segment.IsExecutable())
					continue;

				auto TempMatches = GMemory->FindAllPatternInRange(Segment.GetStart(), Segment.GetSize(), P.Pattern, P.Step);
				if (!TempMatches.empty())
				{
					Matches.insert(Matches.end(), TempMatches.begin(), TempMatches.end());
				}

				if (Matches.size() >= 3)
					break;
			}

			GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: Found {} matches for pattern.\n", Matches.size());

			for (const auto& Match : Matches)
			{
				std::vector<uint32> Insns(10, 0);
				GMemory->ReadBytes(Match, Insns.data(), Insns.size() * sizeof(uint32));

				GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: Testing match (0x{:X}) -> 0x{:X}\n", GMemory->GetUnrealModule().AddressToOffset(Match), Match);
				uintptr_t ADRP = Utils::Arm64::Find_ADRP_Final_Address(Insns, Match);
				if (ADRP)
				{
					// Log 0x80 bytes around the hit so the layout can be read from the log.
					uint8_t Dump[0x80] = {};
					const uintptr_t DumpStart = ADRP - 0x20;
					GMemory->ReadBytes(DumpStart, Dump, sizeof(Dump));
					GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: hit 0x{:X}, dumping from hit-0x20\n", ADRP);
					for (size_t i = 0; i < sizeof(Dump); i += 8)
					{
						GLogger.FmtWrite(ELogLevel::Info,
						    "GetGObjects: 0x{:X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}\n",
						    DumpStart + i,
						    (unsigned)Dump[i], (unsigned)Dump[i + 1], (unsigned)Dump[i + 2], (unsigned)Dump[i + 3],
						    (unsigned)Dump[i + 4], (unsigned)Dump[i + 5], (unsigned)Dump[i + 6], (unsigned)Dump[i + 7]);
					}

					GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: Returning 0x{:X} (hit + 0x{:X})\n", ADRP + kAdjust, (unsigned)kAdjust);
					return ADRP + kAdjust;
				}
			}
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
};
