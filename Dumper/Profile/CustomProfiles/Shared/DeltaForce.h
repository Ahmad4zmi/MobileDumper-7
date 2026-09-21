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

		// Offsets tried, in order, from the scan hit.
		static constexpr intptr_t Deltas[] = {0x10, 0, -0x10, 0x20, -0x20};

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
				if (!ADRP)
					continue;

				GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: Scan hit 0x{:X}\n", ADRP);
				DumpBytes(ADRP);

				for (intptr_t Delta : Deltas)
				{
					const uintptr_t Candidate = ADRP + Delta;
					if (LooksLikeObjectArray(Candidate))
					{
						GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: Accepted 0x{:X} (hit {}0x{:X})\n", Candidate, Delta < 0 ? "-" : "+", (unsigned)(Delta < 0 ? -Delta : Delta));
						return Candidate;
					}
				}

				GLogger.FmtWrite(ELogLevel::Warn, "GetGObjects: No offset near 0x{:X} looked like an object array (empty array, encrypted, or wrong address).\n", ADRP);
			}
		}

		// Returning 0 lets MobileDumper-7 fall back to UEAnalyzerKitty.
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

private:
	static bool IsPtr(uintptr_t V)
	{
		V &= 0x00FFFFFFFFFFFFFFull; // ignore the top tag byte
		return V > 0x10000 && V < 0x0001000000000000ull;
	}

	// True if Addr holds something shaped like a chunked object array:
	// a pointer field -> chunk table -> chunk -> first UObject -> vtable,
	// plus an int32 that looks like an element count.
	static bool LooksLikeObjectArray(uintptr_t Addr)
	{
		for (uintptr_t Off = 0; Off <= 0x40; Off += 8)
		{
			uintptr_t Table = GMemory->Read<uintptr_t>(Addr + Off);
			if (!IsPtr(Table))
				continue;

			uintptr_t Chunk = GMemory->Read<uintptr_t>(Table);
			if (!IsPtr(Chunk))
				continue;

			uintptr_t Obj = GMemory->Read<uintptr_t>(Chunk);
			if (!IsPtr(Obj))
				continue;

			uintptr_t Vtbl = GMemory->Read<uintptr_t>(Obj);
			if (!IsPtr(Vtbl))
				continue;

			for (uintptr_t C = 0; C <= 0x40; C += 4)
			{
				int32_t N = GMemory->Read<int32_t>(Addr + C);
				if (N > 1000 && N < 4000000)
				{
					GLogger.FmtWrite(ELogLevel::Info, "GetGObjects: 0x{:X} -> table at +0x{:X}, count {} at +0x{:X}\n", Addr, (unsigned)Off, N, (unsigned)C);
					return true;
				}
			}
		}
		return false;
	}

	static void DumpBytes(uintptr_t Hit)
	{
		uint8_t Dump[0x80] = {};
		const uintptr_t Start = Hit - 0x20;
		GMemory->ReadBytes(Start, Dump, sizeof(Dump));
		for (size_t i = 0; i < sizeof(Dump); i += 8)
		{
			GLogger.FmtWrite(ELogLevel::Info,
			    "GetGObjects: 0x{:X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}\n",
			    Start + i,
			    (unsigned)Dump[i], (unsigned)Dump[i + 1], (unsigned)Dump[i + 2], (unsigned)Dump[i + 3],
			    (unsigned)Dump[i + 4], (unsigned)Dump[i + 5], (unsigned)Dump[i + 6], (unsigned)Dump[i + 7]);
		}
	}
};
