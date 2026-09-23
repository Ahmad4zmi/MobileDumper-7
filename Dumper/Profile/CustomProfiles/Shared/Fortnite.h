#pragma once

#include "../../IProfile.h"

class MyGameProfile : public IProfile
{
public:
    std::vector<std::string> GetSupportedGames() const override
    {
        return {"com.epicgames.fortnite"};
    }

    void OverrideDecryptCallbacks(FDecryptCallbacks& Callbacks) const override
{
	Callbacks.ChunkedObjects.Objects = [](uintptr_t Value, uintptr_t /* Optional Address */)
	{
		return (0xDC1F96F8C0C17AA5LL * Value - 0x70D8A3D87E4765FCLL);
	};

	Callbacks.ChunkedObjects.NumElements = [](int32 Value, uintptr_t /* Optional Address */)
	{
		return -1225621317 * Value - 106502534;
	};
}
};
