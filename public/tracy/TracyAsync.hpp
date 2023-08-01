#pragma once

#include "../client/TracyResult.hpp"

#if DEBUG_TEMP
#define ZoneAsyncC(color, fiber) \
	static constexpr tracy::SourceLocationData TracyConcat(__tracy_source_location,TracyLine) { nullptr, TracyFunction, TracyFile, (uint32_t)TracyLine, color }; \
	tracy::AsyncScopedZone ___tracy_async_scoped_zone( &TracyConcat(__tracy_source_location, TracyLine), fiber );
#else
#define ZoneAsyncC(color, fiber) \
	static constexpr tracy::SourceLocationData TracyConcat(__tracy_source_location,TracyLine) { nullptr, TracyFunction, TracyFile, (uint32_t)TracyLine, color }; \
	tracy::AsyncScopedZone ___tracy_async_scoped_zone( &TracyConcat(__tracy_source_location, TracyLine) );
#endif
