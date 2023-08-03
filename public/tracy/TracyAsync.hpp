#pragma once

#include "../client/TracyResult.hpp"

#define ZoneAsyncC(color) \
	static constexpr tracy::SourceLocationData TracyConcat(__tracy_source_location,TracyLine) { nullptr, TracyFunction, TracyFile, (uint32_t)TracyLine, color }; \
	tracy::AsyncScopedZone ___tracy_async_scoped_zone( &TracyConcat(__tracy_source_location, TracyLine) );
