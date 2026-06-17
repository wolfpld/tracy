#ifndef __TRACYFORMAT_HPP__
#define __TRACYFORMAT_HPP__

#if (defined(__GNUC__) || defined(__clang__))
#  define TRACY_ATTRIBUTE_FORMAT_PRINTF(fmt_idx, arg_idx) \
     __attribute__((format(printf, fmt_idx, arg_idx)))
#else
#  define TRACY_ATTRIBUTE_FORMAT_PRINTF(fmt_idx, arg_idx)
#endif

#endif
