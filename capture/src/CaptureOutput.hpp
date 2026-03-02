#ifndef __CAPTUREOUTPUT_HPP__
#define __CAPTUREOUTPUT_HPP__

#include <stdint.h>

#define ANSI_RESET "\033[0m"
#define ANSI_BOLD "\033[1m"
#define ANSI_BLACK "\033[30m"
#define ANSI_RED "\033[31m"
#define ANSI_GREEN "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BLUE "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN "\033[36m"
#define ANSI_ERASE_LINE "\033[2K"

namespace tracy { class Worker; }

void InitTerminalDetection();
bool IsTerminal();

#ifdef __GNUC__
[[gnu::format( __printf__, 2, 3 )]]
#endif
void AnsiPrintf( const char* ansiEscape, const char* format, ... );

int WaitForConnection( tracy::Worker& worker );

void PrintWorkerFailure( tracy::Worker& worker );

void PrintCaptureProgress( tracy::Worker& worker, int64_t firstTime, int64_t memoryLimit );

#endif
