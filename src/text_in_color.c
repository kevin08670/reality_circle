#include <stdio.h>
#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#endif
#include "text_in_color.h"
#include <stdint.h>
#include <stdarg.h>
#include <time.h>

static unsigned int trace_index = 0;
#define hex_max_length 48

#if defined(NDEBUG) || defined(RELEASE_BUILD)
#define DEBUG_TRACE 0
#else
#define DEBUG_TRACE 1
#endif

// 优化: 缓存时间戳，减少系统调用
static time_t cached_time = 0;
static struct tm cached_tm;
static unsigned int time_cache_counter = 0;
#define TIME_CACHE_INTERVAL 10  // 每10次日志调用更新一次时间

static void update_time_cache(void) {
	time_t now;
	time(&now);
	// 每秒更新一次，或每TIME_CACHE_INTERVAL次调用更新一次
	if (now != cached_time || (++time_cache_counter % TIME_CACHE_INTERVAL == 0)) {
		cached_time = now;
		cached_tm = *localtime(&now);
		time_cache_counter = 0;
	}
}

void htrace(enum text_color color, const char *fmt, const char* data, size_t len) {
	char szout[ hex_max_length * 4 + 256] = { 0 };
	update_time_cache();
	struct tm *gtime = &cached_tm;
#ifdef INNO_CLIENT
	int n = sprintf(szout, "%04d/%02d/%02d %02d:%02d:%02d C%04d %s (%ld):", (uint16_t)(gtime->tm_year + 1900), (uint8_t)(gtime->tm_mon + 1), (uint8_t)gtime->tm_mday, (uint8_t)(gtime->tm_hour % 24), (uint8_t)gtime->tm_min, gtime->tm_sec, trace_index++, fmt, len);
#else
	int n = sprintf(szout, "%04d/%02d/%02d %02d:%02d:%02d S%04d %s (%ld):", (uint16_t)(gtime->tm_year + 1900), (uint8_t)(gtime->tm_mon + 1), (uint8_t)gtime->tm_mday, (uint8_t)(gtime->tm_hour % 24), (uint8_t)gtime->tm_min, gtime->tm_sec, trace_index++, fmt, len);
#endif
	for (size_t i = 0; i < len && i < hex_max_length; i++) {
		sprintf(&szout[i * 3 + n], "%02X ", (unsigned char)data[i]);
	}
	print_text_in_color(stderr, szout, color);
	fprintf(stderr, "\r\n");
}

void xtrace(enum text_color color, const char *fmt, ...) {
	char szout[1024] = { 0 };
	update_time_cache();
	struct tm *gtime = &cached_tm;
#ifdef INNO_CLIENT
	int n = sprintf(szout, "%04d/%02d/%02d %02d:%02d:%02d C%04d ", (uint16_t)(gtime->tm_year + 1900), (uint8_t)(gtime->tm_mon + 1), (uint8_t)gtime->tm_mday, (uint8_t)(gtime->tm_hour % 24), (uint8_t)gtime->tm_min, gtime->tm_sec, trace_index++);
#else
	int n = sprintf(szout, "%04d/%02d/%02d %02d:%02d:%02d S%04d ", (uint16_t)(gtime->tm_year + 1900), (uint8_t)(gtime->tm_mon + 1), (uint8_t)gtime->tm_mday, (uint8_t)(gtime->tm_hour % 24), (uint8_t)gtime->tm_min, gtime->tm_sec, trace_index++);
#endif
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(&szout[n], sizeof(szout) - n, fmt, ap);
	va_end(ap);
	print_text_in_color(stderr, szout, color);
	fprintf(stderr, "\r\n");
}

void print_text_in_color(FILE *file, const char *text, enum text_color color) {
#if defined(WIN32) || defined(_WIN32)
    WORD wAttributes = 0;
    HANDLE  hConsole = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo = { 0 };
    struct {
        FILE *filePtr;
        DWORD wHandle;
    } std_handles[] = {
        { stdin, STD_INPUT_HANDLE },
        { stdout, STD_OUTPUT_HANDLE },
        { stderr, STD_OUTPUT_HANDLE },
    };
    int i=0;
    DWORD nStdHandle = 0;

#define TEXT_COLOR_WIN(item, ansi_text, win_int) case (item): wAttributes = (win_int); break;
    switch (color) {
        TEXT_COLOR_MAP(TEXT_COLOR_WIN)
    default:;  // Silence text_color_max -Wswitch warning.
    }
#undef TEXT_COLOR_WIN

    for (i=0; i<(sizeof(std_handles) / sizeof(*(std_handles))); ++i) {
        if (std_handles[i].filePtr == file) {
            nStdHandle = std_handles[i].wHandle;
            break;
        }
    }

    if (nStdHandle) {
        hConsole = GetStdHandle(nStdHandle);
        GetConsoleScreenBufferInfo(hConsole, &csbiInfo);
        SetConsoleTextAttribute(hConsole, wAttributes);
    }
    fprintf(file, "%s", text);
    if (nStdHandle) {
        SetConsoleTextAttribute(hConsole, csbiInfo.wAttributes);
    }

#else
    const char *clr_txt = ANSI_COLOR_RESET;

#define TEXT_COLOR_UNIX(item, ansi_text, win_int) case (item): clr_txt = (ansi_text); break;
    switch (color) {
        TEXT_COLOR_MAP(TEXT_COLOR_UNIX)
    default:;  // Silence text_color_max -Wswitch warning.
    }
#undef TEXT_COLOR_UNIX

    fprintf(file, "%s%s" ANSI_COLOR_RESET, clr_txt, text);

#endif /* WIN32 */
}
