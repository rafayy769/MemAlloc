/**
 * @file pretty_tests.h
 * @author Abdul Rafay (24100173@lums.edu.pk)
 * @brief Why am i even doing this, this is clearly extra.
 * @version 0.1
 * @date 2023-08-12
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "log.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

// Define the colors for different things
#define LOG_COLOR_SUCCESS LOG_BOLDGREEN
#define LOG_COLOR_FAIL    LOG_BOLDRED
#define LOG_COLOR_INFO    LOG_BOLDWHITE
#define LOG_COLOR_HEADER  LOG_BOLDWHITE
#define LOG_COLOR_RESULT  LOG_BOLDBLUE
#define LOG_COLOR_UNDLD   LOG_BOLDWHITE

// Symbols for tests
#define TICK_MARK  "   [\u2713]   - "
#define CROSS_MARK "   [\u2717]   - "
#define PLUS_MARK  "   [+]   - "

// Exposed macros for logging in tests
#define LOG_TEST_SUCCESS(...) LOG(LOG_PRI, TICK_MARK, LOG_COLOR_SUCCESS, __VA_ARGS__)
#define LOG_TEST_FAIL(...) LOG(LOG_PRI, CROSS_MARK, LOG_COLOR_FAIL, __VA_ARGS__)
#define LOG_TEST_INFO(...) LOG(LOG_PRI, PLUS_MARK, LOG_COLOR_INFO, __VA_ARGS__)

// makes it look cleaner
#define NEWLINE LOG_OUT("\n")

// this macro logs whatever is provided in the color provided
#define LOG_COLORED(color, ...) \
    do { \
        LOG_OUT("%s", color); \
        LOG_OUT(__VA_ARGS__); \
        LOG_OUT("%s", LOG_RESET); \
    } while (0)

void print_underlined(const char *format, ...) 
{
    va_list args;
    va_start(args, format);

    // Print the formatted string
    LOG_OUT("%s", LOG_COLOR_UNDLD);
    vprintf(format, args);
    NEWLINE;

    // Calculate the length of the formatted string
    size_t length = strlen(format);

    // Print the underline
    for (size_t i = 0; i < length; i++) 
    {
        LOG_OUT("=");
    }
    NEWLINE;

    // Reset the color
    LOG_OUT("%s", LOG_RESET);
    va_end(args);
}

// this macro logs whatever is provided and then underlines it using "=". the underline is of the same length as the log.
#define LOG_TEST_UNDERLINE(...) print_underlined(__VA_ARGS__)

// this macro writes the name of the test case in a fancy way
#define LOG_RUN_TEST(...) LOG(LOG_PRI, "Running test: ", LOG_BOLDYELLOW, __VA_ARGS__)

// this macro prints the test result
#define LOG_TEST_RESULT(prefix, ...) \
    do { \
        LOG_OUT("%s%s%s", LOG_COLOR_RESULT, prefix, LOG_RESET); \
        LOG_OUT(__VA_ARGS__); \
    } while (0)

// prints a heading. the heading is underlined using "=" as well as overlined using "="
#define LOG_HEADER(string) \
    do { \
        LOG_OUT("%s", LOG_COLOR_HEADER); \
        size_t length = strlen(string); \
        for (size_t i = 0; i < length; i++) { \
            LOG_OUT("="); \
        } \
        NEWLINE; \
        LOG_OUT(string); \
        NEWLINE; \
        for (size_t i = 0; i < length; i++) { \
            LOG_OUT("="); \
        } \
        NEWLINE; \
        LOG_OUT("%s", LOG_RESET); \
    } while (0)
