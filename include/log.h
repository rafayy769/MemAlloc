/**
 * @file log.h
 * @author Abdul Rafay (24100173@lums.edu.pk)
 * @brief A collection of macros and functions to facilitate logging in a helpful manner, instead of using plain printf statements. somewhat inspired from the contiki-ng's logging facilities, though the usage is different. 
 * The exposed logging functions can easily be used in any project. The macros for logging in tests are also provided, which are used in the test cases. Just use them like a regular printf statement.
 * @version 0.1
 * @date 2023-06-29
 *
 * @copyright Copyright (c) 2023
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>

// Log coloring
#define LOG_RESET "\033[0m"
#define LOG_RED "\033[1;31m"
#define LOG_GREEN "\033[1;32m"
#define LOG_YELLOW "\033[1;33m"
#define LOG_BLUE "\033[1;34m"
#define LOG_CYAN "\033[1;36m"
#define LOG_WHITE "\033[1;37m"
#define LOG_MAGENTA "\033[1;35m"
#define LOG_BLACK "\033[1;30m"
#define LOG_BOLDBLACK "\033[1m\033[30m"
#define LOG_BOLDRED "\033[1m\033[31m"
#define LOG_BOLDGREEN "\033[1m\033[32m"
#define LOG_BOLDYELLOW "\033[1m\033[33m"
#define LOG_BOLDBLUE "\033[1m\033[34m"
#define LOG_BOLDCYAN "\033[1m\033[36m"
#define LOG_BOLDMAGENTA "\033[1m\033[35m"
#define LOG_BOLDWHITE "\033[1m\033[37m"

#define LOG_WHITE_ON_BLACK "\033[38;5;231;48;5;16m"

// defines for logging modes
#define LOG_ERR 0 /* For printing critical errors, always get printed */
#define LOG_DBG 1 /* For printing debug print statements, only in debug mode */
#define LOG_PRI 2 /* For normal printing of messages, always get printed without annotations */

// Default colors for different log types
#define LOG_COLOR_ERR     LOG_BOLDRED
#define LOG_COLOR_DBG     LOG_BOLDCYAN
#define LOG_COLOR_PRI     LOG_BOLDMAGENTA

// debug mode, debug messages are printed only if this is set to 1 (debug is provided as a compiler flag)
// in debug mode, we also use annotations to specify the function name and line number where the debug message is printed, as well as the type of message
#ifdef DEBUG
#define ANNOTATIONS 1 /* Change this to zero to disable all annotations even in debug mode */
#else
#define DEBUG 0
#define ANNOTATIONS 0
#endif

// Macros to change the behavior of annotations
#define ANNOTATIONS_INFO 0 /* Change this to zero to disable annotations info */

// what annotations do you want to print? format is (file, function, line) set any of these to 0 to not print them
#define ANNOTATIONS_FILE 0
#define ANNOTATIONS_FUNC 1
#define ANNOTATIONS_LINE 1

#define ANNOTATION_COLOR LOG_WHITE

// output function for printing, default is printf
// the advantage of using this is that we can define it to log to a file or something else as well, without changing anything else
#define LOG_OUT(...) printf(__VA_ARGS__)

// defines the annotation string.
// if you want to change the format of the annotation, change the above macros and this string. the annotation string is simply "file,function,line" depending on the above macros
#define ANNOTATION_INFO_STRING                                              \
    do                                                                      \
    {                                                                       \
        if (ANNOTATIONS_INFO)                                               \
        {                                                                   \
            LOG_OUT("%sat (%s", ANNOTATION_COLOR, LOG_RESET);               \
            if (ANNOTATIONS_FILE)                                           \
                LOG_OUT("%s%s%s", ANNOTATION_COLOR, __FILE__, LOG_RESET);   \
            if (ANNOTATIONS_FILE && (ANNOTATIONS_FUNC || ANNOTATIONS_LINE)) \
                LOG_OUT("%s,%s", ANNOTATION_COLOR, LOG_RESET);              \
            if (ANNOTATIONS_FUNC)                                           \
                LOG_OUT("%s%s%s", ANNOTATION_COLOR, __func__, LOG_RESET);   \
            if (ANNOTATIONS_FUNC && ANNOTATIONS_LINE)                       \
                LOG_OUT("%s,%s", ANNOTATION_COLOR, LOG_RESET);              \
            if (ANNOTATIONS_LINE)                                           \
                LOG_OUT("%s%d%s", ANNOTATION_COLOR, __LINE__, LOG_RESET);   \
            LOG_OUT("%s) %s", ANNOTATION_COLOR, LOG_RESET);                 \
        }                                                                   \
    } while (0)

// macro to log a message.
// Super ugly under the hood i know ill get around updating it someday
#define LOG(type, prefix, color, ...)                                         \
    do                                                                        \
    {                                                                         \
        if (DEBUG)                                                            \
        {                                                                     \
            if (type == LOG_DBG)                                              \
            {                                                                 \
                if (ANNOTATIONS)                                              \
                {                                                             \
                    LOG_OUT("%s%s%s", color, prefix, LOG_RESET);              \
                    ANNOTATION_INFO_STRING;                                   \
                }                                                             \
                LOG_OUT(__VA_ARGS__);                                         \
                break;                                                        \
            }                                                                 \
        }                                                                     \
        if (type == LOG_ERR || type == LOG_PRI)                               \
        {                                                                     \
            if (ANNOTATIONS)                                                  \
            {                                                                 \
                LOG_OUT("%s%s%s", color, prefix, LOG_RESET);                  \
                ANNOTATION_INFO_STRING;                                       \
            }                                                                 \
            LOG_OUT(__VA_ARGS__);                                             \
        }                                                                     \
    } while (0)


// Exposed macros for logging
#define LOG_ERROR(...) LOG(LOG_ERR, " [ERROR] - ", LOG_COLOR_ERR, __VA_ARGS__)
#define LOG_DEBUG(...) LOG(LOG_DBG, " [DEBUG] - ", LOG_COLOR_DBG, __VA_ARGS__)
#define LOG_PRINT(...) LOG(LOG_PRI, " [PRINT] - ", LOG_COLOR_PRI, __VA_ARGS__)

#endif // LOG_H
