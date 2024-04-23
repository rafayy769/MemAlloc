/**
 * @file utils.h
 * @brief Contains useful macros and utilities to be used by the memory allocator.
 * @version 0.1
 * @date 2023-06-03
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef UTILS_H
#define UTILS_H

#include "log.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((b) < (a) ? (a) : (b))

// we specify that the strings in our program won't exceed length of 100 characters
#define MAX_STRING_LENGTH 1024

// macros for pointer manipulation
#define PTR_ADD(ptr, offset) ((void*)((char*)(ptr) + (offset)))
#define PTR_SUB(ptr, offset) ((void*)((char*)(ptr) - (offset)))

// macro for checking if a pointer is aligned
#define IS_ALIGNED(ptr, align) (((uintptr_t)(const void*)(ptr)) % (align) == 0)

// macro for aligning a pointer
#define ALIGN_PTR(ptr, align) ((void*)(((uintptr_t)(const void*)(ptr) + (align - 1)) & ~(align - 1)))

// macro to get the offset of a member in a struct
#define OFFSET_OF(type, member) ((size_t) &((type*)0)->member)

#define READ_PTR(ptr) (*(uintptr_t*)(ptr))
#define WRITE_PTR(ptr, val) (*(uintptr_t*)(ptr) = (uintptr_t)(val))

#define COPY(str) (str ? strndup(str, MAX_STRING_LENGTH) : NULL)

#endif // UTILS_H