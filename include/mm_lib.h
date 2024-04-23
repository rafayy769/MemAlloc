/**
 * @file mm_lib.h
 * @brief Memory management library.
 * @version 0.1
 * @date 2023-07-13
 * 
 * @copyright Copyright (c) 2023
 * 
 * Provides a simple memory management library, largely inspired by the libc malloc (more like dlmalloc) using free lists management. Provides corresponding functions for allocation, freeing and reallocation.
 */

#ifndef MM_LIB_H
#define MM_LIB_H

#include <stddef.h>

// standard alignment to be used by the allocator.
#define ALIGNMENT sizeof(void *)

/**
 * @brief Initializes the memory allocator, and the memory management system. All initialization of internal bookkeeping structures is done here. Note however, that the heap memory area is not initialized here. Heap memory initialization is done by the system. If needed, this can however call the sbrk function to get the initial heap memory.
 * 
 */
void mm_init (void);

/**
 * @brief Allocates a block of memory of size `size` bytes. The allocated memory is aligned to 8 bytes. The allocated memory is not initialized.
 * 
 * @param size The size of the memory block to be allocated.
 * @return void* Pointer to the first byte of the allocated memory block. Failure is indicated by NULL.
 */
void* mm_malloc (size_t size)  __attribute__((assume_aligned (ALIGNMENT)));

/**
 * @brief Frees the memory block pointed to by `ptr` which must have been returned by a previous call to `mm_malloc`. If `ptr` is NULL, no operation is performed.
 * 
 * @param ptr Pointer to the first byte of the memory block to be freed.
 */
void mm_free (void* ptr);

/**
 * @brief Changes the size of the memory block pointed to by `ptr` to `size` bytes. The contents of the block are preserved up to the lesser of the new and old sizes. If the new size is larger, the value of the newly allocated portion is indeterminate. If `ptr` is NULL, the call is equivalent to `mm_malloc(size)`. If `size` is equal to zero, the call is equivalent to `mm_free(ptr)`. Unless `ptr` is NULL, it must have been returned by an earlier call to `mm_malloc` or `mm_realloc`. If the area pointed to was moved, a `mm_free(ptr)` is done.
 * 
 * @param ptr Pointer to the first byte of the memory block to be resized.
 * @param size The new size of the memory block.
 * @return void* Pointer to the first byte of the resized memory block. Failure is indicated by NULL.
 */
void* mm_realloc (void* ptr, size_t size) __attribute__((assume_aligned (ALIGNMENT)));

#endif // MM_LIB_H
