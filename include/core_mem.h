/**
 * @file memory.h
 * @brief Provides a custom memory interface, instead of direct communication with the OS. Much more safe and (probably) easy to use.
 * @version 0.1
 * @date 2023-07-13
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef CORE_MEM_H
#define CORE_MEM_H

#include <stddef.h>
#include <unistd.h>

/**
 * @brief Initializes the simulated virtual memory. For any allocator to work, this function must be called atleast once.
 * 
 */
void cm_init_memory (void);

/**
 * @brief Releases the memory for the OS to reclaim.
 * 
 */
void cm_free_memory (void);

/**
 * @brief The custom `sbrk` function. This function is used by the allocator to request for more memory from the OS.
 * 
 * @param incr `sbrk` increments the heap space by >= 0 `incr` bytes.
 * @return void* Pointer to the first byte of the newly allocated memory. Failure is indicated by NULL.
 */
void* cm_sbrk(size_t incr); 

/**
 * @brief Resets the heap brk to the initial value. This function must only be used for testing purposes.
 * 
 */
void cm_reset_heap (void);

/**
 * @brief Returns the current heap start.
 * 
 * @return void* Pointer to the first heap byte.
 */
void* cm_heap_start (void);

/**
 * @brief Returns the current heap end.
 * 
 * @return void* Pointer to the last heap byte.
 */
void* cm_heap_end (void);

/**
 * @brief Returns the current heap size.
 * 
 * @return size_t The current heap size.
 */
size_t cm_heap_size (void);

#endif // !CORE_MEM_H