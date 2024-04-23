#include "core_mem.h"
#include "mm_lib.h"
#include "utils.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

// -------- Macros defined for the allocator --------
#define ALIGN_SIZE(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define BASE_BRK_INCREMENT 512 // 1 MB
#define BASIC_ALLOC_SZ sizeof(void *)

#define MAGIC 0xdeadbeef

#define SEARCH_SCHEME_ENV "SEARCH_SCHEME"

#define ERR_HEAP_FAILURE ((void*)-1)

// --------- Definitions of the headers ---------
// free block header
// simply update the struct and the macro for placing it whenever the header is changed
typedef struct __free_block_header
{
    size_t size;
    struct __free_block_header *next;

    /* more info can be stored as well for a free block but this is enough for now */
} free_block_header;

#define FREE_BLOCK_HEADER_SZ sizeof(free_block_header)

// places the free block header at the given address
#define PLACE_FREE_BLOCK(addr, sz, nxt)                           \
    do                                                            \
    {                                                             \
        free_block_header *__block = (free_block_header *)(addr); \
        __block->size = sz;                                       \
        __block->next = nxt;                                      \
    } while (0)

// allocated block header
typedef struct __alloc_block_header
{
    size_t size;
    long magic;
} alloc_block_header;

#define ALLOC_BLOCK_HEADER_SZ sizeof(alloc_block_header)

// places the allocated block header at the given address
#define PLACE_ALLOC_BLOCK(addr, sz)                                 \
    do                                                              \
    {                                                               \
        alloc_block_header *__block = (alloc_block_header *)(addr); \
        __block->size = sz;                                         \
        __block->magic = MAGIC;                                     \
    } while (0)

// the scheme that finds a free block
typedef enum __free_block_search_scheme
{
    FIRST_FIT,
    BEST_FIT,
    WORST_FIT
} free_block_search_scheme;

// Internal malloc state structure
typedef struct __malloc_state
{
    free_block_header *free_list_head;
    free_block_search_scheme search_scheme;
    
    // fields for the slab allocator, only used when the search scheme is SLAB_ALLOC

    // more fields can be added here easily
} malloc_state;

// global malloc state
static malloc_state allocator_state;

/* search schemes */
static free_block_header* first_fit(size_t size);
static free_block_header* best_fit(size_t size);
static free_block_header* worst_fit(size_t size);

typedef free_block_header* (*search_function)(size_t);
search_function search_function_registry[] = {
    first_fit,
    best_fit,
    worst_fit
};

/* utility functions */
static free_block_header* get_more_heap(size_t extension_size);
static free_block_header *find_free_block(size_t size);
static free_block_header *split_block(free_block_header *block, size_t size);
static void coalesce();

/* Initialize malloc */
static void init_malloc_state(void);

/* debug */
#if (DEBUG)
static void mm_print_free_list();
#endif

void mm_init()
{
    init_malloc_state();

    void *heap_start = cm_sbrk(BASE_BRK_INCREMENT);

    if (!heap_start)
    {
        LOG_ERROR("sbrk failure. can't initialize heap.\n");
        exit(1);
    }

    // initialize the free list
    size_t free_block_size = BASE_BRK_INCREMENT - FREE_BLOCK_HEADER_SZ;
    allocator_state.free_list_head = (free_block_header *)heap_start;
    PLACE_FREE_BLOCK(heap_start, free_block_size, NULL);
}

void *mm_malloc(size_t size)
{
    LOG_DEBUG("malloc(%ld)\n", size);

    // align the size
    size = size < BASIC_ALLOC_SZ ? BASIC_ALLOC_SZ : ALIGN_SIZE(size);

    // find a free block
    free_block_header *free_block = find_free_block(size);

    // split the block if needed
    free_block = split_block(free_block, size);
    if (free_block == ERR_HEAP_FAILURE)
    {
        return NULL;
    }

    if (free_block == allocator_state.free_list_head && free_block->next == NULL)
    {
        get_more_heap(BASE_BRK_INCREMENT);
    }

    // update the free list state
    free_block_header *curr = allocator_state.free_list_head;
    if (curr == free_block)
    {
        allocator_state.free_list_head = curr->next;
        // assert(allocator_state.free_list_head != NULL);
    }
    else
    {
        for (; curr->next != free_block; curr = curr->next)
            ;
        curr->next = free_block->next;
    }

    // place the allocated block header
    void *alloc_block = NULL;
    if (free_block)
    {
        alloc_block = free_block;
        PLACE_ALLOC_BLOCK(alloc_block, free_block->size);
    }

    // simply return the payload after the very first header
    LOG_DEBUG("Returning %p\n", PTR_ADD(alloc_block, ALLOC_BLOCK_HEADER_SZ));
    return PTR_ADD(alloc_block, ALLOC_BLOCK_HEADER_SZ);
}

// FREE THE MEMORY
void mm_free(void *ptr)
{
    LOG_DEBUG("free(%p)\n", ptr);

    if (!ptr)
    {
        LOG_ERROR("NULL pointer passed to free\n");
        return;
    }

    // get the allocated block header
    alloc_block_header *alloc_block = PTR_SUB(ptr, ALLOC_BLOCK_HEADER_SZ);
    // check if the magic number is correct
    if (alloc_block->magic != MAGIC)
    {
        LOG_ERROR("Invalid pointer passed to free\n");
        return;
    }

    // get the size of the block
    size_t size = alloc_block->size;

    // place the free block header
    free_block_header *free_block = (free_block_header*)alloc_block;
    PLACE_FREE_BLOCK(free_block, size, NULL);

    // add the free block to the free list
    // current mechanism keeps the blocks in the free list always in the ascending order
    free_block_header *curr = allocator_state.free_list_head;
    free_block_header *prev = NULL;

    while (curr < free_block && curr != NULL)
    {
        prev = curr;
        curr = curr->next;
    }

    free_block->next = curr;

    if (prev)
    {
        prev->next = free_block;
    }
    else
    {
        allocator_state.free_list_head = free_block;
        // assert(allocator_state.free_list_head != NULL);
    }
    
    // coalesce the free blocks
    coalesce();
}

void* mm_realloc(void* ptr, size_t size)
{
    LOG_DEBUG("realloc(%p, %ld)\n", ptr, size);

    // if ptr is NULL, the call is equivalent to a malloc call for the given size
    if (!ptr)
    {
        return mm_malloc(size);
    }

    // if the size is 0, the call is equivalent to a free call.
    if (size == 0)
    {
        mm_free(ptr);
        return NULL;
    }

    // align the size
    size = ALIGN_SIZE(size);

    // get the allocated block header
    alloc_block_header *alloc_block = PTR_SUB(ptr, ALLOC_BLOCK_HEADER_SZ);
    LOG_DEBUG("alloc block at : %p\n", alloc_block);
    LOG_DEBUG("alloc block's magic : %ld\n", alloc_block->magic);
    // check if the magic number is correct
    if (alloc_block->magic != MAGIC)
    {
        LOG_ERROR("Invalid pointer passed to realloc\n");
        return NULL;
    }

    // store the contens of the alloc block's header
    size_t old_size = alloc_block->size;
    long magic = alloc_block->magic;

    LOG_DEBUG("Old size vs New size : %ld, %ld\n", old_size, size);

    if (size < old_size)
    {
        // split the block if possible
        free_block_header* block = split_block((free_block_header*) alloc_block, size);

        // new splitted block, if any.
        // note if the block is not split, this will be equal to the magic number
        free_block_header* free_block = block->next;
        if ((long) free_block == magic)
        {
            PLACE_ALLOC_BLOCK(block, old_size);
            return ptr;
        }

        // add the free block to the free list
        // current mechanism keeps the blocks in the free list always in the ascending order
        free_block_header *curr = allocator_state.free_list_head;
        free_block_header *prev = NULL;

        while (curr < free_block && curr != NULL)
        {
            prev = curr;
            curr = curr->next;
        }

        free_block->next = curr;

        if (prev)
        {
            prev->next = free_block;
        }
        else
        {
            allocator_state.free_list_head = free_block;
        }
        
        // coalesce the free blocks
        coalesce();

        PLACE_ALLOC_BLOCK(block, size);
        return ptr;
    }
    else if (size > old_size)
    {
        // if the size is greater than the old size, we need to allocate a new block and copy the data
        void* new_ptr = mm_malloc(size);
        if (!new_ptr)
        {
            return NULL;
        }

        memcpy(new_ptr, ptr, old_size);
        mm_free(ptr);

        return new_ptr;
    }
    else
    {
        return ptr;
    }

    return NULL;
}


/**
 * @brief Prints the state of the free list.
 * 
 */
#if DEBUG
void mm_print_free_list()
{
    LOG_DEBUG("FREE LIST STATE: ");
    free_block_header *curr = allocator_state.free_list_head;
    for (; curr != NULL; curr = curr->next)
    {
        assert(curr->next != curr);
        if (curr->next)
            assert(curr->next->next != curr);
        printf("(%p, %zu, %p) -> ", curr, curr->size, curr->next);
    }
    printf("\n");
}
#endif

/**
 * @brief Initializes the malloc state. This function is called by the mm_init function, which initializes the allocator.
 * 
 */
void init_malloc_state(void)
{
    allocator_state.free_list_head = NULL;

    // check the env variable for the search scheme
    char *search_scheme = getenv(SEARCH_SCHEME_ENV);
    if (search_scheme)
    {
        if (strcmp(search_scheme, "FIRST_FIT") == 0)
        {
            allocator_state.search_scheme = FIRST_FIT;
        }
        else if (strcmp(search_scheme, "BEST_FIT") == 0)
        {
            allocator_state.search_scheme = BEST_FIT;
        }
        else if (strcmp(search_scheme, "WORST_FIT") == 0)
        {
            allocator_state.search_scheme = WORST_FIT;
        }
        else
        {
            LOG_ERROR("invalid search scheme: %s\n", search_scheme);
            exit(1);
        }
    }
    else
    {
        allocator_state.search_scheme = FIRST_FIT;
    }
}

/**
 * @brief Finds the first free block of size atleast "size" bytes. Returns NULL if no such block is found.
 * 
 * @param size Size of the block to be allocated.
 * @return free_block_header* Pointer to the first byte of the free block. NULL if no such block is found.
 */
static free_block_header* first_fit(size_t size)
{
    free_block_header *curr = allocator_state.free_list_head;
    for (; curr != NULL; curr = curr->next)
    {
        if (curr->size >= size)
        {
            return curr;
        }
    }

    return NULL;
}

/**
 * @brief Finds the best fit free block of size atleast "size" bytes. Returns NULL if no such block is found.
 * 
 * @param size Size of the block to be allocated.
 * @return free_block_header* Pointer to the first byte of the free block. NULL if no such block is found.
 */
static free_block_header* best_fit(size_t size)
{
    free_block_header *curr = allocator_state.free_list_head;
    free_block_header *best = NULL;
    for (; curr != NULL; curr = curr->next)
    {
        if (curr->size >= size)
        {
            if (best == NULL || curr->size < best->size)
            {
                best = curr;
            }
        }
    }

    return best;
}

/**
 * @brief Finds the worst fit free block of size atleast "size" bytes. Returns NULL if no such block is found. Worst fit is the block with the largest size that fits the allocation size.
 * 
 * @param size Size of the block to be allocated.
 * @return free_block_header* Pointer to the first byte of the free block. NULL if no such block is found.
 */
static free_block_header* worst_fit(size_t size)
{
    free_block_header *curr = allocator_state.free_list_head;
    free_block_header *worst = NULL;
    for (; curr != NULL; curr = curr->next)
    {
        if (curr->size >= size)
        {
            if (worst == NULL || curr->size > worst->size)
            {
                worst = curr;
            }
        }
    }

    return worst;
}

/**
 * @brief Extends the heap by "extension_size" bytes. Returns the pointer to the newly allocated free block. Returns (void*)-1 if the heap cannot be extended.
 * 
 * @param extension_size Size of the heap extension.
 * @return free_block_header* Pointer to the first byte of the newly allocated free block. (void*)-1 if the heap cannot be extended.
 */
static free_block_header* get_more_heap(size_t extension_size)
{
    void *heap_start = cm_sbrk(extension_size);

    if (!heap_start)
    {
        LOG_ERROR("sbrk failure. can't extend heap.\n");
        return (void *)-1;
    }

    // initialize the free block
    PLACE_FREE_BLOCK(heap_start, extension_size - FREE_BLOCK_HEADER_SZ, NULL);

    // add the free block to the free list
    free_block_header *new_block = (free_block_header *)heap_start;

    free_block_header* curr = allocator_state.free_list_head;
    for (; curr->next != NULL; curr = curr->next);
    curr->next = new_block;

    return new_block;
}

/**
 * @brief Finds a free block of size atleast "size" bytes. If no such block is found, extends the heap by atleast "size" bytes and returns the pointer to the newly allocated free block. Returns (void*)-1 if the heap cannot be extended.
 * 
 * @param size Size of the block to be allocated.
 * @return free_block_header* Pointer to the first byte of the free block. (void*)-1 if the heap cannot be extended.
 */
static free_block_header *find_free_block(size_t size)
{
    // free_block_header* block = search_function_registry[allocator_state.search_scheme](size);
    
    // same thing as above, i was just being fancy but it turned out to be slower
    free_block_header* block = NULL;
    switch (allocator_state.search_scheme)
    {
    case FIRST_FIT:
        block = first_fit(size);
        break;
    case BEST_FIT:
        block = best_fit(size);
        break;
    case WORST_FIT:
        block = worst_fit(size);
        break;
    default:
        return NULL;
    }

    if (block)
        return block;

    // Base sbrk increment or the size of the block to be allocated, whichever is greater
    size_t extension_size = MAX(BASE_BRK_INCREMENT, ALIGN_SIZE(size + FREE_BLOCK_HEADER_SZ));
    // size_t extension_size = ALIGN_SIZE(size + FREE_BLOCK_HEADER_SZ);
    
    free_block_header* new_block = get_more_heap(extension_size);

    if (new_block == (void*)-1)
    {
        return (void*)-1;
    }

    return new_block;
}

/**
 * @brief Splits the block into two blocks, one of size "size" and the other of the remaining size. Returns the pointer to the first block.
 * 
 * @param block Pointer to the block to be split.
 * @param size Required split size.
 * @return free_block_header* Pointer to the first block.
 */
static free_block_header *split_block(free_block_header *block, size_t size)
{
    // check if the size is enough to split
    // the size of the new block after split must be atleast the size of the header plus the basic allocation size
    // also return the same block as it is if theres more than 1 blocks in free list
    // and the
    if (block->size < size + FREE_BLOCK_HEADER_SZ + BASIC_ALLOC_SZ)
    {
        return block;
    }

    // split the block
    size_t new_block_size = block->size - size - FREE_BLOCK_HEADER_SZ;

    // place the new block
    void *new_block_addr = PTR_ADD(block, FREE_BLOCK_HEADER_SZ + size);
    PLACE_FREE_BLOCK(new_block_addr, new_block_size, block->next);

    // update the current block
    block->size = size;
    block->next = (free_block_header *)new_block_addr;

    return block;
}

/**
 * @brief Coalesces the free blocks in the free list.
 * 
 */
static void coalesce()
{
    free_block_header *curr = allocator_state.free_list_head;
    for (; curr != NULL; curr = curr->next)
    {
        // assert(curr->next != curr);
        if (curr->next == NULL)
        {
            break;
        }

        if (PTR_ADD(curr, curr->size + FREE_BLOCK_HEADER_SZ) == curr->next)
        {
            curr->size += curr->next->size + FREE_BLOCK_HEADER_SZ;
            curr->next = curr->next->next;
        }
    }
}