#include "mm_lib.h"
#include "utils.h"
#include "core_mem.h"

// forcing debug statements to be printed (or not, set to 0 to get rid of them)
#ifdef DEBUG
#undef DEBUG
#define DEBUG 1
#endif

int main()
{
    cm_init_memory();
    mm_init();

    // your logic goes from here

    LOG_PRINT("Hello\n");
    
    if (IS_ALIGNED(cm_heap_start(), 8))
        LOG_DEBUG("Memory 8 byte aligned.\n");

    int* test = (int*) mm_malloc(sizeof(int));
    LOG_DEBUG("Allocated %zu bytes at %p\n", sizeof(int), test);

    // till here

    cm_free_memory();

    return 0;
}