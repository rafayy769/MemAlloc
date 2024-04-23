#include "mm_lib.h"
#include "core_mem.h"
#include "utils.h"
#include "pretty_tests.h"
#include "driver_config.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>

#ifdef DEBUG
#undef DEBUG
#endif
#ifdef ANNOTATIONS
#undef ANNOTATIONS
#endif

#define DEBUG 1
#define ANNOTATIONS 1

#define SEARCH_SCHEME_ENV "SEARCH_SCHEME"

// define the list of tests to be run here.
// this will be used with X macros to avoid a lot of repetition
#define LIST_OF_TESTS \
    X(FIRST_FIT)      \
    X(WORST_FIT)      \
    X(BEST_FIT)

typedef void *(*allocator_fn_t)(size_t);
typedef void (*deallocator_fn_t)(void *);
typedef void *(*reallocator_fn_t)(void *, size_t);

// Just a macro to make the code look cleaner, i really couldnt add this after every malloc call
#define ASSERT_MALLOC(ptr)                      \
    if (ptr == NULL)                            \
    {                                           \
        LOG_ERROR("Error allocating memory\n"); \
        cm_free_memory();                       \
        exit(1);                                \
    }

/* Compound types and structs */
// represents a single malloc/free/realloc call, belonging to a unique malloc call.
typedef struct
{
    enum
    {
        MALLOC,
        FREE,
        REALLOC
    } type;   // type of request
    int id;   // id of the malloc call
    int size; // size of the malloc/realloc call
} trace_req_t;

// represents the memory blocks in the heap.
typedef struct memblock_node
{
    char *start;
    char *end;

    int id;
    size_t size;

    struct memblock_node *next;
} memblock_node_t;

// contains the stats
typedef struct
{
    size_t total_requested_memory;
    size_t memory_in_use;
    size_t heap_size;

    double total_malloc_time;
    size_t ran_mallocs;
    double total_free_time;
    size_t ran_frees;
    double total_realloc_time;
    size_t ran_reallocs;
} test_stats_t;

// contains information about the trace file.
typedef struct
{
    int num_ids;  // number of unique malloc ids. each id with a free/realloc/malloc corresponds to a unique malloc call.
    int num_reqs; // total number of malloc/free/realloc calls

    trace_req_t *reqs;          // array of malloc/free/realloc calls
    memblock_node_t *memblocks; // linked list of memory blocks

    test_stats_t stats; // stats for the test

    char *trace_name; // name of the trace file
} trace_file_t;

/* Globals */
// the memory management functions to use, by default they are student's functions
static allocator_fn_t ALLOC_ALLOC = &mm_malloc;
static deallocator_fn_t ALLOC_FREE = &mm_free;
static reallocator_fn_t ALLOC_REALLOC = &mm_realloc;

static char *default_trace_files[] = {
    DEFAULT_TRACE_FILES,
    NULL
};

/* Functions declarations */
// memblock functions
int addMemBlock(memblock_node_t **head, char *start, int size, int id);
int removeMemBlock(memblock_node_t **head, int id);
int cleanupMemBlocks(memblock_node_t **head);
int verifyOverlap(memblock_node_t *head, char *start, int size);

// trace file functions
trace_file_t *parseTraceFile(char *filename);
void cleanUpTrace(trace_file_t *trace_file);
int runTrace(trace_file_t *trace_file);

// testing functions
int *test_trace_files(char **trace_files, trace_file_t **traces);
void printStats(trace_file_t **traces, int num_traces);

// helpers
void usage(void);
void dumpHex(const char *ptr, size_t size, int index);

int main(int argc, char *argv[])
{
    int opt;
    int custom_trace_files = 0;
    int num_trace_files = NUM_DEFAULT_TRACE_FILES;
    char **trace_files = default_trace_files;

    extern int optind;

    NEWLINE;
    LOG_HEADER("Memory Management Library Test Suite");
    NEWLINE;
// macro to set the search scheme
// should set the rest of the schemes from the list of tests to 0
#define X(scheme)          \
    if (#scheme[0] == opt) \
        scheme = 1;        \
    else                   \
        scheme = 0;

    while ((opt = getopt(argc, argv, "hltFBWS:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            usage();
            exit(0);
        case 'l':
            ALLOC_ALLOC = &malloc;
            ALLOC_FREE = &free;
            ALLOC_REALLOC = &realloc;
            EVAL_LIBC = 1;
            BEST_FIT = 1;
            WORST_FIT = 0;
            FIRST_FIT = 0;
            break;
        case 't':
            custom_trace_files = 1;
            num_trace_files = argc - optind;
            trace_files = &argv[optind];
            break;
        case 'F':
        case 'W':
        case 'B':
        case 'S':
            LIST_OF_TESTS
            break;
        default:
            LOG_ERROR("Usage: (driver or make driver ARGS=) [-l] [-B OR -W OR -F OR -S] [-t [trace_file1 [trace_file2 ...]]]\n\n");
            exit(1);
        }
    }

#undef X

    if (custom_trace_files && num_trace_files == 0)
    {
        LOG_ERROR("At least one trace file must be provided with -t flag.\n");
        exit(1);
    }

    // print the test configuration summary before running the tests
    LOG_TEST_UNDERLINE("Tests Configuration Summary");
    LOG_OUT("Using %s memory management functions\n", EVAL_LIBC ? "libc" : "student");
    if (!EVAL_LIBC)
    {
        LOG_OUT("Testing algorithms : ");

    #define X(TEST)                \
        if (TEST)                  \
        {                          \
            LOG_OUT("%s ", #TEST); \
        }
        LIST_OF_TESTS
        NEWLINE;
    #undef X
    }

    LOG_OUT("Using %s trace files\n", custom_trace_files ? "custom" : "default");
    NEWLINE;

    LOG_OUT("...\n");

    int total_tests = 0;
    int tests_passed = 0;

    assert(num_trace_files != 0);

    #define X(TEST) \
        trace_file_t **TEST##_TRACES_ARRAY = NULL; \
        if (TEST) \
        { \
            TEST##_TRACES_ARRAY = malloc((num_trace_files) * sizeof(trace_file_t *)); \
            for (int i = 0; i < num_trace_files; i++) \
            { \
                TEST##_TRACES_ARRAY[i] = NULL; \
            } \
        } \

    LIST_OF_TESTS
    #undef X

// an X macro. basically this same block of code gets executed for all the test names defined in the LIST_OF_TESTS macro, just a handy way to avoid repetition. This way new tests can be added easily by just adding to the list of tests, and without changing anything else in the code.
#define X(SCHEME)                                                            \
    if (SCHEME)                                                              \
    {                                                                        \
        const char *scheme_string = #SCHEME;                                 \
        NEWLINE;                                                             \
        if (!EVAL_LIBC)                                                      \
            LOG_RUN_TEST("%s\n", scheme_string);                             \
        setenv(SEARCH_SCHEME_ENV, scheme_string, 1);                         \
        int *results = test_trace_files(trace_files, SCHEME##_TRACES_ARRAY); \
        tests_passed += results[0];                                          \
        total_tests += results[1];                                           \
        free(results);                                                       \
    }

    LIST_OF_TESTS
#undef X

    NEWLINE;
    LOG_TEST_UNDERLINE("Tests Summary");
    LOG_TEST_RESULT("Total tests: ", "%d\n", total_tests);
    LOG_TEST_RESULT("Tests passed:", " %d\n", tests_passed);
    LOG_TEST_RESULT("Tests failed:", " %d\n", total_tests - tests_passed);
    NEWLINE;

    LOG_TEST_UNDERLINE("Statistics");

// another one of those. prints stats for each test that was ran, from the LIST_OF_TESTS
#define X(SCHEME)                                           \
    if (SCHEME)                                             \
    {                                                       \
        NEWLINE;                                            \
        if (!EVAL_LIBC)                                     \
            LOG_COLORED(LOG_BOLDGREEN, "%s\n", #SCHEME);    \
        printStats(SCHEME##_TRACES_ARRAY, num_trace_files); \
    }

        LIST_OF_TESTS
#undef X

    return 0;
}

/* Functions definitions */
// memblock functions
int verifyOverlap(memblock_node_t *head, char *start, int size)
{
    if (head == NULL)
        return 0;

    if (!EVAL_LIBC)
    {
        // check if the block lies within the bounds of the heap
        if (start < (char *)cm_heap_start() || PTR_ADD(start, size) > cm_heap_end())
        {
            LOG_ERROR("A memory block lies outside the bounds of the heap\n");
            LOG_DEBUG("Start: %p, End: %p, Heap Start: %p, Heap End: %p\n", start, PTR_ADD(start, size), cm_heap_start(), cm_heap_end());
            LOG_DEBUG("Heap size (kb): %ld\n", cm_heap_size() / 1024);
            return 1;
        }
    }

    // check if the new block overlaps with any existing block
    for (memblock_node_t *curr = head; curr != NULL; curr = curr->next)
    {
        if ((start >= curr->start && start < curr->end) ||
            ((char *)PTR_ADD(start, size) > curr->start && (char *)PTR_ADD(start, size) <= curr->end))
        {
            LOG_ERROR("Memory block overlaps with existing memory blocks\n");
            LOG_DEBUG("New block: %p - %p, Existing block: %p - %p\n", start, PTR_ADD(start, size), curr->start, curr->end);
            return 1;
        }
    }

    return 0;
}

int addMemBlock(memblock_node_t **head, char *start, int size, int id)
{
    if (verifyOverlap(*head, start, size) != 0)
    {
        return 1;
    }

    // check the alignment of the block
    if (!IS_ALIGNED(start, ALIGNMENT))
    {
        LOG_ERROR("Memory block is not %ld byte aligned\n", ALIGNMENT);
        LOG_DEBUG("Start: %p, End: %p\n", start, PTR_ADD(start, size));
        return 1;
    }

    memblock_node_t *new_node = (memblock_node_t *)malloc(sizeof(memblock_node_t));
    ASSERT_MALLOC(new_node);

    new_node->start = start;
    new_node->end = start + size;
    new_node->size = size;
    new_node->next = *head;
    new_node->id = id;

    *head = new_node;

    return 0;
}

int removeMemBlock(memblock_node_t **head, int id)
{
    if (*head == NULL)
    {
        LOG_ERROR("Memory block list is empty\n");
        return 1;
    }

    memblock_node_t *curr = *head;
    memblock_node_t *prev = NULL;

    while (curr != NULL)
    {
        if (curr->id == id)
        {
            if (prev == NULL)
            {
                *head = curr->next;
            }
            else
            {
                prev->next = curr->next;
            }

            free(curr);
            return 0;
        }

        prev = curr;
        curr = curr->next;
    }

    LOG_ERROR("Memory block not found\n");
    LOG_DEBUG("Requested ID: %d\n", id);
    return 1;
}

int cleanupMemBlocks(memblock_node_t **head)
{
    if (*head == NULL)
    {
        LOG_ERROR("Memory block list is empty\n");
        return 1;
    }

    memblock_node_t *curr = *head;
    memblock_node_t *next = NULL;

    while (curr != NULL)
    {
        next = curr->next;
        free(curr);
        curr = next;
    }

    *head = NULL;

    return 0;
}

// trace file functions
trace_file_t *parseTraceFile(char *filename)
{
    char path[MAX_STRING_LENGTH];
    strcpy(path, TRACE_PATH);
    strcat(path, filename);

    FILE *fp = fopen(path, "r");
    if (fp == NULL)
    {
        LOG_ERROR("Error opening trace file %s. EXITING TEST PROGRAM.\n", filename);
        exit(1);
    }

    int num_reqs = 0;
    int num_mallocs = 0;
    int num_frees = 0;
    int num_reallocs = 0;

    // read the header
    fscanf(fp, "%d", &num_reqs);
    fscanf(fp, "%d", &num_mallocs);
    fscanf(fp, "%d", &num_frees);
    fscanf(fp, "%d", &num_reallocs);

    // create the trace file
    trace_file_t *trace_file = (trace_file_t *)malloc(sizeof(trace_file_t));
    ASSERT_MALLOC(trace_file);

    trace_file->num_ids = num_mallocs;
    trace_file->num_reqs = num_reqs;
    trace_file->trace_name = COPY(filename);
    trace_file->memblocks = NULL;

    LOG_TEST_INFO("Trace: %s\n", trace_file->trace_name);
    LOG_TEST_INFO("Operations: %d, Mallocs: %d, Frees: %d, Reallocs: %d\n", trace_file->num_reqs, trace_file->num_ids, num_frees, num_reallocs);

    // read the traces
    trace_req_t *reqs = (trace_req_t *)malloc(num_reqs * sizeof(trace_req_t));
    ASSERT_MALLOC(reqs);

    int id = 0;
    int size = 0;

    char op[MAX_STRING_LENGTH];
    int op_idx = 0;

    while (fscanf(fp, "%s", op) != EOF)
    {
        switch (op[0])
        {
        case 'M':
            fscanf(fp, "%d %d", &id, &size);
            reqs[op_idx].type = MALLOC;
            reqs[op_idx].id = id;
            reqs[op_idx].size = size;
            break;

        case 'F':
            fscanf(fp, "%d", &id);
            reqs[op_idx].type = FREE;
            reqs[op_idx].id = id;
            reqs[op_idx].size = 0;
            break;

        case 'R':
            fscanf(fp, "%d %d", &id, &size);
            reqs[op_idx].type = REALLOC;
            reqs[op_idx].id = id;
            reqs[op_idx].size = size;
            break;

        default:
            LOG_ERROR("Invalid operation %c in trace file\n", op[0]);
            exit(1);
        }

        op_idx++;

        if (op_idx > num_reqs)
        {
            LOG_ERROR("Number of operations in trace file is greater than the number of operations specified in the header\n");
            exit(1);
        }
    }

    if (op_idx < num_reqs)
    {
        LOG_ERROR("Number of operations in trace file is lesser than the number of operations specified in the header\n");
        exit(1);
    }

    trace_file->reqs = reqs;

    fclose(fp);

    return trace_file;
}

void dumpHex(const char *ptr, size_t size, int index)
{
    if (ptr == NULL || size == 0)
    {
        LOG_ERROR("Invalid arena.\n");
        return;
    }

    int dumpSize = (size < 50) ? size : 21; // Either dump the entire arena or 21 bytes around the index
    int start = dumpSize == size ? 0 : ((index - 10 < 0) ? 0 : index - 10);
    int end = dumpSize == size ? size : ((index + 10 >= size) ? size : index + 10);

    if (start != 0)
    {
        LOG_OUT("...\n");
    }
    for (int i = start; i < end; i++)
    {
        if (i == index)
        {
            // Print the current index in red
            LOG_COLORED(LOG_BOLDRED, "%02x ", (unsigned char)ptr[i]);
        }
        else
        {
            LOG_COLORED(LOG_WHITE, "%02x ", (unsigned char)ptr[i]);
        }

        if ((i + 1) % 8 == 0)
        {
            LOG_OUT(" ");
        }

        if ((i + 1) % 16 == 0 || i == end - 1)
        {
            if (i == end - 1)
            {
                int remainingSpaces = 16 - ((i + 1) % 16);
                for (int j = 0; j < remainingSpaces; j++)
                {
                    LOG_OUT("   ");
                }
            }
            NEWLINE;
        }
    }
    if (end != size)
    {
        LOG_OUT("...\n");
    }
}

int runTrace(trace_file_t *trace_file)
{
    if (!trace_file)
    {
        LOG_ERROR("Trace file is NULL\n");
        return 1;
    }

    // initialize the heap
    if (!EVAL_LIBC)
    {
        cm_reset_heap();
        mm_init();
    }

    // run the trace
    for (int i = 0; i < trace_file->num_reqs; i++)
    {
        trace_req_t request = trace_file->reqs[i];
        clock_t start, end;

        switch (request.type)
        {
        case MALLOC:
            start = clock();
            void *ptr = ALLOC_ALLOC(request.size);
            end = clock();

            if (ptr == NULL)
            {
                LOG_ERROR("Error allocating memory\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Malloc, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
                return 1;
            }

            if (addMemBlock(&trace_file->memblocks, ptr, request.size, request.id) != 0)
            {
                LOG_ERROR("Error adding memory block\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Malloc, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
                return 1;
            }

            memset(ptr, request.id & 0xFF, request.size);

            trace_file->stats.total_requested_memory += request.size;
            trace_file->stats.memory_in_use += request.size;

            trace_file->stats.total_malloc_time += ((double)(end - start)) / CLOCKS_PER_SEC;
            trace_file->stats.ran_mallocs++;

            break;

        case FREE:
            memblock_node_t *curr = trace_file->memblocks;
            for (; (curr != NULL && curr->id != request.id); curr = curr->next)
                ;
            if (!curr)
            {
                LOG_ERROR("No corresponding memory block found for this free call.\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Free, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
                return 1;
            }
            
            start = clock();
            ALLOC_FREE(curr->start);
            end = clock();

            if (removeMemBlock(&trace_file->memblocks, curr->id) != 0)
            {
                LOG_ERROR("Failed to remove memory block.\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Free, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
            }

            trace_file->stats.memory_in_use -= curr->size;

            trace_file->stats.total_free_time += ((double)(end - start)) / CLOCKS_PER_SEC;
            trace_file->stats.ran_frees++;

            break;

        case REALLOC:
            curr = trace_file->memblocks;
            for (; (curr != NULL && curr->id != request.id); curr = curr->next)
                ;
            if (!curr)
            {
                LOG_ERROR("No corresponding memory block found for this realloc call.\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Realloc, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
                return 1;
            }

            int old_size = curr->size;
            char *old_ptr = curr->start;

            if (removeMemBlock(&trace_file->memblocks, curr->id) != 0)
            {
                LOG_ERROR("Failed to remove memory block.\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Free, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
            }

            start = clock();
            char *test = ALLOC_REALLOC(old_ptr, request.size);
            end = clock();

            if (test == NULL)
            {
                LOG_ERROR("Error reallocating memory\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Realloc, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
                return 1;
            }

            if (addMemBlock(&trace_file->memblocks, test, request.size, request.id) != 0)
            {
                LOG_ERROR("Error adding memory block\n");
                LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Realloc, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);
                return 1;
            }

            // check for whether contents were preserved
            for (int i = 0; i < MIN(old_size, request.size); i++)
            {
                if (test[i] != (char)(request.id & 0xFF))
                {
                    LOG_ERROR("Memory contents after realloc weren't preserved.\n");
                    LOG_DEBUG("Trace: %s, Tracenum: %d, Req: Realloc, Size: %d, Id: %d\n", trace_file->trace_name, i, request.size, request.id);

                    // dump the memory contents
                    dumpHex(test, request.size, i);
                    LOG_DEBUG("Expected: %x, Got: %x\n", request.id % 0xFF, test[i]);
                    return 1;
                }
            }

            memset(test, request.id & 0xFF, request.size);

            int size_diff = request.size - old_size;
            trace_file->stats.total_requested_memory += size_diff;
            trace_file->stats.memory_in_use += size_diff;

            trace_file->stats.total_realloc_time += ((double)(end - start)) / CLOCKS_PER_SEC;
            trace_file->stats.ran_reallocs++;

            break;

        default:
            break;
        }
    }

    trace_file->stats.heap_size = cm_heap_size();
    LOG_TEST_SUCCESS("Test passed\n");
    return 0;
}

int *test_trace_files(char **trace_files, trace_file_t **traces)
{
    int total_tests = 0;
    int tests_passed = 0;

    for (int i = 0; trace_files[i] != NULL; i++)
    {
        char *trace_file = trace_files[i];
        total_tests++;

        trace_file_t *trace = parseTraceFile(trace_file);
        if (trace == NULL)
        {
            continue;
        }

        trace->stats.heap_size = 0;
        trace->stats.memory_in_use = 0;
        trace->stats.total_requested_memory = 0;
        trace->stats.total_free_time = 0;
        trace->stats.total_malloc_time = 0;
        trace->stats.total_realloc_time = 0;
        trace->stats.ran_frees = 0;
        trace->stats.ran_mallocs = 0;
        trace->stats.ran_reallocs = 0;

        if (!EVAL_LIBC)
        {
            cm_init_memory();
        }

        if (runTrace(trace) != 0)
        {
            LOG_TEST_FAIL("Test failed.\n");
            cm_free_memory();
            continue;
        }

        tests_passed++;
        traces[i] = trace;

        if (!EVAL_LIBC)
        {
            cm_free_memory();
        }
    }

    int *results = malloc(sizeof(int) * 2);
    results[0] = tests_passed;
    results[1] = total_tests;

    LOG_TEST_RESULT("\n   Tests passed: ", "%d/%d\n", results[0], results[1]);

    return results;
}

void printStats(trace_file_t **traces, int num_traces)
{
    if (!EVAL_LIBC)
    {
        LOG_OUT("------------------------------------------------------------------------------------------------\n");

        LOG_COLORED(LOG_BOLDWHITE, "| %-20s | %-15s | %-15s | %-15s | %-15s |\n", "Trace Name", "Requested (kB)", "In Use (kB)", "Heap Size (kB)", "Space Util (%)");

        LOG_OUT("|----------------------------------------------------------------------------------------------|\n");

        for (int i = 0; i < num_traces; i++)
        {
            trace_file_t *trace = traces[i];
            if (!trace)
                continue;

            float util = (float)trace->stats.memory_in_use / trace->stats.heap_size;

            LOG_OUT("| %-20s | %-15f | %-15f | %-15f | %-15f |\n",
                    trace->trace_name,
                    trace->stats.total_requested_memory / 1024.0,
                    trace->stats.memory_in_use / 1024.0,
                    trace->stats.heap_size / 1024.0,
                    util * 100);
        }
        LOG_OUT("|----------------------------------------------------------------------------------------------|\n");
    }
    else
    {
        LOG_OUT("|----------------------------------------------------------------------------|\n");
    }

    LOG_COLORED(LOG_BOLDWHITE, "| %-20s | %-15s | %-15s | %-15s |\n", "Trace Name", "Avg. mlc (ms)", "Avg. realc (ms)", "Avg. free (ms)");
    LOG_OUT("|----------------------------------------------------------------------------|\n");

    for (int i = 0; i < num_traces; i++)
    {
        trace_file_t *trace = traces[i];
        if (!trace)
            continue;

        float util = (float)trace->stats.memory_in_use / trace->stats.heap_size;

        double avg_malloc = trace->stats.total_malloc_time / trace->stats.ran_mallocs;
        double avg_free = trace->stats.total_free_time / trace->stats.ran_frees;
        double avg_realloc = trace->stats.total_realloc_time / trace->stats.ran_reallocs;

        LOG_OUT("| %-20s | %-15f | %-15f | %-15f |\n",
                trace->trace_name,
                avg_malloc * 1000,
                avg_realloc * 1000,
                avg_free * 1000);
    }
    LOG_OUT("|----------------------------------------------------------------------------|\n");
}

void usage(void)
{
    LOG_COLORED(LOG_BOLDCYAN, "Usage: (driver or make driver ARGS=) [-l] [-v] [-B OR -W OR -F OR -S] [-t [trace_file1 [trace_file2 ...]]]\n\n");
    LOG_COLORED(LOG_BOLDCYAN, "Options\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-h            Print this message and exit.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-l            Run libc malloc. Is used as the standard impl. to verify the validity of trace files.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-B            Runs the driver only with the BEST_FIT search scheme.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-F            Runs the driver only with the FIRST_FIT search scheme.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-W            Runs the driver only with the WORST_FIT search scheme.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-S            Runs the driver only with the SLAB ALLOCATOR.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\t-t <file(s)>  Use <file(s)> as the trace file(s). This option should come at the end.\n");
    LOG_COLORED(LOG_BOLDCYAN, "\nNote that options specifying the allocator must be used alone. If used together the one at the last trumps all.\n\n");
}