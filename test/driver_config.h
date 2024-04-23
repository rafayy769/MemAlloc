/* The default path of the traces directory. The program will look for the trace file, specified by name, in the following directory */
#define TRACE_PATH "test/traces/"

/* The program runs these trace files by default, if no trace file is provided via the command line args. */
#define DEFAULT_TRACE_FILES \
    "huge.trace",           \
    "damn.trace",           \
    "huge2.trace",          \
    "malloc_only.trace",    \
    "easy.trace"

#define NUM_DEFAULT_TRACE_FILES 5

/* These params control the behaviour of the test program */
/* By default, only the student's allocator is tested. 
   Only the first fit allocation scheme is run with the trace files.
   You can however, use the A flag with the program to run the complete test suite.
*/
int EVAL_LIBC = 0;
int BEST_FIT  = 1;
int FIRST_FIT = 1;  // by default run the first fit allocation scheme
int WORST_FIT = 1;
// int SLAB_ALLOC = 0;
// int NEXT_FIT = 0;