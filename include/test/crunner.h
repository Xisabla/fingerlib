/**
 * @file crunner.h
 * @author Gautier Miquet
 * @brief Helpers macros for running C tests
 * @version 0.1.0
 * @date 2023-06-16
 */
#ifndef TEST_CRUNNER_H
#define TEST_CRUNNER_H

#include <stdio.h>
#include <time.h>

#define CTEST_INIT()                                                        \
    int __TEST_RC = 0, __TEST_CNT = 0, __TEST_RT;                           \
    clock_t __TEST_START = clock(), __TEST_END, __TEST_USTART, __TEST_UEND; \
    int __TEST_ELP, __TEST_UELP;

#define CTEST_RUN(FNC)                                                              \
    __TEST_USTART = clock();                                                        \
    __TEST_RT = FNC();                                                              \
    __TEST_UEND = clock();                                                          \
    __TEST_UELP = (int)(((double) 1000 * (__TEST_UEND - __TEST_USTART)) / CLOCKS_PER_SEC); \
    if (__TEST_RT == 0) printf("TEST(" #FNC ") - %d ms\n", __TEST_UELP);            \
    else {                                                                          \
        printf("TEST(" #FNC ")\n%s:%d: Failure in TEST("#FNC")\n  - %d ms\n", __FILE__, __LINE__, __TEST_UELP);           \
        __TEST_RC += 1;                                                             \
    }                                                                               \
    __TEST_CNT += 1;

#define CTEST_END()                                                          \
    __TEST_END = clock(); \
        __TEST_ELP = (int)(((double) 1000 * (__TEST_END - __TEST_START)) / CLOCKS_PER_SEC); \
    if (__TEST_RC == 0) printf("\nOK (%d test, 0 fails, %d ms)\n\n", __TEST_CNT, __TEST_ELP);     \
    else                                                                     \
        printf("\nErrors (%d failures, %d tests, %d ms)\n\n", __TEST_RC, __TEST_CNT, __TEST_ELP); \
    return __TEST_RC

#endif // TEST_CRUNNER_H
