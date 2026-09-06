#pragma once

#define BINSAFE_BEGIN() \
    { \
        __asm__ volatile(".byte {begin}" ::: "memory");

#define BINSAFE_END() \
        __asm__ volatile(".byte {end}" ::: "memory"); \
    }
    