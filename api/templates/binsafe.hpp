#pragma once

#define BINSAFE_BEGIN() \
    __label__ _l##__LINE__; \
    __asm__ volatile(".byte {begin}" ::: "memory"); \
    __asm__ goto("" :::: _l##__LINE__)

#define BINSAFE_END() \
    _l##__LINE__: \
    __asm__ volatile(".byte {end}" ::: "memory")
    