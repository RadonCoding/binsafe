#pragma once

#if defined(__GNUC__) || defined(__clang__)
#define BINSAFE __attribute__((section(".binsafe"), noinline))
#elif defined(_MSC_VER)
#define BINSAFE __declspec(code_seg(".binsafe")) __declspec(noinline)
#else
#define BINSAFE
#endif
