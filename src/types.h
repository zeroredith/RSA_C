#ifndef TYPES_H
#define TYPES_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>


typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

typedef float f32;
typedef double f64;

#define internal static
#define global static
#define null NULL
#define __packed __attribute__((packed))
#define static_assert _Static_assert
#define function
#endif

