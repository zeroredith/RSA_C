#ifndef TYPEDEF_GEN_H
#define TYPEDEF_GEN_H

#define function

#include "types.h" 

// 
// STRUCT DEFS
// 
typedef struct String String;
typedef struct String String;
typedef struct String_Builder_Arena String_Builder_Arena;
typedef struct String_Builder String_Builder;
typedef struct Flat_Arena Flat_Arena;
typedef struct Arena Arena;
typedef struct Allocator Allocator;
typedef struct Context Context;
typedef struct RSA_Keys RSA_Keys;
typedef struct Public_Key Public_Key;

// 
// ENUM DEFS
// 

// 
// UNION DEFS
// 

// 
// FUNCTION DEFS
// 
internal inline void* _temp_allocator_func(void* data, u64 size);
internal inline void _temp_allocator_free_func(void* data);
internal inline Flat_Arena flat_arena_new(u64 size);
internal inline Arena* arena_new(u64 size);
internal inline void arena_reset(Arena* arena);
internal inline void arena_free(Arena* arena);
internal inline void* arena_alloc(Arena* arena, u64 size);
internal inline String_Builder sb_init(u64 initial_capacity);
internal inline String sb_to_string(String_Builder sb);
internal inline void string_to_file(String path, String s);
internal inline String_Builder string_to_sb(String s);
internal inline void sb_append(String_Builder* sb, String s);
internal inline void sb_append_at(String_Builder* sb, String s, s64 at);
internal inline void sb_remove_single_char_at(String_Builder* sb, s64 at);
internal inline void sb_remove_from_to(String_Builder* sb, s64 from, s64 to);
internal inline void sb_append_char(String_Builder* sb, char c);
internal inline String_Builder_Arena sb_init_arena(Arena* arena, u64 initial_capacity);
internal inline void sb_reset(String_Builder_Arena* sb);
internal inline void sb_arena_append(String_Builder_Arena* sb, char* data, u64 count);
internal inline bool sb_arena_append_char(String_Builder_Arena* sb, char c);
internal inline void sb_arena_pop(String_Builder_Arena* sb);
internal inline String sb_read_line(String_Builder* sb, s64* cursor);
internal inline bool sb_read_line_from_line(String_Builder_Arena* sb, FILE* f, u64* line_count);
internal inline String temp_c_string(String s);
internal inline String string_from_cstring(char* cstr);
internal inline String to_string(char* cstr);
internal inline String string_reserve(u64 size);
internal inline String string_slice(String s, u64 start, u64 new_len);
internal inline String string_arena(Arena* arena, char* str);
internal inline String string_arena_init(Arena* arena, u64 size);
internal inline String string_to_string(Arena* arena, String* str);
internal inline String string_to_cstr(String str, Arena* arena);
internal inline String string_copy(String src, Arena* arena);
internal inline bool string_copy_to(String src, String* dest, Arena* arena);
internal inline bool is_cstr(String* str);
internal inline void to_cstr(String* str);
internal inline bool string_scmp(String s1, String s2, u64 length);
internal inline bool string_cmp(String s1, String s2);
internal inline bool cstring_cmp(String s1, char* s2);
internal inline void trimlp(String_Builder* s);
internal inline void trimrp(String_Builder* s);
internal inline void trimp(String_Builder* s);
internal inline String trim_slice(String s);
internal inline bool starts_with(String s, String starts);
internal inline void prints(String s);
internal inline void printsln(String s);
internal inline String read_entire_file(String path);
internal inline s64 string_contains(String source, String target);

#endif
