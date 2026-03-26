#ifndef BASE_C
#define BASE_C

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "types.h"

typedef struct String String;
typedef struct String_Builder_Arena String_Builder_Arena;
typedef struct String_Builder String_Builder;
typedef struct Arena Arena;
typedef struct Flat_Arena Flat_Arena;
typedef struct Context Context;
typedef struct Allocator Allocator;

internal inline void* _temp_allocator_func(void* data, u64 size);
internal inline void _temp_allocator_free_func(void* data);

struct String {
	u8* data;
	u64 count;
};

struct String_Builder_Arena {
	String str;
	Arena* arena;
	u64 capacity;
};

struct String_Builder {
	u8* data;
	u64 count;
	u64 capacity;
};

struct Flat_Arena {
	u64 count;
	u64 capacity;
	u8* data;
};

struct Arena {
	u64 count;
	u64 capacity;
	u8* data;
	Arena* next;
};

struct Allocator {
	void* (*func_allocator)(void*, u64); // El void nunca se pasa manualmente, pero es necesario pasarlo explicitamente en la macro. Realmente se podria usar el context.data sin embargo esto hace que el func_allocator solo funcione con context.
	void (*func_free)(void*);
	void* data;
};

struct Context {
	Allocator allocator;
	Allocator temp_allocator;
};

internal Arena* arena_new(u64 size);
internal void arena_free(Arena* arena);
internal void* arena_alloc(Arena* arena, u64 size);

u64 default_temp_arena_size = 256000000;
Arena temp_arena = {0};
bool is_temp_arena_initted = false;

void* default_allocator(void* data, u64 size) {
	return malloc(size);
}

Context context = {
	.allocator.func_allocator = default_allocator,
	.allocator.data = null,
	.allocator.func_free = free,

	.temp_allocator.func_allocator = _temp_allocator_func,
	.temp_allocator.data = &temp_arena,
	.temp_allocator.func_free = _temp_allocator_free_func,
};

function internal inline void*
_temp_allocator_func(void* data, u64 size) {
	if(!is_temp_arena_initted) {
		Arena* _arena = arena_new(default_temp_arena_size);
		temp_arena = *_arena;

	}
	Arena* arena = (Arena*)data;
	return (void*)arena_alloc(arena, size);
}

function internal inline void
_temp_allocator_free_func(void* data) {
	Arena* arena = (Arena*)context.temp_allocator.data;
	arena_free(arena);
}
// TODO: quizas no deberia de haber un free()
#define fini(memory) context.allocator.func_free(context.allocator.data);
#define alloc(size) context.allocator.func_allocator(context.allocator.data, size)

#define char_to_s32(c) ((s32)((c) - '0'))
#define string(str) ((String){.data = str, .count = strlen(str)})
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

//
//	Arena
//

function internal inline Flat_Arena
flat_arena_new(u64 size) {
	Flat_Arena arena = {0};
	arena.data = alloc(size);
	if(!arena.data) {
		return arena;
	}
	arena.capacity = size;
	arena.count = 0;
	return arena;
}


// function internal inline bool
// use_flat_arena_as_allocator(Flat_Arena* arena) {
// 	if (!arena->data) return false;
// 	context.allocator.data = *arena;
// 	context.func_allocator = _flat_arena_alloc_func;

// 	return true;
// }

// function internal inline void*
// _flat_arena_alloc_func(u64 size) {
// 	Flat_Arena* arena = (Flat_Arena*)context.data;
// }

function internal inline Arena*
arena_new(u64 size) {
	Arena* arena = (Arena*)alloc(sizeof(Arena));
	if (!arena) return null;

	arena->data = (u8*)alloc(size);
	if(!arena->data)
	{
		free(arena);
		return null;
	}
	arena->capacity = size;
	arena->count = 0;
	arena->next = null;
	return arena;
}

function internal inline void
arena_reset(Arena* arena)
{
	while(arena)
	{
		arena->count = 0;
		arena = arena->next;
	}
}

function internal inline void
arena_free(Arena* arena)
{
	while(arena)
	{
		Arena* next = arena->next;
		if (arena->data) free(arena->data);
		free(arena);
		arena = next;
	}
}

// The arena have to be enough big to be able to hold at least the biggest object you gonna put
function internal inline void*
arena_alloc(Arena* arena, u64 size)
{
	if (size == 0) return null;
	assert(size <= arena->capacity);
	while(arena)
	{
		if (arena->count + size <= arena->capacity)
		{
			void* ptr = arena->data + arena->count;
			arena->count += size;
			return ptr;
		}

		if (!arena->next)
		{
			arena->next = arena_new(size);
			if (!arena->next) return null;
		}

		arena = arena->next;
	}
	return null;
}


//
// STRING
//

function internal inline String_Builder
sb_init(u64 initial_capacity) {
	if (initial_capacity == 0) initial_capacity = 1;
	String_Builder sb;
	sb.data = malloc(initial_capacity);
	sb.count = 0;
	sb.capacity = initial_capacity;
	return sb;
}

function internal inline String
sb_to_string(String_Builder sb) {
	return (String){sb.data, sb.count};
}

function internal inline void
string_to_file(String path, String s) {
	FILE* f = fopen(path.data, "wb");
	if (!f) { perror("Error abriendo archivo"); return; }
	fwrite(s.data, 1, s.count, f);
	fclose(f);
}

function internal inline String_Builder
string_to_sb(String s) {
	String_Builder sb = {0};
	sb.data = s.data;
	sb.count = s.count;
	sb.capacity = s.count;
	return sb;
}

function internal inline void
sb_append(String_Builder* sb, String s) {
	if (sb->count + s.count > sb->capacity) {
		u64 new_capacity = sb->capacity * 2;
		while (new_capacity < sb->count + s.count) new_capacity *= 2;
		u8* new_data = malloc(new_capacity);
		memcpy(new_data, sb->data, sb->count);
		free(sb->data);
		sb->data = new_data;
		sb->capacity = new_capacity;
	}
	memcpy(sb->data + sb->count, s.data, s.count);
	sb->count += s.count;
}

function internal inline void
sb_append_at(String_Builder* sb, String s, s64 at) {
	u64 new_count = sb->count + s.count;
	if (new_count > sb->capacity) {
		u64 new_capacity = sb->capacity * 2;
		while (new_capacity < new_count) new_capacity *= 2;
		u8* new_data = alloc(new_capacity);
		memcpy(new_data, sb->data, sb->count);
		free(sb->data);
		sb->data     = new_data;
		sb->capacity = new_capacity;
	}
	memmove(sb->data + at + s.count, sb->data + at, sb->count - at);
	memcpy(sb->data + at, s.data, s.count);
	sb->count = new_count;
}

function internal inline void
sb_remove_single_char_at(String_Builder* sb, s64 at) {
	if (at >= sb->count) return;

	memmove(sb->data + at, sb->data + at + 1, sb->count - at - 1);
	sb->count--;
}

function internal inline void
sb_remove_from_to(String_Builder* sb, s64 from, s64 to) {
	if (from >= sb->count || from > to) return;
	if (to >= sb->count) to = sb->count - 1;

	s64 num_bytes_after_to = sb->count - (to + 1);
	if (num_bytes_after_to > 0) memmove(sb->data + from, sb->data + to + 1, num_bytes_after_to);

	sb->count -= (to - from + 1);
}

function internal inline void
sb_append_char(String_Builder* sb, char c) {
	if (sb->capacity - sb->count + 1 > sb->capacity) {
		u8* new_data = malloc(sb->capacity*2);
		memcpy(new_data, sb->data, sb->count);
		free(sb->data);
		sb->data = new_data;
	}

	sb->data[sb->count] = c;
	sb->count += 1;
}

function internal inline String_Builder_Arena
sb_init_arena(Arena* arena, u64 initial_capacity)
{
	if (initial_capacity == 0) initial_capacity = 1;
	String_Builder_Arena sb;
	sb.arena = arena;
	sb.str.data = arena_alloc(arena, initial_capacity);
	sb.str.count = 0;
	sb.capacity = initial_capacity;
	return sb;
}

function internal inline void
sb_reset(String_Builder_Arena* sb)
{
	if(sb) sb->str.count = 0;
}

function internal inline void
sb_arena_append(String_Builder_Arena* sb, char* data, u64 count)
{
	if (sb->str.count + count >= sb->capacity) {
		u64 new_capacity = sb->capacity * 2;
		while (sb->str.count + count >= new_capacity) {
			new_capacity *= 2;
		}

		u8* new_data = arena_alloc(sb->arena, new_capacity);
		memcpy(new_data, sb->str.data, sb->str.count);
		sb->str.data = new_data;
		sb->capacity = new_capacity;
	}

	memcpy(sb->str.data + sb->str.count, data, count);
	sb->str.count += count;
}

function internal inline bool
sb_arena_append_char(String_Builder_Arena* sb, char c)
{
		if (!sb) return false;

		if (sb->str.count >= sb->capacity)
		{
				u64 new_capacity = sb->capacity * 2;
				if (new_capacity < 16) new_capacity = 16;

				u8* new_data = arena_alloc(sb->arena, new_capacity);
				if (!new_data) return false;

				if (sb->str.count > 0 && sb->str.data) memcpy(new_data, sb->str.data, sb->str.count);

				sb->str.data = new_data;
				sb->capacity = new_capacity;
		}

		sb->str.data[sb->str.count++] = (u8)c;
		return true;
}

function internal inline void
sb_arena_pop(String_Builder_Arena* sb)
{
		if(sb->str.count > 0) sb->str.count--;
}

function internal inline String
sb_read_line(String_Builder* sb, s64* cursor) { // cursor es el index en sb no el contador de lineas.
	bool exists_new_line = false;
	s64 starts = *cursor;
	while(true) {
		if(sb->count <= *cursor) {
			*cursor = sb->count;
			break;
		}
		if(sb->data[(*cursor)++] == '\n') break;
	}
	String s = {.data = sb->data + starts, .count = *cursor - starts};
	return s;
}

function internal inline bool
sb_read_line_from_line(String_Builder_Arena* sb, FILE* f, u64* line_count)
{
	char buffer[2048]; // TODO: cambiar por parametro.
	if (!sb || !f) return false;
	sb_reset(sb);

	s32 c;
	bool line_read = false;
	while ((c = fgetc(f)) != EOF)
	{
		line_read = true;

		if (c == '\n')
		{
			if (line_count) (*line_count)++;
			break;
		}

		if (c == '\r') continue;

		if (!sb_arena_append_char(sb, (char)c)) return false;
	}

	// Devolver true si leímos algo (incluso si fue solo \n)
	return line_read || (c != EOF);
}

// #define use_temp_allocator()

function internal inline String
temp_c_string(String s) {
	char* new_c_string;

}

function internal inline String
string_from_cstring(char* cstr) {
	String s;
	s.count = strlen(cstr);
	s.data = alloc(s.count + 1);
	memcpy(s.data, cstr, s.count);
	s.data[s.count] = '\0'; // aseguramos por compatibilidad que siempre acabe en \0
	return s;
}

function internal inline String
to_string(char* cstr) {
	String s;
	s.count = strlen(cstr);
	s.data = cstr;
	return s;
}

function internal inline String
string_reserve(u64 size){
	assert(size > 0);
	String s = {0};
	s.count = size;
	s.data = alloc(size+1);
	return s;
}

function internal inline String
string_slice(String s, u64 start, u64 new_len) {
	assert(start < s.count || start + new_len < s.count);
	String new_slice;
	new_slice.data = s.data + start;
	new_slice.count = new_len;
	return new_slice;
}

function internal inline String
string_arena(Arena* arena, char* str) {
	String result = {0};
	u64 count = strlen(str);
	result.data = arena_alloc(arena, count);
	if (!result.data) return result;
	result.count = count;
	if (str)	memcpy(result.data, str, count);
	return result;
}

function internal inline String
string_arena_init(Arena* arena, u64 size) {
	String result = {0};
	result.data = arena_alloc(arena, size);
	if (!result.data) return result;
	result.count = size;

	return result;
}

function internal inline String
string_to_string(Arena* arena, String* str) {
	String result = {0};
	result.data = arena_alloc(arena, str->count);
	if (!result.data) return result;
	result.count = str->count;
	if (str) memcpy(result.data, str->data, str->count);
	return result;
}

function internal inline String
string_to_cstr(String str, Arena* arena)
{
	if (str.count > 0 && str.data[str.count - 1] == '\0') return str;

	String result = {
		.data = arena_alloc(arena, str.count+1),
		.count = str.count
	};
	if(!result.data) return(String){0};

	if(str.count > 0 && str.data) memcpy(result.data, str.data, str.count);
	result.data[str.count] = '\0';

	return result;
}

function internal inline String
string_copy(String src, Arena* arena)
{
	String result = {0};
	if (!arena) return result;

	result.data = arena_alloc(arena, src.count);
	if (!result.data) return result;

	memcpy(result.data, src.data, src.count);
	result.count = src.count;
	return result;
}

function internal inline bool
string_copy_to(String src, String* dest, Arena* arena)
{
	if (!dest || !arena) return false;

	if (dest->data && dest->count >= src.count)
	{
		memcpy(dest->data, src.data, src.count);
		dest->count = src.count;
		return true;
	}

	dest->data = arena_alloc(arena, src.count);
	if (!dest->data) return false;

	memcpy(dest->data, src.data, src.count);
	dest->count = src.count;
	return true;
}

function internal inline bool
is_cstr(String* str)
{
	if (!str || !str->data || str->count == 0) return false;
	return (str->data[str->count - 1] == '\0');
}

function internal inline void
to_cstr(String* str)
{
	if(str->data[str->count] != '\0') str->data[str->count] = '\0';
}

function internal inline bool
string_scmp(String s1, String s2, u64 length) { // Esto usa la longitud de s1
	if(MIN(s1.count, s2.count) < length) length = MIN(s1.count, s2.count); // La longitud maxima que acepta la funcion es la longitud del string mas pequeño.
	if(memcmp(s1.data, s2.data, length) == 0) return true;
	else return false;
}

function internal inline bool
string_cmp(String s1, String s2)
{
	if (s1.count != s2.count) return false;
	if(memcmp(s1.data, s2.data, s1.count) == 0) return true;
	else return false;
}

function internal inline bool
cstring_cmp(String s1, char* s2)
{
	if (strlen(s2) < s1.count) return false;
	if(memcmp(s1.data, s2, strlen(s2)) == 0) return true;
	else return false;
}

function internal inline void
trimlp(String_Builder* s)
{
	if (!s || !s->data || s->count == 0) return;
	u64 count = 0;

	while (count < s->count && isspace(s->data[count])) count++;

	if (count == 0) return;

	memmove(s->data, s->data + count, s->count - count);
	s->count -= count;
}

function internal inline void
trimrp(String_Builder* s)
{
	if (!s || !s->data || s->count == 0) return;

	if (s->count > 0 && s->data[s->count - 1] == '\0') s->count--;

	u64 last_char = s->count;
	while (last_char > 0 && isspace(s->data[last_char - 1])) last_char--;

	s->count = last_char;
}

function internal inline void
trimp(String_Builder* s)
{
	trimlp(s);
	trimrp(s);
}

function internal inline String
trim_slice(String s) {
	if (!s.data || s.count == 0) return s;
	String new_s = s;
	// left
	while(true) {
		if(isspace(new_s.data[0])) {
			new_s.data++;
			new_s.count--;
		}
		else break;
	}

	// right

	u64 last_char = s.count;
	if (s.count > 0 && s.data[s.count - 1] == '\0') s.count--;
	while(last_char > 0 && isspace(s.data[last_char - 1])) last_char--;
	new_s.count = last_char;

	return new_s;
}

function internal inline bool
starts_with(String s, String starts) {
	return string_scmp(starts, s, starts.count);
}

function internal inline void
prints(String s)
{
	printf("%.*s", (int)s.count, s.data);
}

function internal inline void
printsln(String s)
{
	printf("%.*s\n", (int)s.count, s.data);
}

function internal inline String
read_entire_file(String path) {
	FILE* f = fopen(path.data, "r");
	if(!f) {
		perror("fopen failed\n");
		return (String){0};
	}

	fseek(f, 0, SEEK_END);
	u64 size = ftell(f);
	fseek(f, 0, SEEK_SET);

	String file_buffer = string_reserve(size);
	fread(file_buffer.data, 1, size, f);
	fclose(f);
	return file_buffer;
}

function internal inline s64
string_contains(String source, String target) {
	if (target.count > source.count) return -1;

	for (u64 i = 0; i <= source.count - target.count; i++) {
		if (memcmp(source.data + i, target.data, target.count) == 0) return i;
	}
	return -1;
}

#endif
