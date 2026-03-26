#ifndef ARRAYS_C_START
#define ARRAYS_C_START

#include <stdio.h>
#define STB_DS_IMPLEMENTATION
#define STB_C_LEXER_IMPLEMENTATION
#include "stb_c_lexer.h"
#include "base.c"
#include <sys/stat.h>

typedef struct Array_String Array_String;
struct Array_String {
	u64 count;
	u64 capacity;
	String *data;
};

// @TODO cambiar esto por el allocator del context.
#define array_may_grow(array) \
if ((array).count >= (array).capacity) {                                  \
  (array).capacity = (array).capacity ? (array).capacity * 2 : 8;         \
  (array).data = realloc((array).data, (array).capacity * sizeof(*(array).data)); \
}

#define array_add(array, item)          \
do {                                    \
array_may_grow(array);                  \
(array).data[(array).count++] = item; \
} while(0)                              \

#define array_pop(array) do { if(array.count > 0) array.count--; } while(0)

#endif

#ifdef MAIN

bool
exists(Array_String array, String s) {
	for (int i = 0; i < array.count; i++) {
		if (string_scmp(array.data[i], s, s.count)) return true;
	}
	return false;
}

void
write_string(FILE *f, String s) {
	if(!f || !s.data) return;
	fprintf(f, "%.*s", (int)s.count, s.data);
}

String
get_type_slice(String s) {
	return string_slice(s, 6, s.count - 6);
}

void
add_type(Array_String* array, String s) {
	String type = get_type_slice(s);
	if(starts_with(type, string("Array_"))) {
		add_type(array, type);
	}
	if (!exists(*array, s)) array_add(*array, s);
}

String
build_typedef(String array_declaration) {
	char buffer[1024];
	sprintf(buffer,
	"typedef struct %s %s;\n",
	array_declaration.data, array_declaration.data);
	return string_from_cstring(buffer);
}
String
build_struct(String array_declaration) {
	char buffer[1024];
	String type_of_array = get_type_slice(array_declaration);

	sprintf(buffer,
	"struct %s {\n"
	"	u64 count;\n"
	"	u64 capacity;\n"
	"	%s *data;\n"
	"};\n",
	array_declaration.data, type_of_array.data);

	return string_from_cstring(buffer);
}

char* generated_text = "//:Generated\n";

int
main(int argc, char** argv) {
	if (argc < 2) return 0;
	Array_String declarations = {0};
	Array_String built_structs = {0};
	for(int i = 1; i < argc; i++) {
		String path = string_from_cstring(argv[i]);
		String file_string = read_entire_file(path);

		stb_lexer lexer;
		char buffer_token[1024];

	  stb_c_lexer_init(&lexer, file_string.data, file_string.data + file_string.count, buffer_token, sizeof(buffer_token));
	  int tok_exist;

	  while((tok_exist = stb_c_lexer_get_token(&lexer)) != 0) {
			if(lexer.token != CLEX_id) continue;
			String lexer_string = to_string(lexer.string);

			if (string_scmp(lexer_string, string("Array_String"), 12)) continue;

	  	if (starts_with(lexer_string, string("Array_"))) {
		  	bool exists = false;
		  	for (u64 i = 0; i < declarations.count; i++) {
		  		if (string_scmp(declarations.data[i], lexer_string, lexer_string.count)) {
			  		exists = true;
			  		break;
		  		}
		  	}
		  	if (!exists) array_add(declarations, string_from_cstring(lexer.string));
	  	}

	  }

		for(int i = 0; i < declarations.count; i++)	add_type(&declarations, declarations.data[i]);
	}

	String this_file_string = read_entire_file(string("arrays.c"));
	s64 index = string_contains(this_file_string, string(generated_text));

	String_Builder this_file_sb = string_to_sb(this_file_string);
  sb_remove_from_to(&this_file_sb, index + strlen(generated_text), this_file_sb.count);

	sb_append_at(&this_file_sb, string("\n"), this_file_sb.count-1);
	for(int i = 0; i < declarations.count; i++) {
		String built_struct = build_struct(declarations.data[i]);
		array_add(built_structs, built_struct);
	}

	for(int i = 0; i < declarations.count; i++) {
		String built_typedef = build_typedef(declarations.data[i]);
		sb_append_at(&this_file_sb, built_typedef, this_file_sb.count-1);
		free(built_typedef.data);
	}
	for (int i = 0; i < built_structs.count; i++) {
		sb_append_at(&this_file_sb, built_structs.data[i], this_file_sb.count-1);
	}
	sb_append_at(&this_file_sb, string("#endif"), this_file_sb.count-1);

	string_to_file(string("arrays.c"), sb_to_string(this_file_sb));
	return 0;
}
#endif
#ifndef ARRAYS_C_END
#define ARRAYS_C_END


//:Generated
typedef struct Array_char Array_char;
typedef struct Array_u64 Array_u64;
struct Array_char {
	u64 count;
	u64 capacity;
	char *data;
};
struct Array_u64 {
	u64 count;
	u64 capacity;
	u64 *data;
};
#endif
