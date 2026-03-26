#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "arrays.c"

typedef struct String String;
typedef struct String_Builder_Arena String_Builder_Arena;
typedef struct String_Builder String_Builder;
typedef struct Arena Arena;

#include "base.c"

Array_String function_defs;
Array_String enum_defs;
Array_String struct_defs;
Array_String union_defs;

typedef enum Def_Type {
  STRUCT,
  UNION,
  ENUM
} Def_Type;

void
add_declaration(Array_String* defs, String name, Def_Type type) {
  if (cstring_cmp(name, "{")) return;
  String_Builder sb = sb_init(64);
  sb_append(&sb, string("typedef "));

  switch(type) {
  case STRUCT: sb_append(&sb, string("struct ")); break;
  case ENUM:   sb_append(&sb, string("enum ")); break;
  case UNION:  sb_append(&sb, string("union ")); break;
  }

  sb_append(&sb, name);
  sb_append_char(&sb, ' ');
  sb_append(&sb, name);
  sb_append_char(&sb, ';');
  array_add(*defs, sb_to_string(sb));
}

void
write_string(FILE *f, String s) {
	if(!f || !s.data) return;
	fprintf(f, "%.*s", (int)s.count, s.data);
}

void
parse_file(char* file_name) {
  FILE* f = fopen(file_name, "r");
  if(!f) {
    perror("fopen");
    return;
  }

  fseek(f, 0, SEEK_END);
  u64 size = ftell(f);
  fseek(f, 0, SEEK_SET);

  String file_buffer = string_reserve(size+1);
  fread(file_buffer.data, 1, size, f);
  file_buffer.data[size] = '\0';
  fclose(f);

  stb_lexer lexer;
  char buffer_token[1024];

  stb_c_lexer_init(&lexer, file_buffer.data, file_buffer.data + file_buffer.count, buffer_token, sizeof(buffer_token));
  int tok;
  bool in_function_def = false;
  bool in_struct_def = false;
  bool in_union_def = false;
  bool in_enum_def = false;

  Array_char def_buffer = {0};

  while((tok = stb_c_lexer_get_token(&lexer)) != 0) {
    int word_size = (int)(lexer.where_lastchar - lexer.where_firstchar+1);


    if (strncmp(lexer.where_firstchar, "{", 1) == 0 && in_function_def) {
      array_add(def_buffer, ';');
      in_function_def = false;
      Array_char tmp_arr = {0};
      for (int i = 0; i < def_buffer.count -1; i++) array_add(tmp_arr, def_buffer.data[i]);
      String s = {tmp_arr.data, tmp_arr.count};
      array_add(function_defs, s);
      def_buffer.count = 0;
    }

    if (in_function_def) {
      bool no_space = false;
      for (int i = 0; i < word_size; i++) {
        char c = lexer.where_firstchar[i];

        if (c == '\0') break;
        if (c == '(' || c == ')') {
          if (def_buffer.data[def_buffer.count - 1] == ' ') {
            array_pop(def_buffer);
            no_space = true;
          }
        }
        if (c == ',' && def_buffer.data[def_buffer.count - 1] == ' ') array_pop(def_buffer);
        if (c == '*' && def_buffer.data[def_buffer.count - 1] == ' ') array_pop(def_buffer);
        array_add(def_buffer, c);
      }

      if (!no_space) array_add(def_buffer, ' ');
    }

    if (strncmp(lexer.where_firstchar, "function", 8) == 0) {
      in_function_def = true;
    }

    if (in_union_def) {
      String s = {lexer.where_firstchar, word_size};
      add_declaration(&union_defs, s, UNION);
      in_union_def = false;
    }
    else if (in_struct_def) {
      String s = {lexer.where_firstchar, word_size};
      add_declaration(&struct_defs, s, STRUCT);
      in_struct_def = false;
    }
    else if (in_enum_def){
      String s = {lexer.where_firstchar, word_size};
      add_declaration(&enum_defs, s, ENUM);
      in_enum_def = false;
    }

    if (strncmp(lexer.where_firstchar, "union", 5) == 0)  in_union_def = true;
    if (strncmp(lexer.where_firstchar, "enum", 4) == 0)   in_enum_def = true;
    if (strncmp(lexer.where_firstchar, "struct", 6) == 0) {
    	char* c = lexer.where_firstchar + 6;
    	int i;
    	while(c[i] != '\n') i++;
    	while (isspace(c[i])) {
    		i++;
    		if(c[i] == '{') in_struct_def = true;
    	}
    	while(i >= 0) {
    		if (c[i] == '{') in_struct_def = true;
    		i--;
    	}
    }
  }
  free(file_buffer.data);
}


int main() {

  parse_file("./src/base.c");
  parse_file("./src/main.c");
  FILE* new_f = fopen("./src/typedef_gen.h", "wb");

  write_string(new_f, string("#ifndef TYPEDEF_GEN_H\n#define TYPEDEF_GEN_H\n"));
  write_string(new_f, string("\n#define function\n"));
  write_string(new_f, string("\n#include \"types.h\" \n"));

  write_string(new_f, string("\n// \n"));
  write_string(new_f, string("// STRUCT DEFS"));
  write_string(new_f, string("\n// \n"));

  for (int i = 0; i < struct_defs.count; i++) {
    write_string(new_f, struct_defs.data[i]);
    write_string(new_f, string("\n"));
  }
  write_string(new_f, string("\n// \n"));
  write_string(new_f, string("// ENUM DEFS"));
  write_string(new_f, string("\n// \n"));

  for (int i = 0; i < enum_defs.count; i++) {
    write_string(new_f, enum_defs.data[i]);
    write_string(new_f, string("\n"));
  }

  write_string(new_f, string("\n// \n"));
  write_string(new_f, string("// UNION DEFS"));
  write_string(new_f, string("\n// \n"));

  for (int i = 0; i < union_defs.count; i++) {
    write_string(new_f, union_defs.data[i]);
    write_string(new_f, string("\n"));
  }
  write_string(new_f, string("\n// \n"));
  write_string(new_f, string("// FUNCTION DEFS"));
  write_string(new_f, string("\n// \n"));

  for (int i = 0; i < function_defs.count; i++) {
    write_string(new_f, function_defs.data[i]);
    write_string(new_f, string(";"));
    write_string(new_f, string("\n"));
  }

  write_string(new_f, string("\n#endif\n"));
  fclose(new_f);


  return 0;
}