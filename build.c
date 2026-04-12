#include <stdlib.h>

char* source = "src/rsa.h";

int main(void) {
	if(system("./autogen src/rsa.h")) return 1;
	if(system("tcc -run -DMAIN src/arrays.c src/rsa.h")) return 1;
	if(system("gcc -x c -g3 -O0 -DRSA_IMPLEMENTATION -DRSA_TESTS src/rsa.h -o rsa -lgmp")) return 1;
	return 0;
}