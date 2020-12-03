#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>

struct foo {
	char buffer[10000];
	jmp_buf jb;
};

// Function with buffer overflow vulnerability
void fill_buf(char* buf, FILE *fd) {
	int i = 0;
	// Reads to the end of the file rather without any bounds check on the buffer
	while(!feof(fd)) {
		// Read the hexadecimal value from the file
		uint64_t next_val;
		fscanf(fd, "%lx\n", &next_val);
		// Copy the hex value byte-by-byte into the buffer
		for (int j = 0; j < 8; j++) {
			buf[i++] = ((uint8_t*)&next_val)[j];
		}
	}
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "Please provide a file!\n");
		exit(EXIT_FAILURE);
	}

	FILE *fd = fopen(argv[1], "r");
	if (fd == NULL) {
		fprintf(stderr, "Failed to open the file: %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	struct foo *f = malloc(sizeof(*f));
	fill_buf(f->buffer, fd);
	longjmp(f->jb, 1);
}
