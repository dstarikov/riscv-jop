#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

void *fill_buf(void *location, FILE *fd) {
	uint64_t *buf = mmap((void*)location, 0x10000000, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);

	if((uint64_t)buf == -1l) {
		perror("error mapping buf");
		exit(1);
	}

	if(buf != location) {
		printf("failed to allocate %lx\n", buf);
		exit(1);
	}

	int i = 0;

	while(!feof(fd)) {
		uint64_t next_val;
		fscanf(fd, "%lx\n", &next_val);
		buf[i++] = next_val;
	}

	return location;
}

void start_jop(void *stackbuf);

int main() {
	setbuf(stdout, NULL);
	FILE *dispatch_buf_fd = fopen("dispatch.txt", "r");
	void *dispatch_buf = fill_buf((void*)0x20000000, dispatch_buf_fd);
	start_jop(dispatch_buf);
}
