#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "utils.h"

// TODO: Actually use a library to assemble instead of calling out to rasm2
bool assemble_string(char *str, uint8_t bits, uint64_t address, unsigned char **output, size_t *output_size) {
	*output_size = 0;
	*output = malloc(16);

	char *cmd;
	asprintf(&cmd, "rasm2 -a x86.nasm -b %u -o 0x%llx \"%s\"", bits, address, str);

	FILE *f = popen(cmd, "r");
	free(cmd);

	if(!f) {
		return false;
	}

	size_t bytes_read = 0;

	char buf[256];
	while(fgets(buf, sizeof(buf), f)) {
		size_t len = strlen(buf);
		*output_size += (len - 1) / 2;
		*output = realloc(*output, *output_size);
		for(int i = 0; i < len; i += 2) {
			(*output)[bytes_read++] = hex2int(buf[i]) * 0x10 + hex2int(buf[i + 1]);
		}
	}

	pclose(f);

	if(bytes_read == 0) {
		return false;
	}

	return true;
}
