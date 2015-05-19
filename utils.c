#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int hex2int(char c) {
	if('0' <= c && c <= '9') {
		return c - '0';
	}
	if('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	}
	if('A' <= c && c <= 'F') {
		return c - 'A' + 10;
	}

	return -1;
}

char int2hex(int i) {
	if(0 <= i && i <= 9) {
		return '0' + i;
	}
	if(0xa <= i && i <= 0xf) {
		return 'a' - 0xa + i;
	}
	return -1;
}

unsigned char *hex2bytes(char *hex, size_t *size, bool allow_odd) {
	size_t len = strlen(hex);
	bool odd = false;
	if(len % 2 != 0) {
		if(allow_odd) {
			odd = true;
		} else {
			return NULL;
		}
	}

	*size = (len + 1) / 2;
	unsigned char *buf = malloc(*size);

	for(ssize_t i = odd? -1: 0; i != len; i += 2) {
		int i1 = i == -1? 0: hex2int(hex[i]);
		int i2 = hex2int(hex[i + 1]);
		if(i1 == -1 || i2 == -1) {
			free(buf);
			return NULL;
		}
		buf[(i + 1) / 2] = i1 * 0x10 + i2;
	}

	return buf;
}
