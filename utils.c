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
