sdk = $(shell xcodebuild -sdk -version | grep '^Path: .*MacOSX10.10' | awk '{print $$2}')

all:
	$(CC) $(CFLAGS) $(wildcard *.c mach_exc/*c) -ledit -o asm_repl

clean:
	rm -f asm_repl

run: all
	sudo ./asm_repl

mach_exc:
	mkdir -p mach_exc; \
	cd mach_exc; \
	mig "$(sdk)/usr/include/mach/mach_exc.defs"

scan:
	scan-build make CFLAGS='-isysroot $(sdk)'
