all:
	cc $(wildcard *.c mach_exc/*c) -o asm_repl

clean:
	rm -f asm_repl

run: all
	sudo ./asm_repl

mach_exc:
	mkdir -p mach_exc; \
	cd mach_exc; \
	sdk=$$(xcodebuild -sdk -version | grep '^Path: .*MacOSX10.10' | awk '{print $$2}'); \
	mig "$$sdk/usr/include/mach/mach_exc.defs"
