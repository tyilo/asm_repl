sdk = $(shell xcodebuild -sdk -version | grep '^Path: .*MacOSX10.10' | awk '{print $$2}')
CERTNAME=task_for_pid

all:
	@$(CC) -arch i386 -arch x86_64 $(wildcard *.c mach_exc/*.c) -ledit -framework Security -o asm_repl -sectcreate __TEXT __info_plist Info.plist
	@if ! codesign -s $(CERTNAME) asm_repl; then \
		echo "WARNING:"; \
		echo "You don't have a certificate named $(CERTNAME)."; \
		echo "If you want to run asm_repl without root,"; \
		echo "create a certificate named $(CERTNAME) using the guide here: "; \
		echo "https://gcc.gnu.org/onlinedocs/gnat_ugn/Codesigning-the-Debugger.html"; \
	fi
	@rm -rf _CodeSignature


clean:
	rm -f asm_repl

run64: all
	@arch -64 ./asm_repl

run32: all
	@arch -32 ./asm_repl

mach_exc:
	mkdir -p mach_exc; \
	cd mach_exc; \
	mig "$(sdk)/usr/include/mach/mach_exc.defs"

scan:
	scan-build make CFLAGS='-isysroot $(sdk)'
