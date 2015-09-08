# asm_repl
A [REPL](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop) for assembly.

Type some assembly instructions and immediatly see which registers were changed.

Currently only supports i386 and x86_64 on OS X.

Screenshot
==
[![Screenshot x86_64](http://i.imgur.com/Eb8Bz15.png)](http://i.imgur.com/Eb8Bz15.png)

Also see [https://asciinema.org/a/19605](https://asciinema.org/a/19605).

Running
==

* Install [radare2](https://github.com/radare/radare2).
* `make`
* `./asm_repl` (`make run32` or `make run64` to choose a specific architecture)

You need to codesign `asm_repl` binary or run it as root as we have to access the process we're running the assembly code in. You can codesign the binary so it can use `task_for_pid` without root by creating a certificate named `task_for_pid` using the guide [here](https://gcc.gnu.org/onlinedocs/gnat_ugn/Codesigning-the-Debugger.html) and then running `make`.

Commands
==

```
Valid input:
  Help:
    ?      - show this help
    ?[cmd] - show help for a command

  Commands:
    .set      - change value of register
    .read     - read from memory
    .write    - write hex to memory
    .writestr - write string to memory
    .alloc    - allocate memory
    .regs     - show the contents of the registers
    .show     - toggle shown register types

Any other input will be interpreted as x86_64 assembly
```

`.set`
--

```
Usage: .set register value
Changes the value of a register

  register - register name (GPR, FPR or status)
  value    - hex if GPR or FPR, 0 or 1 if status
```

`.read`
--

```
Usage: .read address [len]
Displays a hexdump of memory starting at address

  address - an integer or a register name
  len     - the amount of bytes to read
```

`.write`
--

```
Usage: .write address hexpairs
Writes hexpairs to a destination address

  address  - an integer or a register name
  hexpairs - pairs of hexadecimal numbers
```

`.writestr`
--

```
Usage: .writestr address string
Writes an ascii string to a destination address

  address - an integer or a register name
  string  - an ascii string
```

`.alloc`
--

```
Usage: .alloc len
Allocates some memory and returns the address

  len - the amount of bytes to allocate
```

`.regs`
--

```
Usage: .regs
Displays the values of the registers currently toggled on
```

`.show`
--

```
Usage: .show [gpr|status|fpr_hex|fpr_double]
Toggles which types of registers are shown

  gpr        - General purpose registers (rax, rsp, rip, ...)
  status     - Status registers (CF, ZF, ...)
  fpr_hex    - Floating point registers shown in hex (xmm0, xmm1, ...)
  fpr_double - Floating point registers shown as doubles
```

Todo
==

* Use a library (libr?) for assembling instead of reading the output of running `rasm2`.
* Support more architectures (arm).
* Support more platforms (linux).
* Arithmetic for commands (`.read rip-0x10`).
* Variables to specific memory addresses (`.alloc 4` => `.write $alloc 12345678`).
