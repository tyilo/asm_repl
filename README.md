# asm_repl
A [REPL](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop) for assembly.

Type some assembly instructions and immediatly see which registers were changed.

Currently only supports x86_64 on OS X.

Screenshot
==
![Screenshot](http://i.imgur.com/OQz12RO.png)

Also see [https://asciinema.org/a/19605](https://asciinema.org/a/19605).


Running
==

* Install [radare2](https://github.com/radare/radare2).
* `make`
* `sudo ./asm_repl`



Todo
==

* Use a library (libr?) for assembling instead of reading the output of running `rasm2`.
* Support more architectures (32-bit x86, arm).
* Support more platforms (linux).
* Use readline for prompt.
* Arithmetic for commands (`.read rip-0x10`).