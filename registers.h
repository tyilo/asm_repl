#if defined(__i386__)

#define REGISTERS 9

#define FOREACH_REGISTER(X) \
	X(eax); \
	X(ebx); \
	X(ecx); \
	X(edx); \
	X(edi); \
	X(esi); \
	X(ebp); \
	X(esp); \
	X(eip);

#elif defined(__x86_64__)

#define REGISTERS 17

#define FOREACH_REGISTER(X) \
	X(rax); \
	X(rbx); \
	X(rcx); \
	X(rdx); \
	X(rdi); \
	X(rsi); \
	X(rbp); \
	X(rsp); \
	X(r8);  \
	X(r9);  \
	X(r10); \
	X(r11); \
	X(r12); \
	X(r13); \
	X(r14); \
	X(r15); \
	X(rip);

#endif
