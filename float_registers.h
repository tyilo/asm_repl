#if defined(__i386__)

#define FLOAT_REGISTERS 8

#define FOREACH_FLOAT_REGISTER(X) \
	X(xmm0); \
	X(xmm1); \
	X(xmm2); \
	X(xmm3); \
	X(xmm4); \
	X(xmm5); \
	X(xmm6); \
	X(xmm7);

#elif defined(__x86_64__)

#define FLOAT_REGISTERS 16

#define FOREACH_FLOAT_REGISTER(X) \
	X(xmm0);  \
	X(xmm1);  \
	X(xmm2);  \
	X(xmm3);  \
	X(xmm4);  \
	X(xmm5);  \
	X(xmm6);  \
	X(xmm7);  \
	X(xmm8);  \
	X(xmm9);  \
	X(xmm10); \
	X(xmm11); \
	X(xmm12); \
	X(xmm13); \
	X(xmm14); \
	X(xmm15);

#endif
