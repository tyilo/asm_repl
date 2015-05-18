#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/param.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <setjmp.h>
#include <editline/readline.h>

#include "assemble.h"
#include "colors.h"
#include "utils.h"

extern boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

typedef union {
	uint64_t value;
	struct __attribute__((packed)) {
		uint8_t CF    :1;
		uint8_t _res1 :1;
		uint8_t PF    :1;
		uint8_t _res2 :1;
		uint8_t AF    :1;
		uint8_t _res3 :1;
		uint8_t ZF    :1;
		uint8_t SF    :1;
		uint8_t TF    :1;
		uint8_t IF    :1;
		uint8_t DF    :1;
		uint8_t OF    :1;
		uint8_t IOPL  :2;
		uint8_t NT    :1;
		uint8_t _res4 :1;

		uint8_t RF    :1;
		uint8_t VM    :1;
		uint8_t AC    :1;
		uint8_t VIF   :1;
		uint8_t VIP   :1;
		uint8_t ID    :1;

		uint64_t _res5 :42;
	} flags;
} rflags_t;

pthread_mutex_t mutex;

#define MEMORY_SIZE 0x10000
#define INT3 0xCC

#define STD_FAIL(s, x) do { \
	int ret = (x); \
	if(ret != 0) { \
		perror(s "()"); \
		exit(ret); \
	} \
} while(false)

#define KERN_FAIL(s, x) do { \
	kern_return_t ret = (x); \
	if(ret != KERN_SUCCESS) { \
		printf(s "() failed: %s\n", mach_error_string(ret)); \
		exit(ret); \
	} \
} while(false)

#define KERN_TRY(s, x, f) if(true) { \
	kern_return_t ret = (x); \
	if(ret != KERN_SUCCESS) { \
		printf(s "() failed: %s\n", mach_error_string(ret)); \
		f \
	} \
} else do {} while(0)

void get_thread_state(thread_act_t thread, x86_thread_state64_t *state, mach_msg_type_number_t *stateCount) {
	mach_msg_type_number_t _stateCount;
	if(!stateCount) {
		stateCount = &_stateCount;
	}
	*stateCount = x86_AVX_STATE64_COUNT;
	KERN_FAIL("thread_get_state", thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)state, stateCount));
}

uint64_t get_rip(thread_act_t thread) {
	x86_thread_state64_t state;
	mach_msg_type_number_t stateCount = x86_AVX_STATE64_COUNT;
	get_thread_state(thread, &state, &stateCount);
	return state.__rip;
}

void set_rip(thread_act_t thread, uint64_t rip_value) {
	x86_thread_state64_t state;
	mach_msg_type_number_t stateCount = x86_AVX_STATE64_COUNT;
	get_thread_state(thread, &state, &stateCount);
	state.__rip = rip_value;
	KERN_FAIL("thread_set_state", thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, stateCount));
}

void write_int3(task_t task, mach_vm_address_t address) {
	unsigned char int3 = INT3;
	KERN_FAIL("mach_vm_write", mach_vm_write(task, address, (vm_offset_t)&int3, sizeof(int3)));
}

void setup_child(task_t task, thread_act_t *_thread, mach_vm_address_t *_memory) {
	thread_act_array_t thread_list;
	mach_msg_type_number_t thread_count;
	KERN_FAIL("task_threads", task_threads(task, &thread_list, &thread_count));

	if(thread_count != 1) {
		printf("1 thread expected, got %d.\n", thread_count);
		exit(KERN_FAILURE);
	}

	thread_act_t thread = thread_list[0];
	*_thread = thread;

	mach_vm_address_t memory;
	KERN_FAIL("mach_vm_allocate", mach_vm_allocate(task, &memory, MEMORY_SIZE, VM_FLAGS_ANYWHERE));
	*_memory = memory;

	KERN_FAIL("mach_vm_protect", mach_vm_protect(task, memory, MEMORY_SIZE, 0, VM_PROT_ALL));

	write_int3(task, memory);

	set_rip(thread, memory);
}

// Start of the exception handler thread
void *exception_handler_main(void *arg) {
	mach_port_t exception_port = (mach_port_t)arg;
	if(mach_msg_server(mach_exc_server, 2048, exception_port, MACH_MSG_TIMEOUT_NONE) != MACH_MSG_SUCCESS) {
		puts("error: mach_msg_server()");
		exit(1);
	}

	return NULL;
}

kern_return_t  catch_mach_exception_raise_state(mach_port_t __unused exception_port, exception_type_t __unused exception, exception_data_t __unused code, mach_msg_type_number_t __unused code_count, int * __unused flavor, thread_state_t __unused in_state, mach_msg_type_number_t __unused in_state_count, thread_state_t __unused out_state, mach_msg_type_number_t * __unused out_state_count) {
	return KERN_FAILURE;
}

kern_return_t  catch_mach_exception_raise_state_identity(mach_port_t __unused exception_port, mach_port_t __unused thread, mach_port_t __unused task, exception_type_t __unused exception, exception_data_t __unused code, mach_msg_type_number_t __unused code_count, int * __unused flavor, thread_state_t __unused in_state, mach_msg_type_number_t __unused in_state_count, thread_state_t __unused out_state, mach_msg_type_number_t * __unused out_state_count) {
	return KERN_FAILURE;
}

// Called when an exception is caught from the child, e.g. SIGTRAP
kern_return_t catch_mach_exception_raise(mach_port_t __unused exception_port, mach_port_t thread, mach_port_t __unused task, exception_type_t exception, exception_data_t __unused code, mach_msg_type_number_t __unused code_count) {
	if(exception == EXC_BREAKPOINT) {
		KERN_FAIL("task_suspend", task_suspend(task));
		set_rip(thread, get_rip(thread) - 1);
		pthread_mutex_unlock(&mutex);
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

void setup_exception_handler(task_t task) {
	mach_port_t exception_port;
	KERN_FAIL("mach_port_allocate", mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port));
	KERN_FAIL("mach_port_insert_right", mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND));
	KERN_FAIL("task_set_exception_port", task_set_exception_ports(task, EXC_MASK_BREAKPOINT, exception_port, (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), MACHINE_THREAD_STATE));

	pthread_t exception_handler_thread;
	STD_FAIL("pthread_create", pthread_create(&exception_handler_thread, NULL, exception_handler_main, (void *)(uintptr_t)exception_port));
}

void print_registers(x86_thread_state64_t *state) {
	puts("");

	static x86_thread_state64_t last_state;
	static rflags_t last_rflags;
	static int first = 1;

	int i = 0;
#define X(r) do { \
	uint64_t v = state->__ ## r; \
	int c = !first && v != last_state.__ ## r; \
	printf(KGRN "%3s: %s%016" PRIX64 RESET "%s", #r, c? KRED: RESET, v, (i % 3 == 2 || i == REGISTERS - 1)? "\n": "  "); \
	i++; \
} while(false)
#include "registers.h"
#undef X

	printf(KBLU "Status: " KNRM);

	rflags_t rflags = (rflags_t)state->__rflags;

#define X(f) do { \
	uint8_t v = rflags.flags.f; \
	int c = !first && v != last_rflags.flags.f; \
	printf("  " KGRN "%s: %s%d" RESET, #f, c? KRED: RESET, v); \
} while(false)
#include "status_flags.h"
#undef X

	puts("");

	first = 0;
	last_state = *state;
	last_rflags = rflags;
}

bool get_number(char *str, uint64_t *val) {
	char *endptr;
	*val = strtoll(str, &endptr, 0);
	return *endptr == '\0';
}

bool get_value(char *str, x86_thread_state64_t *state, uint64_t *val) {
	if(get_number(str, val)) {
		return true;
	}

#define X(r) do { \
	if(strcmp(str, #r) == 0) { \
		*val = state->__ ## r; \
		return true; \
	} \
} while(false)
#include "registers.h"
#undef X

	return false;
}

size_t count_tokens(char *str, char *seperators) {
	size_t i = 0;
	char *p = strdup(str);
	while(strsep(&p, seperators)) {
		i++;
	}
	free(p);
	return i;
}

char *histfile;
bool waiting_for_input = false;
jmp_buf prompt_jmp_buf;

void read_input(task_t task, x86_thread_state64_t *state) {
	static char *line = NULL;
	while(true) {
		if(line) {
			free(line);
		}

		waiting_for_input = true;
		setjmp(prompt_jmp_buf);

		line = readline("> ");

		waiting_for_input = false;

		if(!line) {
			exit(0);
		}

		if(line[0] == '\0') {
			continue;
		}

		add_history(line);
		write_history(histfile);

		char *cmds[] = {"read", "write", "alloc", "regs"};

		char *help[] = {
			"Usage: .read address [len]\n"
			"Displays a hexdump of memory starting at address\n"
			"\n"
			"  address - an integer or a register name\n"
			"  len     - the amount of bytes to read",

			"Usage: .write address hexpairs\n"
			"Writes hexpairs to a destination address\n"
			"\n"
			"  address  - an integer or a register name\n"
			"  hexpairs - pairs of hexadecimal numbers",

			"Usage: .alloc size\n"
			"Allocates some memory and returns the address\n"
			"\n"
			"  len - the amount of bytes to allocate",

			"Usage: .regs\n"
			"Displays the values of the GPU registers"
		};

		ssize_t cmd_index = -1;
		if(line[0] == '?' || line[0] == '.') {
			for(size_t i = 0; i != sizeof(cmds) / sizeof(*cmds); i++) {
				size_t len = strlen(cmds[i]);
				if(strncmp(cmds[i], line + 1, len) == 0 && (line[len + 1] == '\0' || line[len + 1] == ' ')) {
					cmd_index = i;
					break;
				}
			}
		}

		if(line[0] == '?') {
			if(cmd_index != -1) {
				puts(help[cmd_index]);
				continue;
			}

			puts("Valid input:\n"
			       "  Help:\n"
			       "    ?      - show this help\n"
				   "    ?[cmd] - show help for a command\n"
				   "\n"
				   "  Commands:\n"
				   "    .read  - read from memory\n"
				   "    .write - write to memory\n"
				   "    .alloc - allocate memory\n"
				   "    .regs  - shows the contents of the registers\n"
				   "\n"
				   "Any other input will be interpreted as x86_64 assembly"
			);
		} else if(line[0] == '.') {
			size_t args = count_tokens(line, " ") - 1;

			char *p = line + 1;
			char *cmd = strsep(&p, " ");
			char *arg1 = strsep(&p, " ");
			char *arg2 = strsep(&p, " ");

			if(cmd_index == 0) {
				uint64_t address;
				if(args < 1 || args > 2 || !get_value(arg1, state, &address)) {
					puts(help[0]);
					continue;
				}

				uint64_t len = 0x20;
				if(args == 2) {
					if(!get_number(arg2, &len)) {
						puts(help[0]);
						continue;
					}
				}

				unsigned char *data = malloc(len);
				mach_vm_size_t count;
				KERN_TRY("mach_vm_read_overwrite", mach_vm_read_overwrite(task, address, len, (mach_vm_address_t)data, &count), {
					free(data);
					continue;
				});

				const size_t row_bytes = 8;
				for(int i = 0; i < count; i += row_bytes) {
					char str[3 * row_bytes];
					for(int j = 0; j < row_bytes && i + j < count; j++) {
						unsigned char c = data[i + j];
						str[3 * j] = int2hex(c >> 4);
						str[3 * j + 1] = int2hex(c & 0x0f);
						str[3 * j + 2] = ' ';
					}
					str[sizeof(str) - 1] = '\0';
					printf("%llx: %s\n", address + i, str);
				}

				free(data);
			} else if(cmd_index == 1) {
				uint64_t address;
				size_t len = strlen(arg2);
				if(args != 2 || !get_value(arg1, state, &address) || len % 2 != 0) {
					puts(help[1]);
					continue;
				}

				unsigned char *data = malloc(len / 2);
				for(int i = 0; i < len / 2; i++) {
					data[i] = hex2int(arg2[2 * i]) * 0x10 + hex2int(arg2[2 * i + 1]);
				}

				KERN_TRY("mach_vm_write", mach_vm_write(task, address, (vm_offset_t)data, len / 2), {
					free(data);
					continue;
				});

				printf("Wrote %zu bytes.\n", len / 2);

				free(data);
			} else if(cmd_index == 2) {
				uint64_t size;
				if(args != 1 || !get_number(arg1, &size)) {
					puts(help[2]);
					continue;
				}

				mach_vm_address_t address;
				KERN_TRY("mach_vm_allocate", mach_vm_allocate(task, &address, size, VM_FLAGS_ANYWHERE), {
					continue;
				});

				printf("Allocated %llu bytes at 0x%llx\n", size, address);
			} else if(cmd_index == 3) {
				print_registers(state);
			} else {
				printf("Invalid command: .%s\n", cmd);
			}
		} else {
			unsigned char *assembly;
			size_t asm_len;
			if(assemble_string(line, state->__rip, &assembly, &asm_len)) {
				KERN_FAIL("mach_vm_write", mach_vm_write(task, state->__rip, (vm_offset_t)assembly, asm_len));
				free(assembly);
				write_int3(task, state->__rip + asm_len);
				break;
			} else {
				puts("Failed to assemble instruction.");
			}
		}
	}
}

void setup_readline() {
	// Disable file auto-complete
	rl_bind_key('\t', rl_insert);

	asprintf(&histfile, "%s/%s", getenv("HOME"), ".asm_repl_history");
	read_history(histfile);
}

#define READY 'R'

void write_ready(int fd) {
	static char ready = READY;
	write(fd, &ready, sizeof(ready));
}

void read_ready(int fd) {
	char buf;
	if(read(fd, &buf, sizeof(buf)) <= 0 || buf != READY) {
		puts("Failed to read");
		exit(1);
	}
}

task_t child_task;

void sigint_handler(int sig) {
	if(waiting_for_input) {
		// Clear line
		printf("\33[2K\r");
		// Print prompt again
		longjmp(prompt_jmp_buf, 0);
	} else {
		// Suspend child and prompt for input
		puts("");
		task_suspend(child_task);
		pthread_mutex_unlock(&mutex);
	}
}

void sigchld_handler(int sig) {
	int status;
	pid_t result = waitpid(-1, &status, WNOHANG);
	if(WIFSIGNALED(status)) {
		puts("Process died!");
		exit(1);
	}
}

int main(int argc, const char *argv[]) {
	int p1[2];
	int p2[2];
	pipe(p1);
	pipe(p2);

	int parent_read = p1[0];
	int child_write = p1[1];
	int child_read = p2[0];
	int parent_write = p2[1];

	pid_t pid = fork();
	if(pid == -1) {
		perror("fork");
		return 1;
	}

	if(pid == 0) {
		close(parent_read);
		close(parent_write);

		signal(SIGINT, SIG_IGN);

		// Drop privileges
		setgid(-2);
		setuid(-2);

		// We are ready for the parent to register the exception handlers
		write_ready(child_write);

		// Wait for the parents exception handler
		read_ready(child_read);

		// This will be caught by the parents exception handler
		__asm__("int3");
	} else {
		close(child_read);
		close(child_write);

		signal(SIGINT, sigint_handler);
		signal(SIGCHLD, sigchld_handler);

		setup_readline();

		// Wait for the child to be ready
		read_ready(parent_read);

		task_t task;
		KERN_FAIL("task_for_pid", task_for_pid(mach_task_self(), pid, &task));
		child_task = task;

		pthread_mutex_init(&mutex, NULL);
		pthread_mutex_lock(&mutex);

		setup_exception_handler(task);

		// We have set up the exception handler so we make the child raise SIGTRAP
		write_ready(parent_write);

		// Wait for exception handler to be called
		pthread_mutex_lock(&mutex);

		thread_act_t thread;
		mach_vm_address_t memory;
		setup_child(task, &thread, &memory);

		task_resume(task);

		while(true) {
			// Wait for exception handler
			pthread_mutex_lock(&mutex);

			x86_thread_state64_t state;
			mach_msg_type_number_t stateCount = x86_AVX_STATE64_COUNT;
			get_thread_state(thread, &state, &stateCount);

			print_registers(&state);

			read_input(task, &state);

			task_resume(task);
		}
	}

	return 0;
}
