/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/*
 * Note that bpf programs need to include either
 * vmlinux.h (auto-generated from BTF) or linux/types.h
 * in advance since bpf_helper_defs.h uses such types
 * as __u64.
 */
#include "bpf_helper_defs.h"

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif

/*
 * Helper macro to manipulate data structures
 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member)				\
	({							\
		void *__mptr = (void *)(ptr);			\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

/*
 * Helper macro to throw a compilation error if __bpf_unreachable() gets
 * built into the resulting code. This works given BPF back end does not
 * implement __builtin_trap(). This is useful to assert that certain paths
 * of the program code are never used and hence eliminated by the compiler.
 *
 * For example, consider a switch statement that covers known cases used by
 * the program. __bpf_unreachable() can then reside in the default case. If
 * the program gets extended such that a case is not covered in the switch
 * statement, then it will throw a build error due to the default case not
 * being compiled out.
 */
#ifndef __bpf_unreachable
# define __bpf_unreachable()	__builtin_trap()
#endif

#define printt(fmt, ...)                                           \
	({                                                             \
		char ____fmt[] = fmt;                                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})


/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

enum libbpf_pin_type {
	LIBBPF_PIN_NONE,
	/* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
	LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate {
	TRI_NO = 0,
	TRI_YES = 1,
	TRI_MODULE = 2,
};

#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))

#endif