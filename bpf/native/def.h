#pragma once

#include "bpf_core_read.h"

#define SEC(name) __attribute__((section(name),used))
#define UINT(name, val) int(*name)[val]

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

#define BPF_MAP_TYPE_PERF_EVENT_ARRAY (4)

#define BPF_F_CURRENT_CPU (0xffffffffUL)

// from tools/lib/bpf/libbpf.h
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

static int (*perf_event_output)(void *ctx, const void *map, uint64_t flags, const void *data, uint64_t size) = (void *)25;
static long (*get_current_comm)(void *buf, uint32_t size_of_buf) = (void *) 16;
static long (*bpf_probe_read_kernel)(void *dst, uint32_t size, const void *unsafe_ptr) = (void *) 113;

struct pt_regs;

// from bpf/bpf_core_read.h
#define BPF_CORE_READ(src, a, ...)					    \
	({								    \
		___type((src), a, ##__VA_ARGS__) __r;			    \
		BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);	    \
		__r;							    \
	})


// from asm/ptrace.h
// from bpf/bpf_tracing.h
#if AMD64

struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};

#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rsp)
#define PT_REGS_FP(x) ((x)->rbp)
#define PT_REGS_RC(x) ((x)->rax)
#define PT_REGS_SP(x) ((x)->rsp)
#define PT_REGS_IP(x) ((x)->rip)

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), rdi)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), rsi)
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), rdx)
#define PT_REGS_PARM4_CORE(x) BPF_CORE_READ((x), rcx)
#define PT_REGS_PARM5_CORE(x) BPF_CORE_READ((x), r8)
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), rsp)
#define PT_REGS_FP_CORE(x) BPF_CORE_READ((x), rbp)
#define PT_REGS_RC_CORE(x) BPF_CORE_READ((x), rax)
#define PT_REGS_SP_CORE(x) BPF_CORE_READ((x), rsp)
#define PT_REGS_IP_CORE(x) BPF_CORE_READ((x), rip)

#elif I386

struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

#define PT_REGS_PARM1(x) ((x)->eax)
#define PT_REGS_PARM2(x) ((x)->edx)
#define PT_REGS_PARM3(x) ((x)->ecx)
#define PT_REGS_PARM4(x) 0
#define PT_REGS_PARM5(x) 0
#define PT_REGS_RET(x) ((x)->esp)
#define PT_REGS_FP(x) ((x)->ebp)
#define PT_REGS_RC(x) ((x)->eax)
#define PT_REGS_SP(x) ((x)->esp)
#define PT_REGS_IP(x) ((x)->eip)

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), eax)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), edx)
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), ecx)
#define PT_REGS_PARM4_CORE(x) 0
#define PT_REGS_PARM5_CORE(x) 0
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), esp)
#define PT_REGS_FP_CORE(x) BPF_CORE_READ((x), ebp)
#define PT_REGS_RC_CORE(x) BPF_CORE_READ((x), eax)
#define PT_REGS_SP_CORE(x) BPF_CORE_READ((x), esp)
#define PT_REGS_IP_CORE(x) BPF_CORE_READ((x), eip)

#else

#error "unsupported platform"

#endif