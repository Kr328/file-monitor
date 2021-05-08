#pragma once

#include "bpf_core_read.h"

#define SEC(name) __attribute__((section(name),used))
#define UINT(name, val) int(*name)[val]
#define INLINE __attribute__((always_inline))

typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned char u8;
typedef int s32;

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

static int (*bpf_perf_event_output)(void *ctx, const void *map, u64 flags, const void *data, u64 size) = (void *)25;
static long (*bpf_get_current_comm)(void *buf, u32 size_of_buf) = (void *) 16;
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *unsafe_ptr) = (void *) 4;
static long (*bpf_probe_read_str)(void *dst, u32 size, const void *unsafe_ptr) = (void *) 45;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;

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

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), rdi)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), rsi)
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), rdx)
#define PT_REGS_PARM4_CORE(x) BPF_CORE_READ((x), rcx)
#define PT_REGS_PARM5_CORE(x) BPF_CORE_READ((x), r8)
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), rsp)

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

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), eax)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), edx)
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), ecx)
#define PT_REGS_PARM4_CORE(x) 0
#define PT_REGS_PARM5_CORE(x) 0
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), esp)

#elif ARM64

struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), regs[0])
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), regs[1])
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), regs[2])
#define PT_REGS_PARM4_CORE(x) BPF_CORE_READ((x), regs[3])
#define PT_REGS_PARM5_CORE(x) BPF_CORE_READ((x), regs[4])
#define PT_REGS_PARM6_CORE(x) BPF_CORE_READ((x), regs[5])
#define PT_REGS_PARM7_CORE(x) BPF_CORE_READ((x), regs[6])
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), regs[0])

#else

#error "unsupported platform"

#endif