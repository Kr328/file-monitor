#include "def.h"

struct {
    UINT(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/openat")
int kprobe_openat(struct pt_regs *ctx) {
    struct pt_regs *real = (struct pt_regs *) PT_REGS_PARM1_CORE(ctx);

    char event[128];

    get_current_comm(event, sizeof(event));

    perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("license")
char LICENSE[] = "GPL";