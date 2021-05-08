#include "def.h"

struct {
    UINT(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct filename {
    const char *name;
};

SEC("kprobe/filp_open")
int kprobe_filp_open(struct pt_regs *ctx) {
    struct filename *filename = (struct filename *) PT_REGS_PARM2_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    char event[256];

    get_current_comm(event, 128);
    bpf_probe_read_str(&event[128], 128, name);

    perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("license")
char LICENSE[] = "GPL";