#include "def.h"

struct {
    UINT(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct filename {
    const char *name;
};

struct event_msg {
    u32 pid;
    u32 uid;
    u8 thread_name[16];
    u8 path[256];
};

SEC("kprobe/filp_open")
int kprobe_filp_open(struct pt_regs *ctx) {
    struct filename *filename = (struct filename *) PT_REGS_PARM2_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    struct event_msg event;

    if (bpf_probe_read_str(&event.path, sizeof(event.path), name) < 0)
        return 0;
    
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event.uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);

    if (bpf_get_current_comm(event.thread_name, sizeof(event.thread_name)) < 0)
        event.thread_name[0] = '\0';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("license")
char LICENSE[] = "GPL";