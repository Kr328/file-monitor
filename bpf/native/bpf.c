#include "def.h"

#define ACTION_OPEN   1
#define ACTION_CREATE 2
#define ACTION_UNLINK 3

struct {
    UINT(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct filename {
    const char *name;
};

struct event_msg {
    u32 pid;
    u32 uid;
    s32 dfd;
    u8 thread_name[16];
    u8 path[256];
};

INLINE
void write_event(void *ctx, s32 dfd, const char *name, u32 action) {
    struct event_msg event;

    if (bpf_probe_read_str(&event.path, sizeof(event.path), name) < 0)
        return;
    
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event.uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
    event.dfd = dfd;

    if (bpf_get_current_comm(event.thread_name, sizeof(event.thread_name)) < 0)
        event.thread_name[0] = '\0';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("kprobe/do_filp_open")
int kprobe_do_filp_open(struct pt_regs *ctx) {
    s32 dfd = (s32) PT_REGS_PARM1_CORE(ctx);
    struct filename *filename = (struct filename *) PT_REGS_PARM2_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    write_event(ctx, dfd, name, ACTION_OPEN);

    return 0;
}

SEC("license")
char LICENSE[] = "GPL";