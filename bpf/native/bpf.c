#include "def.h"

#define ACTION_OPEN   1
#define ACTION_CREATE 2
#define ACTION_UNLINK 3

#define KEY_ACTION       1
#define KEY_DIRECTION_FD 2

struct {
    UINT(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_PERCPU_HASH);
    UINT(key_size, sizeof(u8));
    UINT(value_size, sizeof(s32));
    UINT(max_entries, 4);
} local SEC(".maps");

struct filename {
    const char *name;
};

struct event_msg {
    u32 action;
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
    
    event.action = action;
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event.uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
    event.dfd = dfd;

    if (bpf_get_current_comm(event.thread_name, sizeof(event.thread_name)) < 0)
        event.thread_name[0] = '\0';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("kprobe/filp_open")
int kprobe_filp_open(struct pt_regs *ctx) {
    s32 dfd = (s32) PT_REGS_PARM1_CORE(ctx);
    struct filename *filename = (struct filename *) PT_REGS_PARM2_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    write_event(ctx, dfd, name, ACTION_OPEN);

    return 0;
}

SEC("kprobe/filename_create")
int kprobe_filename_create(struct pt_regs *ctx) {
    s32 dfd = (s32) PT_REGS_PARM1_CORE(ctx);
    struct filename *filename = (struct filename *) PT_REGS_PARM2_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    write_event(ctx, dfd, name, ACTION_CREATE);

    return 0;
}

SEC("kprobe/unlinkat")
int kprobe_unlinkat(struct pt_regs *ctx) {
    s32 dfd = (s32) PT_REGS_PARM1_CORE(ctx);
    struct filename *filename = (struct filename *) PT_REGS_PARM2_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    write_event(ctx, dfd, name, ACTION_UNLINK);

    return 0;
}

SEC("kprobe/openat")
int kprobe_openat(struct pt_regs *ctx) {
    struct pt_regs *user_regs = (struct pt_regs *) PT_REGS_PARM1_CORE(ctx);

    u8 key_action = KEY_ACTION;
    u8 key_dfd = KEY_DIRECTION_FD;

    u32 action = ACTION_OPEN;
    s32 dfd = (s32) PT_REGS_PARM1_CORE(user_regs);

    bpf_map_update_elem(&local, &key_action, &action, 0);
    bpf_map_update_elem(&local, &key_dfd, &dfd, 0);
    
    return 0;
}

SEC("kretprobe/ret_filename")
int kprobe_return_filename(struct pt_regs *ctx) {
    u8 key_action = KEY_ACTION;
    u8 key_dfd = KEY_DIRECTION_FD;

    s32 *action = bpf_map_lookup_elem(&local, &key_action);
    if (action == NULL)
        return 0;
    
    s32 *dfd = bpf_map_lookup_elem(&local, &key_dfd);
    if (dfd == NULL)
        return 0;
    
    struct filename *filename = (struct filename *) PT_REGS_RET_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    write_event(ctx, -100, name, ACTION_OPEN);

    bpf_map_delete_elem(&local, &key_action);
    bpf_map_delete_elem(&local, &key_dfd);

    return 0;
}

SEC("license")
char LICENSE[] = "GPL";