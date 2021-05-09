#include "def.h"

#define ACTION_OPEN    1
#define ACTION_MKDIR   2
#define ACTION_UNLINK  3

#define OPEN_AT_CWD (-100)

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

struct context {
    u32 action;
    s32 dfd;
};

struct {
    UINT(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_HASH);
    UINT(key_size, sizeof(u64));
    UINT(value_size, sizeof(struct context));
    UINT(max_entries, 256);
} local SEC(".maps");

INLINE
void write_event(void *ctx, s32 dfd, const char *name, u32 action) {
    struct event_msg event;

    if (bpf_probe_read_str(&event.path, sizeof(event.path), name) < 0) {
        return;
    }
    
    event.action = action;
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event.uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
    event.dfd = dfd;

    if (bpf_get_current_comm(event.thread_name, sizeof(event.thread_name)) < 0)
        event.thread_name[0] = '\0';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

INLINE 
void store_context(u32 action, s32 dfd) {
    struct context ctx = {
        .action = action,
        .dfd = dfd,
    };

    u64 id = bpf_get_current_task();

    bpf_map_update_elem(&local, &id, &ctx, 0);
}

SEC("kprobe/open")
int kprobe_open(struct pt_regs *ctx) {
    store_context(ACTION_OPEN, OPEN_AT_CWD);

    return 0;
}

SEC("kprobe/openat")
int kprobe_openat(struct pt_regs *ctx) {
    struct pt_regs *user_regs = (struct pt_regs *) PT_REGS_PARM1_CORE(ctx);

    s32 dfd = (s32) PT_REGS_PARM1_CORE(user_regs);

    store_context(ACTION_OPEN, dfd);
    
    return 0;
}

SEC("kprobe/openat2")
int kprobe_openat2(struct pt_regs *ctx) {
    struct pt_regs *user_regs = (struct pt_regs *) PT_REGS_PARM1_CORE(ctx);

    s32 dfd = (s32) PT_REGS_PARM1_CORE(user_regs);

    store_context(ACTION_OPEN, dfd);
    
    return 0;
}

SEC("kprobe/mkdir")
int kprobe_mkdir(struct pt_regs *ctx) {
    store_context(ACTION_MKDIR, OPEN_AT_CWD);

    return 0;
}

SEC("kprobe/mkdirat")
int kprobe_mkdirat(struct pt_regs *ctx) {
    struct pt_regs *user_regs = (struct pt_regs *) PT_REGS_PARM1_CORE(ctx);

    s32 dfd = (s32) PT_REGS_PARM1_CORE(user_regs);

    store_context(ACTION_MKDIR, dfd);

    return 0;
}

SEC("kprobe/unlink")
int kprobe_unlink(struct pt_regs *ctx) {
    store_context(ACTION_UNLINK, OPEN_AT_CWD);

    return 0;
}

SEC("kprobe/unlinkat")
int kprobe_unlinkat(struct pt_regs *ctx) {
    struct pt_regs *user_regs = (struct pt_regs *) PT_REGS_PARM1_CORE(ctx);

    s32 dfd = (s32) PT_REGS_PARM1_CORE(user_regs);

    store_context(ACTION_UNLINK, dfd);

    return 0;
}

SEC("kretprobe/ret_filename")
int kprobe_return_filename(struct pt_regs *ctx) {
    u64 id = bpf_get_current_task();

    struct context *local_ctx = (struct context *) bpf_map_lookup_elem(&local, &id);
    if (local_ctx == NULL)
        return 0;
    
    struct filename *filename = (struct filename *) PT_REGS_RET_CORE(ctx);
    const char *name = (const char *) BPF_CORE_READ(filename, name);

    write_event(ctx, local_ctx->dfd, name, local_ctx->action);

    bpf_map_delete_elem(&local, &id);

    return 0;
}

SEC("license")
char LICENSE[] = "GPL";