#include "vmlinux.h"
#include "bpf_helpers.h"

// perf map to send update events to userspace.
struct bpf_map_def SEC("maps/perf_open") openat2 = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u32),
  .max_entries = 128,
};

struct data_t {
	__u32 pid;
	char file_name[256];
};

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_open(struct pt_regs *ctx)
{
	struct data_t data = {0};
    data.pid = bpf_get_current_pid_tgid() >> 32;
	char *filename = (char *)PT_REGS_PARM2(ctx);
	bpf_probe_read(&data.file_name, sizeof(data.file_name), filename);
    printt("do_sys_openat2 pid: %u file_name: %s", data.pid, data.file_name);
	bpf_perf_event_output(ctx, &openat2, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;