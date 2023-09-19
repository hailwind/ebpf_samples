#include "vmlinux.h"
#include "bpf_helpers.h"

// perf map to send update events to userspace.
struct bpf_map_def SEC("maps/my_map") my_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u64),
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

    int key = 0;
    unsigned long *value;
    value = bpf_map_lookup_elem(&my_map, &key);
    if (value) {
        printt("Read value from map: %lu\n", *value);
    }

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
