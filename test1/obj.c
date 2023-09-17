#include <vmlinux.h>
#include "bpf_helpers.h"

struct data_t {
	__u32 pid;
	char file_name[256];
    __u32 mode;
};


SEC("kprobe/do_fchmodat")
int kprobe__do_fchmodat(struct pt_regs *ctx) {
    struct data_t data = {0};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    // long unsigned int xmode;
    // struct mytest_t xmode;
    // bpf_probe_read(&xmode, sizeof(xmode), &ctx->uregs[1]);
    // bpf_trace_printk(fmt_str, sizeof(fmt_str), data.pid, data.file_name, xmode.a);

    char *filename = (char *)PT_REGS_PARM2(ctx);
    unsigned int mode = PT_REGS_PARM3(ctx);
    bpf_probe_read(&data.file_name, sizeof(data.file_name), filename);
    data.mode = (__u32) mode;

    printt("do_fchmodat pid: %u file_name: %s mode: %u\n", data.pid, data.file_name, mode);

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;