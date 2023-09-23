#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

SEC("prog")
int xdp_ipv6_filter_program(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
	u16 eth_type = 0;

    u64 offset = sizeof(*eth);
    if ((void *)eth + offset > data_end)
        return XDP_PASS;
    eth_type = eth->h_proto;

    printt("Debug: eth_type:0x%x\n", bpf_ntohs(eth_type));
	if (eth_type == bpf_ntohs(0x86dd)) {
		return XDP_PASS;
	} else {
		return XDP_DROP;
	}
}

char _license[] SEC("license") = "GPL";