#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "if_ether.h"

#define TLS_HANDSHAKE 22
#define TLS_1_0 0x0301
#define TLS_1_1 0x0302
#define TLS_1_2 0x0303
#define TLS_1_3 0x0304

#define TLS_CLIENT_HELLO 1
#define TLS_EXT_SERVER_NAME 0

struct data_t {
    u16 len;
    char ext[256];
};

SEC("prog")
int  bpf_prog1(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    printt("src ip: %u, dst ip: %u", bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));
    printt("src port: %u, dst port: %u, protocol: %u\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), ip->protocol);

    void *payload = (void *)(tcp+1);
    printt("tcp: 0x%08x payload: 0x%08x", tcp, payload);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";