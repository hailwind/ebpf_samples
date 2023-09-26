#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "xdp_helpers.h"

//len: 1+2+2=5
struct tls_hdr {
    __u8 content_type;
    __u16 tls_ver;
    __u16 pkt_len;
}__attribute__((__packed__));

//len 1+3+2+32 = 38
struct tls_handshake {
    __u8 handshake_type;
    __u8 handshake_len[3];
    __u16 tls_ver2;
    __u8 random[32];
    //u8 session_id_len;
    //session_id
    //u16 cipher_suites_len;
    //cipher suites
    //u8 compression_method length
    //compression method
    //u16 extensions_len;
    //extensions
    //session_id, cipher_suites, compression_methods, extensions 需要动态解析
}__attribute__((__packed__));


struct tls_xl1 {
    __u8 len;
};

struct tls_xl2 {
    __u16 len;
};

/*
struct tls_extension {
    __u16 type;
    __u16 len;
    // extension_data 需要动态解析
};

struct tls_server_name {
    __u16 server_name_list_len;
    __u8 server_name_type;
    __u16 server_name_len;
}__attribute__((__packed__));
*/

// perf map to send update events to userspace.
struct bpf_map_def SEC("maps/tls_hello") tls_hello = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u32),
  .max_entries = 128,
};

// XDP program //
SEC("xdp/prog1")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data     = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_ntohs(ETH_P_IP) && eth->h_proto != bpf_ntohs(ETH_P_IPV6))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip+sizeof(*ip);

    if ((void *)tcp + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }
    // printt("> > > > > > > > > > > > > > > > > > > > > > > ");
    if (bpf_ntohs(tcp->dest)!=443) {
        return XDP_PASS;
    }

    __u16 hdr_len = sizeof(*eth) + sizeof(*ip) + tcp->doff*4;
    __u16 offset = hdr_len;
    // printt("src ip: %u, dst ip: %u", bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));
    // printt("src port: %u, dst port: %u, protocol: %u", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), ip->protocol);
    struct tls_hdr *tlshdr = data + offset;
    if ((void *)(tlshdr) + sizeof(*tlshdr) > data_end)
        return XDP_PASS;
    // printt("content_type 0x%02x tls_ver 0x%04x pkt_len %u", tlshdr->content_type, tlshdr->tls_ver, bpf_ntohs(tlshdr->pkt_len));

    // printt("ip.tot_len: %u", bpf_ntohs(ip->tot_len));
    // printt("tcp: 0x%x tlshdr: 0x%x", tcp, tlshdr);
    if (tlshdr->content_type != TLS_HANDSHAKE)
        return XDP_PASS;

    // tlshdr->pkt_len =bpf_ntohs(tlshdr->pkt_len);
    __u16 tls_ver=bpf_ntohs(tlshdr->tls_ver);
    if (tls_ver!=TLS_1_0 && tls_ver!=TLS_1_1 && tls_ver!=TLS_1_2 && tls_ver!=TLS_1_3)
        return XDP_PASS;
    // printt("offset.1: %u", offset);//54
    offset += sizeof(*tlshdr);
    // printt("offset.2: %u", offset);//59

    struct tls_handshake *tlshs = data + offset;
    if ((void *)(tlshs) + sizeof(*tlshs) > data_end)
        return XDP_PASS;
    // printt("handshake_type 0x%02x tls_ver2 0x%04x", tlshs->handshake_type, tlshs->tls_ver2);
    if (tlshs->handshake_type != TLS_CLIENT_HELLO)
        return XDP_PASS;
    offset += sizeof(*tlshs);
    // printt("offset.3: %u", offset);//97

    // 下面分别是session_id, cipher suites, compression methods, extensions
    if (data+hdr_len+4 > data_end )
        return XDP_PASS;
    char payload[4];
    memcpy(&payload, data + hdr_len, sizeof(payload));

    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &tls_hello, flags, &payload, sizeof(payload));

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;