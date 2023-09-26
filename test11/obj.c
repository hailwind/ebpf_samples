// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// XDP dump is simple program that dumps new IPv4 TCP connections through perf events.

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x1
#define TLS_EXT_SERVER_NAME 0x0
#define TLS_CLIENT_HELLO_MAX_LEN 512

#define SSL_V3  0x0300
#define TLS_1_0 0x0301
#define TLS_1_1 0x0302
#define TLS_1_2 0x0303
#define TLS_1_3 0x0304

#define IPPROTO_TCP 6

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define printt(fmt, ...)                                           \
	({                                                             \
		char ____fmt[] = fmt;                                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})

struct tls_xl1 {
    __u8 len;
};

struct tls_xl2 {
    __u16 len;
};

struct tls_extension {
    __u16 type;
    __u16 len;
    // extension_data 需要动态解析
};

struct tls_server_name {
    __u16 server_name_list_len;
    __u8 server_name_type;
    __u16 server_name_len;
    char domain[256];
}__attribute__((__packed__));

// char domain[256];

struct bufft {
    char buff[4];
};

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


// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;
  union {
    struct {
      // Field order has been converted LittleEndiand -> BigEndian
      // in order to simplify flag checking (no need to ntohs())
      __u16 ns : 1,
      reserved : 3,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
    };
  };
  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};

// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);


// PerfEvent item
struct perf_event_item {
  __u32 src_ip, dst_ip;
  __u16 src_port, dst_port;
};
_Static_assert(sizeof(struct perf_event_item) == 12, "wrong size of perf_event_item");

// XDP program //
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data     = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_ntohs(ETH_P_IP))
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
    printt("content_type 0x%02x tls_ver 0x%04x pkt_len %u", tlshdr->content_type, tlshdr->tls_ver, bpf_ntohs(tlshdr->pkt_len));

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
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        struct tls_xl1 *xl1 = data + offset;
        if ((void *)xl1 + sizeof(*xl1) > data_end)
            return XDP_PASS;
        // printt("xl1.len %u", xl1->len);
        offset+=sizeof(*xl1);
        __u8 xl1_len=xl1->len;
        if ( xl1_len> 0)
            offset+=xl1_len;
        // printt("loop %d offset: %u xl1_len: %u", i, offset, xl1_len);
        if (offset > TLS_CLIENT_HELLO_MAX_LEN)
            return XDP_PASS;

        struct tls_xl2 *xl2 = data + offset;
        if ((void *)xl2 + sizeof(*xl2) > data_end)
            return XDP_PASS;
        offset+=sizeof(*xl2);
        __u16 xl2_len=bpf_ntohs(xl2->len);
        if ( i==0 && xl2_len> 0)
            offset+=xl2_len;
        // printt("loop %d offset: %u xl2_len: %u", i, offset, xl2_len);
        if (offset > TLS_CLIENT_HELLO_MAX_LEN)
            return XDP_PASS;
    }

    if (data+hdr_len+512 > data_end )
        return XDP_PASS;
    // printt("ttt %02x%02x%02x", payload.buff[142],payload.buff[143],payload.buff[144]);
    // struct bufft payload;
    char payload[4];
    memcpy(&payload, data + hdr_len, sizeof(payload));

    printt("payload: %x", &payload[0]);
    printt("data: %x", data + hdr_len);

    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &payload, sizeof(payload));

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";