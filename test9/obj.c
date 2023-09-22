#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

// #define TLS_HANDSHAKE 22
// #define TLS_1_0 0x0301
// #define TLS_1_1 0x0302
// #define TLS_1_2 0x0303
// #define TLS_1_3 0x0304

// #define TLS_CLIENT_HELLO 1
// #define TLS_EXT_SERVER_NAME 0

// struct data_t {
//     u16 len;
//     char ext[256];
// };


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


SEC("kprobe/__nf_conntrack_hash_insert")
int kprobe____nf_conntrack_hash_insert(struct pt_regs *ctx) {

  u64 ts = bpf_ktime_get_ns();

  printt("ts: %lu", ts);
//   nf_conn_t *ct = (nf_conn_t *) PT_REGS_PARM1(ctx);

  return 0;
}

SEC("kprobe/__nf_ct_refresh_acct")
int kprobe__nf_ct_refresh_acct(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();

    printt("ts: %lu", ts);

    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM3(ctx);

    unsigned int skb_len;
	unsigned int data_len;
    bpf_probe_read(&skb_len, sizeof(skb_len), &skb->len);
    bpf_probe_read(&data_len, sizeof(data_len), &skb->data_len);

    if (skb_len <=40 || data_len <=40)
        return 0;

    unsigned char * skb_head;
    bpf_probe_read(&skb_head, sizeof(skb_head), &skb->head);
    unsigned char *skb_data;
    bpf_probe_read(&skb_data, sizeof(skb_data), &skb->data);

    u16 protocol;
    bpf_probe_read(&protocol, sizeof(protocol), &skb->protocol);

    u16 l3_off;
    bpf_probe_read(&l3_off, sizeof(l3_off), &skb->network_header);

    u8 iphdr_first_byte;
    u8 ip_vsn;
    struct iphdr *ip;
    ip = (struct iphdr *)(skb_head + l3_off);
    
    bpf_probe_read(&iphdr_first_byte, 1, skb_data);
    ip_vsn = iphdr_first_byte >> 4;

    u8 l4_proto=0;
    if (ip_vsn == 4) {
        bpf_probe_read(&l4_proto, 1, &ip->protocol);
    } else if (ip_vsn == 6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
        bpf_probe_read(&l4_proto, 1, &ip6->nexthdr);
    } else {
        printt("ip_vsn: %u", ip_vsn);
    }
    if (l4_proto != IPPROTO_TCP)
        return 0;

    u16 l4_off;
    bpf_probe_read(&l4_off, sizeof(l4_off), &skb->transport_header);

    struct tcphdr tcph = {};
    bpf_probe_read(&tcph, sizeof(tcph), skb_head + l4_off);
    if (bpf_ntohs(tcph.dest) != 443) 
        return 0;

    sk_buff_data_t tail;
    bpf_probe_read(&tail, sizeof(tail), &skb->tail);

    printt("skb->len: %u, skb->data_len: %u", skb_len, data_len);

    printt("l3_off: %u, l4_off: %u", l3_off, l4_off);
    printt("sport: %u dport: %u", bpf_ntohs(tcph.source),bpf_ntohs(tcph.dest));
    printt("doff: %u", tcph.doff);
    printt("skb->head: %2x  skb_data: %2x", skb_head, skb_data);
    printt("skb->tail: %2x", skb_head+tail);

    unsigned char * offset = skb_head + l4_off + tcph.doff*4;

    printt("offset: %2x %2x %2x",skb_head + l3_off, skb_head + l4_off, offset);

    u8 content_type;
    bpf_probe_read(&content_type, sizeof(content_type), offset);
    printt("content_type: %2x", content_type);

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
