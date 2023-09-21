#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

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

SEC("classifier")
int extract_sni_from_skb(struct __sk_buff *skb) {
    struct ethhdr eth = {};
    struct iphdr iph = {};
    struct tcphdr tcph = {};
    u8 content_type;
    u16 tls_ver;
    u16 pkt_len;
    u8 handshake_type;


    // Load Ethernet, IP, and TCP headers
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph));
    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph), &tcph, sizeof(tcph));

    if (iph.protocol != IPPROTO_TCP)
        return 0;

    // Load TLS type and handshake type
    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph) + tcph.doff*4, &content_type, sizeof(content_type));
    // printt("content_type: %u", content_type);
    if (content_type != TLS_HANDSHAKE) 
        return 0;

    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph) + tcph.doff*4 + 1, &tls_ver, sizeof(tls_ver));
    // printt("tls_ver: %2x", tls_ver);
    tls_ver=bpf_ntohs(tls_ver);

    if (tls_ver!=TLS_1_0 && tls_ver!=TLS_1_1 && tls_ver!=TLS_1_2 && tls_ver!=TLS_1_3)
        return 0;

    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph) + tcph.doff*4 + 5, &handshake_type, sizeof(handshake_type));
    // printt("handshake_type: %u", handshake_type);
    if (handshake_type!=TLS_CLIENT_HELLO)
        return 0;

    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph) + tcph.doff*4 + 3, &pkt_len, sizeof(pkt_len));
    printt("content_type: %2x tls: %2x", content_type, tls_ver);

    int offset = sizeof(eth) + sizeof(iph) + tcph.doff*4;
    offset += 1+2+2; // content_type tls_ver pkt_len
    offset += 1+3+2; // handshake_type length tls_ver
    offset += 32;  // random
    
    // session_id_len session_id
    u8 session_id_len;
    bpf_skb_load_bytes(skb, offset, &session_id_len, sizeof(session_id_len));
    offset += 1 + session_id_len; 
    
    // cipher_suites_len cipher_suites
    u16 cipher_suites_len;
    bpf_skb_load_bytes(skb, offset, &cipher_suites_len, sizeof(cipher_suites_len));
    cipher_suites_len = bpf_ntohs(cipher_suites_len);
    offset += 2 + cipher_suites_len; 
    
    // compression_methods_len compression_methods
    u8 compression_methods_len;
    bpf_skb_load_bytes(skb, offset, &compression_methods_len, sizeof(compression_methods_len));
    offset += 1 + compression_methods_len; 

    // printt("extensions_len offset %u", offset);

    u16 extensions_len;
    bpf_skb_load_bytes(skb, offset, &extensions_len, sizeof(extensions_len));
    extensions_len=bpf_ntohs(extensions_len);

    // printt("extensions_len: %u", extensions_len);

    offset+=2;
    u16 end_offset = offset+extensions_len;
    printt("extensions offset %u end: %u", offset, end_offset);

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        // printt("loop offset %u", offset);
        unsigned short ext_type;
        bpf_skb_load_bytes(skb, offset, &ext_type, sizeof(ext_type));
        if (ext_type == TLS_EXT_SERVER_NAME) {
            struct data_t sni = {0};
            unsigned short domain_len;
            bpf_skb_load_bytes(skb, offset + 7, &domain_len, sizeof(domain_len));
            sni.len=bpf_ntohs(domain_len);

            bpf_skb_load_bytes(skb, offset + 9, &sni.ext, 256);
            printt("len: %u domain: %s",sni.len, sni.ext);
            break;
        }
        u16 ext_len;
        bpf_skb_load_bytes(skb, offset+2, &ext_len, sizeof(ext_len));
        ext_len=bpf_ntohs(ext_len);
        // printt("ext len %u", ext_len);

        offset+=4;
        offset+=ext_len;
        // printt("end loop offset %u", offset);
        if ( offset>end_offset ) 
            break;
    }

    // struct data_t ext = {0};
    // ext.len = bpf_ntohs(ext_len);

    // bpf_skb_load_bytes(skb, offset+2, &ext.ext_bin, 256);    
    // printt("domain: %x", ext.ext_bin);

    // Find Server Name extension
    // int offset = sizeof(eth) + sizeof(iph) + tcph.doff*4 + 144; // 43 is the minimum size of Client Hello
    // while (true) {
    // u8 arr[4];
    // bpf_skb_load_bytes(skb, offset, &arr, sizeof(arr));
    // printt("arr_u: %u %u %u ", arr[0], arr[1], arr[2]);
    // printt("arr_x: %2x %2x %2x ", arr[0], arr[1], arr[2]);
    // unsigned short ext_total_len;
    /*
    unsigned short ext_type;

        // bpf_skb_load_bytes(skb, offset, &ext_total_len, sizeof(ext_total_len));
        bpf_skb_load_bytes(skb, offset, &ext_type, sizeof(ext_type));


        // printt("ext_type %2x", bpf_ntohs(ext_type));
        if (ext_type == TLS_EXT_SERVER_NAME) {
            struct data_t sni = {0};
            unsigned short domain_len;
            bpf_skb_load_bytes(skb, offset + 7, &domain_len, sizeof(domain_len));
            sni.len=bpf_ntohs(domain_len);

            printt("offset: %u domain_len: %u skb.len: %u\n", offset, sni.len, skb->len);
            bpf_skb_load_bytes(skb, offset + 9, &sni.domain, 256);
            printt("domain: %s", sni.domain);
        }
    */
    // offset += 4 + len; // 4 is the size of extension type and length fields
    // }

    return 0;
}

char _license[] SEC("license") = "GPL";