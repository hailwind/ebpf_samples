#include "vmlinux.h"
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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct tls_xl1 {
    u8 len;
};

struct tls_xl2 {
    u16 len;
};

struct tls_extension {
    u16 type;
    u16 len;
    // extension_data 需要动态解析
};

struct tls_server_name {
    u16 server_name_list_len;
    u8 server_name_type;
    u16 server_name_len;
    char domain[256];
}__attribute__((__packed__));

char domain[256];

struct bufft {
    char buff[512];
};

//len: 1+2+2=5
struct tls_hdr {
    u8 content_type;
    u16 tls_ver;
    u16 pkt_len;
}__attribute__((__packed__));

//len 1+3+2+32 = 38
struct tls_handshake {
    u8 handshake_type;
    u8 handshake_len[3];
    u16 tls_ver2;
    u8 random[32];
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

struct bufft payload;

SEC("prog")
int  bpf_prog1(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

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

    u16 hdr_len = sizeof(*eth) + sizeof(*ip) + tcp->doff*4;
    u16 offset = hdr_len;
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
    u16 tls_ver=bpf_ntohs(tlshdr->tls_ver);
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
        u8 xl1_len=xl1->len;
        if ( xl1_len> 0)
            offset+=xl1_len;
        // printt("loop %d offset: %u xl1_len: %u", i, offset, xl1_len);
        if (offset > TLS_CLIENT_HELLO_MAX_LEN)
            return XDP_PASS;

        struct tls_xl2 *xl2 = data + offset;
        if ((void *)xl2 + sizeof(*xl2) > data_end)
            return XDP_PASS;
        offset+=sizeof(*xl2);
        u16 xl2_len=bpf_ntohs(xl2->len);
        if ( i==0 && xl2_len> 0)
            offset+=xl2_len;
        // printt("loop %d offset: %u xl2_len: %u", i, offset, xl2_len);
        if (offset > TLS_CLIENT_HELLO_MAX_LEN)
            return XDP_PASS;
    }

    if (data+hdr_len+512 > data_end )
        return XDP_PASS;
    // printt("ttt %02x%02x%02x", payload.buff[142],payload.buff[143],payload.buff[144]);
    memcpy(&payload, data + hdr_len, 512);
    offset=offset-hdr_len;
    printt("offset: %u", offset);
    // if ( offset<512 )
    //     printt("ttt %02x", payload.buff[offset]);
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if ( offset+sizeof(struct tls_extension) < 512 ) {
            struct tls_extension *ext = &payload.buff[offset];
            printt("type %02x len: %u", ext->type, bpf_ntohs(ext->len));
            if (ext->type == TLS_EXT_SERVER_NAME) {
                offset+=sizeof(struct tls_extension);
                if ( offset+sizeof(struct tls_server_name) < 512 ) {
                    struct tls_server_name *servername = &payload.buff[offset];
                    u16 server_name_len =bpf_ntohs(servername->server_name_len);
                    printt("list_len: %u len: %u", servername->server_name_type, server_name_len);
                    // offset+=sizeof(struct tls_server_name);
                    // if ( offset+server_name_len < 512 ) {
                    //     bpf_probe_read(&domain, server_name_len, &payload.buff[offset]);
                    //     printt("server name: %s", domain);
                    // }
                    break;
                }else{
                    return XDP_PASS;
                }
            }else{
                continue;
            }
        }else{
            return XDP_PASS;
        }
    }
/*
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        // printt("ttt %02x", payload.buff[offset]);
        // if (offset<512){
        //     printt("ttt %02x", payload.buff[offset]);
        //     offset++;
        // }
        
        if (offset >= 512 -sizeof(struct tls_extension) - sizeof(struct tls_server_name))
            return XDP_PASS;
 
        struct tls_extension *ext = &payload.buff[offset];
        offset+=sizeof(struct tls_extension);
        printt("ext %x", ext->type);
        printt("ext %u", bpf_ntohs(ext->len));

        if (ext->type == TLS_EXT_SERVER_NAME) {
            if (offset < 512 - sizeof(struct tls_server_name)) {
                // printt("payload.buff[offset]: %x", payload.buff[offset]);
                printt("offset %u", offset);

                struct tls_server_name *tlssn = &payload.buff[offset];
                printt("tlssn->server_name_list_len: %u", bpf_ntohs(tlssn->server_name_list_len));
                printt("tlssn->server_name_type: %u", tlssn->server_name_type);
                printt("tlssn->server_name_len: %u", bpf_ntohs(tlssn->server_name_len));

            }
            break;
        }
 
        
        u16 ext_len=bpf_ntohs(ext->len);
        offset+=ext_len;
     
        // hdr_len += sizeof(struct tls_extension);
        // if (hdr_len > TLS_CLIENT_HELLO_MAX_LEN)
        //     return XDP_PASS;
        // u16 ext_len = bpf_ntohs(ext->ext_len);
        // if (ext_len>0)
        //     hdr_len +=ext_len;
        // if (hdr_len > TLS_CLIENT_HELLO_MAX_LEN)
        //     return XDP_PASS;
    }
*/
    /*  BEGIN
    hdr_len += sizeof(*tlshs);
    // printt("hdr_len.3: %u", hdr_len);//97
    struct tls_xl1 *session_id = data + hdr_len;
    if ((void *)session_id + sizeof(*session_id) > data_end)
        return XDP_PASS;
    // printt("session_id.len %u", session_id->len);

    hdr_len+=sizeof(*session_id);
    u8 sesson_id_len = session_id->len;
    if ( sesson_id_len> 0)
        hdr_len+=sesson_id_len;
    // printt("hdr_len.4: %u", hdr_len);//130
    struct tls_xl2 *cipher_suites = data+hdr_len;
    if ((void *)cipher_suites + sizeof(*cipher_suites) > data_end)
        return XDP_PASS;

    hdr_len+=sizeof(*cipher_suites);
    u16 cipher_suites_len = bpf_ntohs(cipher_suites->len);
    if (cipher_suites_len > 0)
        hdr_len+=cipher_suites_len;
    printt("hdr_len.5: %u", hdr_len);//194
    if (hdr_len > TLS_CLIENT_HELLO_MAX_LEN)
        return XDP_PASS;
    struct tls_xl1 *compression_method = data+hdr_len;
    if ((void *)compression_method + sizeof(*compression_method) > data_end)
        return XDP_PASS;
    // printt("compression_method: %x data_end: %x", cipher_suites_len, data_end);

    hdr_len+=sizeof(*compression_method);
    if ( compression_method->len > 0 )
        hdr_len+=compression_method->len;
    if (hdr_len > TLS_CLIENT_HELLO_MAX_LEN)
        return XDP_PASS;
    printt("hdr_len.6: %u", hdr_len);//195
    struct tls_xl2 *extensions = data+hdr_len;
    if ((void *)extensions + sizeof(*extensions) > data_end)
        return XDP_PASS;
    printt("extensions.len: %u", bpf_ntohs(extensions->len));
    END
    */

    /*
    void *skb = (void *)tlshdr+sizeof(*tlshdr);
    u32 offset = 0;
    // session_id_len session_id
    u8 *session_id_len;
    if (offset>0) {
        session_id_len = skb;
        if ((void *)session_id_len+1>data_end)
            return XDP_PASS;
        offset += 1 + *session_id_len;
    } 
    printt("offset: %u", offset);

    // cipher_suites_len cipher_suites
    u16 *cipher_suites_len;
    if (offset>0) {
        cipher_suites_len = skb + offset;
        if ((void *)cipher_suites_len+2>data_end)
            return XDP_PASS;
        *cipher_suites_len = bpf_ntohs(*cipher_suites_len);
        offset += 2 + *cipher_suites_len; 
    }

    // compression_methods_len compression_methods
    u8 *compression_methods_len;
    if (offset>0) {
        compression_methods_len = skb + offset;
        if ((void *)compression_methods_len+1>data_end)
            return XDP_PASS;
        offset += 1 + *compression_methods_len;
    }

    // printt("extensions_len offset %u", offset);
    u16 *extensions_len;
    if (offset>0) {
        extensions_len = skb +offset;
        if ((void *)extensions_len+2>data_end)
            return XDP_PASS;
        extensions_len=bpf_ntohs(*extensions_len);
        printt("extensions_len:%u", *extensions_len);
    }
    */

    /*
    void *tlsdp = (void *)tlshdr+sizeof(*tlshdr);

    if (tlsdp + sizeof(struct tls_xl1) > data_end)
        return XDP_PASS;
    struct tls_xl1 *session = tlsdp;
    if (session->len >0)
        tlsdp = tlsdp + sizeof(*session) + session->len;

    if (tlsdp + sizeof(struct tls_xl2) > data_end)
        return XDP_PASS;
    struct tls_xl2 *cipher_suites = tlsdp;
    if (bpf_ntohs(cipher_suites->len) >0) 
        tlsdp = tlsdp + sizeof(*cipher_suites) + bpf_ntohs(cipher_suites->len);

    if (tlsdp + sizeof(struct tls_xl1) > data_end)
        return XDP_PASS;
    struct tls_xl1 *compression_method = tlsdp;
    if (compression_method->len >0)
        tlsdp = tlsdp + sizeof(*compression_method) + compression_method->len;

    if (tlsdp + sizeof(struct tls_xl2) > data_end)
        return XDP_PASS;
    struct tls_xl2 *extensions = tlsdp;
    if (bpf_ntohs(extensions->len) >0)
        tlsdp = tlsdp + sizeof(*extensions) + bpf_ntohs(extensions->len);
    */

    /*
    void *tlsdp = (void *)tlshdr+sizeof(*tlshdr);

    struct tls_xl1 *session = tlsdp;
    if (tlsdp + sizeof(*session) > data_end)
        return XDP_PASS;
    if (session->len >0)
        tlsdp = tlsdp + sizeof(*session) + session->len;

    struct tls_xl2 *cipher_suites = tlsdp;
    if (tlsdp + sizeof(*cipher_suites) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(cipher_suites->len) >0) 
        tlsdp = tlsdp + sizeof(*cipher_suites) + bpf_ntohs(cipher_suites->len);

    struct tls_xl1 *compression_method = tlsdp;
    if (tlsdp + sizeof(*compression_method) > data_end)
        return XDP_PASS;
    if (compression_method->len >0)
        tlsdp = tlsdp + sizeof(*compression_method) + compression_method->len;

    struct tls_xl2 *extensions = tlsdp;
    if ((void *)extensions + sizeof(*extensions) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(extensions->len) >0)
        tlsdp = tlsdp + sizeof(*extensions) + bpf_ntohs(extensions->len);
    */

    /*
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        struct tls_extension *ext = (void *)tlsdp;
        if ((void *)ext + sizeof(*ext) > data_end)
            return XDP_PASS;
        tlsdp = tlsdp + sizeof(*ext) + ext->ext_len;
        if (ext->ext_type == TLS_EXT_SERVER_NAME) {
            struct tls_hello_domain sni = {0};
            if ( (void *)&ext + sizeof(*ext) > data_end)
                return XDP_PASS;
            bpf_skb_load_bytes(ext, sizeof(*ext), &sni.domain_name, 256);
            printt("domain: %s", sni.domain_name);
            break;
        }
    }
    */
    printt("< < < < < < < < < < < < < < < < < < < < < < \n");
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";