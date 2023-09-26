#ifndef __XDP_HELPERS_H
#define __XDP_HELPERS_H

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
#endif