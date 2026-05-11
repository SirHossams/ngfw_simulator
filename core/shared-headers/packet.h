#ifndef PACKET_H
#define PACKET_H

#include <pcap/pcap.h>
#include <string>
#include <vector>

using namespace std;

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};

struct sniff_ip {
        u_char  ip_vhl;
        u_char  ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;
        u_char  ip_p;
        u_short ip_sum;
        struct  in_addr ip_src,ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;
        u_short th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char  th_offx2;
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

struct sniff_udp {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};

struct sniff_icmp {
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_checksum;
};

struct sniff_arp {
    uint16_t arp_hrd;
    uint16_t arp_pro;
    uint8_t  arp_hln;
    uint8_t  arp_pln;
    uint16_t arp_op;

    uint8_t  arp_sha[6];
    uint8_t  arp_spa[4];
    uint8_t  arp_tha[6];
    uint8_t  arp_tpa[4];
};

#define MAX_PAYLOAD_SIZE 1500
#define MAX_CERT_SIZE 4096
#define MAC_ADDR_STR_LEN 18
#define IP_ADDR_STR_LEN 16
#define APP_PROTO_STR_LEN 16
#define INTERFACE_STR_LEN 16

struct NormalizedPacket {
    uint64_t capture_sequence_number;
    uint32_t capture_timestamp_sec;
    uint32_t capture_timestamp_usec;
    char interface[INTERFACE_STR_LEN];

    char src_mac[MAC_ADDR_STR_LEN];
    char dst_mac[MAC_ADDR_STR_LEN];
    uint16_t ether_type;

    uint8_t  ip_version;
    char src_ip[IP_ADDR_STR_LEN];
    char dst_ip[IP_ADDR_STR_LEN];
    uint8_t  ttl;
    uint16_t header_checksum;
    uint16_t identification;
    uint16_t flags;
    uint16_t fragment_offset;
    uint16_t total_length;
    uint8_t  protocol;

    uint16_t src_port;
    uint16_t dst_port;

    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint16_t window_size;
    uint8_t  tcp_flags;

    uint16_t udp_length;

    uint8_t icmp_type;
    uint8_t icmp_code;

    uint16_t arp_opcode;
    char arp_src_ip[IP_ADDR_STR_LEN];
    char arp_dst_ip[IP_ADDR_STR_LEN]; 

    char app_protocol[APP_PROTO_STR_LEN];
    
    uint32_t ssl_cert_size;
    uint8_t ssl_certificate[MAX_CERT_SIZE];

    uint32_t payload_size;
    uint8_t payload[MAX_PAYLOAD_SIZE];
};

#endif