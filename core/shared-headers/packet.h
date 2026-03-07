#ifndef PACKET_H
#define PACKET_H

#include <pcap/pcap.h>
#include <string>
#include <vector>

using namespace std;
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
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
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP Header */
struct sniff_udp {
    uint16_t uh_sport;   /* source port */
    uint16_t uh_dport;   /* destination port */
    uint16_t uh_ulen;    /* udp length */
    uint16_t uh_sum;     /* udp checksum */
};

/* ICMP Header */
struct sniff_icmp {
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_checksum;
};

/* ARP Header */
struct sniff_arp {
    uint16_t arp_hrd;    /* hardware type */
    uint16_t arp_pro;    /* protocol type */
    uint8_t  arp_hln;    /* hardware address length */
    uint8_t  arp_pln;    /* protocol address length */
    uint16_t arp_op;     /* opcode */

    uint8_t  arp_sha[6]; /* sender hardware address */
    uint8_t  arp_spa[4]; /* sender protocol address */
    uint8_t  arp_tha[6]; /* target hardware address */
    uint8_t  arp_tpa[4]; /* target protocol address */
};

/* Normalized Packet */
struct NormalizedPacket {

    /* ===== Capture Metadata ===== */
    uint64_t capture_sequence_number;
    uint32_t capture_timestamp_sec;
    uint32_t capture_timestamp_usec;

    /* ===== Layer 1 ===== */
    string src_mac;
    string dst_mac;
    uint16_t ether_type;

    /* ===== Layer 2 ===== */
    uint8_t  ip_version;
    string src_ip;
    string dst_ip;
    uint8_t  ttl;
    uint16_t header_checksum;
    uint16_t identification;
    uint16_t flags;
    uint16_t fragment_offset;
    uint16_t total_length;
    uint8_t  protocol = 0;   // IP protocol number

    /* ===== Layer 3 ===== */
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    /* TCP */
    uint32_t sequence_number = 0;
    uint32_t acknowledgment_number = 0;
    uint16_t window_size = 0;
    uint8_t  tcp_flags = 0;

    /* UDP */
    uint16_t udp_length = 0;

    /* ICMP */
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;

    /* ARP */
    uint16_t arp_opcode = 0;
    string arp_src_ip;
    string arp_dst_ip; 

    /* ===== Application Layer ===== */
//     string transport_protocol_name;   Useless
    string app_protocol; // "HTTP", "DNS", etc.

    /* ===== Payload ===== */
    vector<uint8_t> payload;
};



#endif