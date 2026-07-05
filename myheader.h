#ifndef MYHEADER_H
#define MYHEADER_H

#include <stdint.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHER_TYPE_IP 0x0800

#define IP_MF      0x2000
#define IP_OFFMASK 0x1fff

struct ethheader {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];  // destination MAC
    uint8_t  ether_shost[ETHER_ADDR_LEN];  // source MAC
    uint16_t ether_type;                   // IP, ARP, etc.
};

struct ipheader {
    uint8_t  ip_vhl;        // version + header length
    uint8_t  ip_tos;
    uint16_t ip_len;        // total length
    uint16_t ip_id;
    uint16_t ip_off;        // flags + fragment offset
    uint8_t  ip_ttl;
    uint8_t  ip_protocol;   // TCP, UDP, ICMP, etc.
    uint16_t ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

struct tcpheader {
    uint16_t tcp_sport;     // source port
    uint16_t tcp_dport;     // destination port
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  tcp_offx2;     // data offset
    uint8_t  tcp_flags;
    uint16_t tcp_win;
    uint16_t tcp_sum;
    uint16_t tcp_urp;
};

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

#endif