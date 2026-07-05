#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "myheader.h"

#define MAX_HTTP_PRINT 2048

static int packet_no = 0;

static void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int starts_with(const uint8_t *data, int len, const char *prefix) {
    int prefix_len = (int)strlen(prefix);

    if (len < prefix_len) {
        return 0;
    }

    return memcmp(data, prefix, (size_t)prefix_len) == 0;
}

static int is_http_payload(const uint8_t *payload,
                           int payload_len,
                           uint16_t src_port,
                           uint16_t dst_port) {
    if (payload_len <= 0) {
        return 0;
    }

    if (src_port == 80 || dst_port == 80 ||
        src_port == 8080 || dst_port == 8080 ||
        src_port == 8000 || dst_port == 8000) {
        return 1;
    }

    return starts_with(payload, payload_len, "GET ") ||
           starts_with(payload, payload_len, "POST ") ||
           starts_with(payload, payload_len, "HEAD ") ||
           starts_with(payload, payload_len, "PUT ") ||
           starts_with(payload, payload_len, "DELETE ") ||
           starts_with(payload, payload_len, "OPTIONS ") ||
           starts_with(payload, payload_len, "PATCH ") ||
           starts_with(payload, payload_len, "HTTP/");
}

static void print_http_message(const uint8_t *payload, int payload_len) {
    int print_len = payload_len;

    if (print_len > MAX_HTTP_PRINT) {
        print_len = MAX_HTTP_PRINT;
    }

    printf("HTTP Message (%d bytes)\n", payload_len);
    printf("--------------------------------------------------\n");

    for (int i = 0; i < print_len; i++) {
        unsigned char c = payload[i];

        if (c == '\r') {
            continue;
        } else if (c == '\n') {
            putchar('\n');
        } else if (isprint(c) || c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    if (payload_len > MAX_HTTP_PRINT) {
        printf("\n... truncated ...");
    }

    printf("\n--------------------------------------------------\n");
}

static void got_packet(u_char *args,
                       const struct pcap_pkthdr *header,
                       const u_char *packet) {
    (void)args;

    if (header->caplen < SIZE_ETHERNET) {
        return;
    }

    const struct ethheader *eth = (const struct ethheader *)packet;

    if (ntohs(eth->ether_type) != ETHER_TYPE_IP) {
        return;
    }

    if (header->caplen < SIZE_ETHERNET + 20) {
        return;
    }

    const struct ipheader *ip =
        (const struct ipheader *)(packet + SIZE_ETHERNET);

    int ip_header_len = IP_HL(ip) * 4;

    if (IP_V(ip) != 4 || ip_header_len < 20) {
        return;
    }

    if (header->caplen < (bpf_u_int32)(SIZE_ETHERNET + ip_header_len)) {
        return;
    }

    if (ip->ip_protocol != IPPROTO_TCP) {
        return;
    }

    uint16_t ip_fragment = ntohs(ip->ip_off);

    if ((ip_fragment & (IP_MF | IP_OFFMASK)) != 0) {
        return;
    }

    uint16_t ip_total_len = ntohs(ip->ip_len);

    if (ip_total_len < (uint16_t)ip_header_len) {
        return;
    }

    if (header->caplen < (bpf_u_int32)(SIZE_ETHERNET + ip_header_len + 20)) {
        return;
    }

    const struct tcpheader *tcp =
        (const struct tcpheader *)(packet + SIZE_ETHERNET + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    if (tcp_header_len < 20) {
        return;
    }

    if (ip_total_len < (uint16_t)(ip_header_len + tcp_header_len)) {
        return;
    }

    if (header->caplen <
        (bpf_u_int32)(SIZE_ETHERNET + ip_header_len + tcp_header_len)) {
        return;
    }

    const uint8_t *payload =
        packet + SIZE_ETHERNET + ip_header_len + tcp_header_len;

    int payload_len =
        (int)ip_total_len - ip_header_len - tcp_header_len;

    int captured_payload_len =
        (int)header->caplen - SIZE_ETHERNET - ip_header_len - tcp_header_len;

    if (captured_payload_len < 0) {
        return;
    }

    if (captured_payload_len > payload_len) {
        captured_payload_len = payload_len;
    }

    uint16_t src_port = ntohs(tcp->tcp_sport);
    uint16_t dst_port = ntohs(tcp->tcp_dport);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->ip_src), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, sizeof(dst_ip));

    printf("\n========== Packet #%d ==========\n", ++packet_no);

    printf("Ethernet Header\n");
    printf("  src mac : ");
    print_mac(eth->ether_shost);
    printf("\n  dst mac : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("IP Header\n");
    printf("  src ip  : %s\n", src_ip);
    printf("  dst ip  : %s\n", dst_ip);
    printf("  ip_header_len : %d bytes\n", ip_header_len);

    printf("TCP Header\n");
    printf("  src port : %u\n", src_port);
    printf("  dst port : %u\n", dst_port);
    printf("  tcp_header_len : %d bytes\n", tcp_header_len);

    if (payload_len <= 0) {
        printf("HTTP Message : no application data\n");
        return;
    }

    if (is_http_payload(payload, captured_payload_len, src_port, dst_port)) {
        print_http_message(payload, captured_payload_len);
    } else {
        printf("HTTP Message : not plain HTTP or encrypted TCP data (%d bytes)\n",
               payload_len);
    }
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: sudo %s <interface>\n", program);
    fprintf(stderr, "Example: sudo %s enp0s3\n", program);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
    char filter_exp[] = "tcp";

    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
        mask = PCAP_NETMASK_UNKNOWN;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "This program supports Ethernet only.\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("PCAP sniffer started. filter = %s\n", filter_exp);
    printf("Press Ctrl+C to stop.\n");

    if (pcap_loop(handle, -1, got_packet, NULL) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_freecode(&fp);
    pcap_close(handle);

    return EXIT_SUCCESS;
}