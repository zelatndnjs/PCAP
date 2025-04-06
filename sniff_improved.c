#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void usage(char *prog) {
    printf("Usage: %s [interface | pcap file]\n", prog);
    exit(1);
}

void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("%s", inet_ntoa(ip_addr));
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)(user);
    struct ethernet_header *eth = (struct ethernet_header *)packet;
    uint16_t ether_type = ntohs(eth->ether_type);
    if (ether_type != 0x0800)
        return;
    struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
    if (ip->ip_p != 6)
        return;
    int ip_header_len = IP_HL(ip) * 4;
    struct tcp_header *tcp = (struct tcp_header *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;
    int header_total_len = sizeof(struct ethernet_header) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - header_total_len;
    printf("=====================================\n");
    printf("[Ethernet Header]\n");
    printf("  |- Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("  |- Dst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");
    printf("[IP Header]\n");
    printf("  |- Src IP: ");
    print_ip(ip->ip_src);
    printf("\n");
    printf("  |- Dst IP: ");
    print_ip(ip->ip_dst);
    printf("\n");
    printf("  |- IP Header Length: %d bytes\n", ip_header_len);
    printf("[TCP Header]\n");
    printf("  |- Src Port: %d\n", ntohs(tcp->th_sport));
    printf("  |- Dst Port: %d\n", ntohs(tcp->th_dport));
    if (payload_len > 0) {
        printf("[Payload]\n");
        int len = payload_len > 16 ? 16 : payload_len;
        for (int i = 0; i < len; i++) {
            if (isprint(packet[header_total_len + i]))
                printf("%c", packet[header_total_len + i]);
            else
                printf(".");
        }
        printf("\n");
    }
    printf("=====================================\n\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2)
        usage(argv[0]);
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    FILE *fp = fopen(dev, "rb");
    if (fp != NULL) {
        fclose(fp);
        handle = pcap_open_offline(dev, errbuf);
        if (!handle) {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", dev, errbuf);
            return 2;
        }
        printf("[*] Reading from pcap file: %s\n", dev);
    } else {
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return 2;
        }
        printf("[*] Listening on device: %s\n", dev);
    }
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0)
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 0;
}
