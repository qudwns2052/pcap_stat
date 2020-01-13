#include <pcap.h>
#include <iostream>
#include "packet_structure.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <map>

using namespace std;

#define ETHER_HEADER_SIZE   14
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

using namespace std;

void print_ip(uint32_t ip)
{
    uint8_t temp[4];
    temp[0] = (ip >> 24);
    temp[1] = (ip >> 16) & 0xff;
    temp[2] = (ip >> 8) & 0xff;
    temp[3] = ip & 0xff;
    printf("%u.%u.%u.%u\t", temp[0], temp[1], temp[2], temp[3]);
}

void print_mac(Mac mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\t", mac.mac_f >> 24, (mac.mac_f >> 16) & 0xff, (mac.mac_f >> 8) & 0xff,
                                                mac.mac_f & 0xff, (mac.mac_b >> 8) & 0xff, mac.mac_b & 0xff);
}


void Endpoints_map_ip(map<uint32_t, Info> & end_ip, Ip* ip_header)
{
    if(end_ip.find(ntohl(ip_header->s_ip)) == end_ip.end()) // not found
    {
        end_ip[ntohl(ip_header->s_ip)].s_packet_cnt = 1;
        end_ip[ntohl(ip_header->s_ip)].d_packet_cnt = 0;
        end_ip[ntohl(ip_header->s_ip)].s_byte = ntohs(ip_header->Total_LEN) + 14;
        end_ip[ntohl(ip_header->s_ip)].d_byte = 0;

    }
    else // found
    {
        end_ip[ntohl(ip_header->s_ip)].s_packet_cnt++;
        end_ip[ntohl(ip_header->s_ip)].s_byte += ntohs(ip_header->Total_LEN) + 14;
    }

    if(end_ip.find(ntohl(ip_header->d_ip)) == end_ip.end()) // not found
    {
        end_ip[ntohl(ip_header->d_ip)].s_packet_cnt = 0;
        end_ip[ntohl(ip_header->d_ip)].d_packet_cnt = 1;
        end_ip[ntohl(ip_header->d_ip)].s_byte = 0;
        end_ip[ntohl(ip_header->d_ip)].d_byte = ntohs(ip_header->Total_LEN) + 14;

    }
    else // found
    {
        end_ip[ntohl(ip_header->d_ip)].d_packet_cnt++;
        end_ip[ntohl(ip_header->d_ip)].d_byte += ntohs(ip_header->Total_LEN) + 14;
    }
}

void Endpoints_print_ip(map<uint32_t, Info> & end_ip)
{

    printf("Endpoints\nAddress\t\tPackets\tBytes\tTx Packets\tTx Bytes\tRx Packets\tRx Bytes\n");

    for(map<uint32_t, Info>::iterator it = end_ip.begin(); it!= end_ip.end(); it++)
    {

        print_ip(it->first);
        printf("%d\t", it->second.s_packet_cnt + it->second.d_packet_cnt);

        if(it->second.s_byte+it->second.d_byte > 1024)
            printf("%dk\t", (it->second.s_byte+it->second.d_byte)/1024);
        else {
            printf("%d\t", it->second.s_byte+it->second.d_byte);
        }
        printf("%d\t\t", it->second.s_packet_cnt);

        if(it->second.s_byte > 1024)
            printf("%dk\t\t", it->second.s_byte/1024);
        else {
            printf("%d\t\t", it->second.s_byte);
        }
        printf("%d\t\t", it->second.d_packet_cnt);

        if(it->second.d_byte > 1024)
            printf("%dk\t\t\n", it->second.d_byte/1024);
        else {
            printf("%d\t\t\n", it->second.d_byte);
        }
    }

}

void Conversations_map_ip(map<uint64_t, Info> & conv_ip, Ip * ip_header)
{
    uint64_t key, state;

    if(ntohl(ip_header->s_ip) < ntohl(ip_header->d_ip))
    {
        key = ntohl(ip_header->s_ip);
        key = (key << 32) + ntohl(ip_header->d_ip);
        state = 0;
    }
    else {
        key = ntohl(ip_header->d_ip);
        key = (key << 32) + ntohl(ip_header->s_ip);
        state = 1;
    }

    if(conv_ip.find(key) == conv_ip.end())
    {
        conv_ip[key].s_packet_cnt = 0;
        conv_ip[key].d_packet_cnt = 0;
        conv_ip[key].s_byte = 0;
        conv_ip[key].d_byte = 0;
    }

    switch(state)
    {
    case 0:
        conv_ip[key].s_packet_cnt++;
        conv_ip[key].s_byte += ntohs(ip_header->Total_LEN) + 14;
        break;
    case 1:
        conv_ip[key].d_packet_cnt++;
        conv_ip[key].d_byte += ntohs(ip_header->Total_LEN) + 14;
    }


}

void Conversations_print_ip(map<uint64_t, Info> conv_ip)
{

    printf("\nConversations\nAddress A\tAddress B\tPackets\tBytes\tPackets A->B\tBytes A->B\tPackets A->B\tBytes A->B\n");

    for(map<uint64_t, Info>::iterator it = conv_ip.begin(); it != conv_ip.end(); it++)
    {
        print_ip(it->first>>32);
        print_ip(it->first&0xffffffff);
        printf("%d\t", it->second.s_packet_cnt + it->second.d_packet_cnt);

        if(it->second.s_byte+it->second.d_byte > 1024)
            printf("%dk\t", (it->second.s_byte+it->second.d_byte)/1024);
        else {
            printf("%d\t", it->second.s_byte+it->second.d_byte);
        }
        printf("%d\t\t", it->second.s_packet_cnt);

        if(it->second.s_byte > 1024)
            printf("%dk\t\t", it->second.s_byte/1024);
        else {
            printf("%d\t\t", it->second.s_byte);
        }
        printf("%d\t\t", it->second.d_packet_cnt);

        if(it->second.d_byte > 1024)
            printf("%dk\t\t\n", it->second.d_byte/1024);
        else {
            printf("%d\t\t\n", it->second.d_byte);
        }
    }


}

void Endpoints_map_mac(map<Mac, Info> & end_mac, Ethernet * ethernet_header, Ip * ip_header)
{
    if(end_mac.find(ethernet_header->s_mac) == end_mac.end()) // not found
    {
        end_mac[ethernet_header->s_mac].s_packet_cnt = 1;
        end_mac[ethernet_header->s_mac].d_packet_cnt = 0;
        end_mac[ethernet_header->s_mac].s_byte = ntohs(ip_header->Total_LEN) + 14;
        end_mac[ethernet_header->s_mac].d_byte = 0;

    }
    else // found
    {
        end_mac[ethernet_header->s_mac].s_packet_cnt++;
        end_mac[ethernet_header->s_mac].s_byte += ntohs(ip_header->Total_LEN) + 14;
    }

    if(end_mac.find(ethernet_header->d_mac) == end_mac.end()) // not found
    {
        end_mac[ethernet_header->d_mac].s_packet_cnt = 0;
        end_mac[ethernet_header->d_mac].d_packet_cnt = 1;
        end_mac[ethernet_header->d_mac].s_byte = 0;
        end_mac[ethernet_header->d_mac].d_byte = ntohs(ip_header->Total_LEN) + 14;

    }
    else // found
    {
        end_mac[ethernet_header->d_mac].d_packet_cnt++;
        end_mac[ethernet_header->d_mac].d_byte += ntohs(ip_header->Total_LEN) + 14;
    }
}

void Endpoints_print_mac(map<Mac, Info> end_mac)
{

    printf("Endpoints\nAddress\t\t\tPackets\tBytes\tTx Packets\tTx Bytes\tRx Packets\tRx Bytes\n");



    for(map<Mac, Info>::iterator it = end_mac.begin(); it!= end_mac.end(); it++)
    {
        print_mac(it->first);
        printf("%d\t", it->second.s_packet_cnt + it->second.d_packet_cnt);

        if(it->second.s_byte+it->second.d_byte > 1024)
            printf("%dk\t", (it->second.s_byte+it->second.d_byte)/1024);
        else {
            printf("%d\t", it->second.s_byte+it->second.d_byte);
        }
        printf("%d\t\t", it->second.s_packet_cnt);

        if(it->second.s_byte > 1024)
            printf("%dk\t\t", it->second.s_byte/1024);
        else {
            printf("%d\t\t", it->second.s_byte);
        }
        printf("%d\t\t", it->second.d_packet_cnt);

        if(it->second.d_byte > 1024)
            printf("%dk\t\t\n", it->second.d_byte/1024);
        else {
            printf("%d\t\t\n", it->second.d_byte);
        }
    }
}

void Conversations_map_mac(map<Mac_conv, Info> & conv_mac, Ethernet * ethernet_header, Ip *ip_header)
{
    Mac s_mac = ethernet_header->s_mac;
    Mac d_mac = ethernet_header->d_mac;

    Mac_conv key(s_mac, d_mac);
    uint64_t state;


    if(s_mac < d_mac)
    {
        state = 0;
    }
    else {
        key = Mac_conv(d_mac, s_mac);
        state = 1;
    }

    if(conv_mac.find(key) == conv_mac.end())
    {
        conv_mac[key].s_packet_cnt = 0;
        conv_mac[key].d_packet_cnt = 0;
        conv_mac[key].s_byte = 0;
        conv_mac[key].d_byte = 0;
    }

    switch(state)
    {
    case 0:
        conv_mac[key].s_packet_cnt++;
        conv_mac[key].s_byte += ntohs(ip_header->Total_LEN) + 14;
        break;
    case 1:
        conv_mac[key].d_packet_cnt++;
        conv_mac[key].d_byte += ntohs(ip_header->Total_LEN) + 14;
    }
}


void Conversations_print_mac(map<Mac_conv, Info> conv_mac)
{

    printf("\nConversations\nAddress A\t\tAddress B\t\tPackets\tBytes\tPackets A->B\tBytes A->B\tPackets A->B\tBytes A->B\n");

    for(map<Mac_conv, Info>::iterator it = conv_mac.begin(); it != conv_mac.end(); it++)
    {

        print_mac(it->first.mac1);
        print_mac(it->first.mac2);


        printf("%d\t", it->second.s_packet_cnt + it->second.d_packet_cnt);

        if(it->second.s_byte+it->second.d_byte > 1024)
            printf("%dk\t", (it->second.s_byte+it->second.d_byte)/1024);
        else {
            printf("%d\t", it->second.s_byte+it->second.d_byte);
        }
        printf("%d\t\t", it->second.s_packet_cnt);

        if(it->second.s_byte > 1024)
            printf("%dk\t\t", it->second.s_byte/1024);
        else {
            printf("%d\t\t", it->second.s_byte);
        }
        printf("%d\t\t", it->second.d_packet_cnt);

        if(it->second.d_byte > 1024)
            printf("%dk\t\t\n", it->second.d_byte/1024);
        else {
            printf("%d\t\t\n", it->second.d_byte);
        }
    }


}

int main(int argc, char* argv[])
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1],errbuf);

    if (handle == NULL) {
        printf("fail open_offline...%s\n",errbuf);
        return -1;
    }

    map<uint32_t, Info> end_ip;
    map<uint64_t, Info> conv_ip;
    map<Mac, Info> end_mac;
    map<Mac_conv, Info> conv_mac;

    int ethernet_SIZE;
    int ip_SIZE;
    int tcp_SIZE;
    int payload_SIZE;

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        Ethernet * ethernet_header = (Ethernet *)packet;
        ethernet_SIZE = 14;

        if(ntohs(ethernet_header->type) != 0x0800)
            continue;

        Ip * ip_header = (Ip *)(packet + ethernet_SIZE);
        ip_SIZE = (ip_header->VHL & 0x0F) * 4;

        Tcp * tcp_header = (Tcp *)(packet + ethernet_SIZE + ip_SIZE);
        tcp_SIZE = ((tcp_header->HLR & 0xF0) >> 4) * 4;

        u_char * payload = (u_char *)(packet + ethernet_SIZE + ip_SIZE + tcp_SIZE);
        payload_SIZE = ntohs(ip_header->Total_LEN) - (ip_SIZE + tcp_SIZE);

        Endpoints_map_ip(end_ip, ip_header);
        Conversations_map_ip(conv_ip, ip_header);

        Endpoints_map_mac(end_mac, ethernet_header, ip_header);
        Conversations_map_mac(conv_mac, ethernet_header, ip_header);
    }

    printf("Ip\n----------------------------------------------------------------------------\n");
    Endpoints_print_ip(end_ip);
    Conversations_print_ip(conv_ip);
    printf("----------------------------------------------------------------------------\n");

    printf("Mac\n---------------------------------------------------------------------------\n");
    Endpoints_print_mac(end_mac);
    Conversations_print_mac(conv_mac);
    printf("----------------------------------------------------------------------------\n");


    pcap_close(handle);
    return 0;
}
