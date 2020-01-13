#ifndef PACKET_STRUCTURE_H
#define PACKET_STRUCTURE_H

#endif // PACKET_STRUCTURE_H
#include <stdint.h>
#include <stdio.h>
class Mac
{
public:
    uint32_t mac_f;
    uint16_t mac_b;

    Mac(uint8_t * _mac = NULL)
    {
        mac_f = _mac[0];
        mac_f = (mac_f << 8) + _mac[1];
        mac_f = (mac_f << 8) + _mac[2];
        mac_f = (mac_f << 8) + _mac[3];

        mac_b = _mac[4];
        mac_b = (mac_b << 8) + _mac[5];
    }

    bool operator <(const Mac & ref) const
    {
        if(this->mac_f == ref.mac_f)
            return this->mac_b < ref.mac_b;
        else
        {
            return this->mac_f < ref.mac_f;
        }
    }

};

class Mac_conv
{
public:
    Mac mac1;
    Mac mac2;

    Mac_conv(Mac _mac1, Mac _mac2) : mac1(_mac1), mac2(_mac2) {}

    bool operator <(const Mac_conv & ref) const
    {
        if(!(mac1 < ref.mac1) && !(ref.mac1 < mac1))
        {
            return mac2 < ref.mac2;
        }
        else
        {
            return mac1 < ref.mac1;
        }
    }

};

typedef struct info
{
    uint32_t s_packet_cnt;
    uint32_t d_packet_cnt;
    uint32_t s_byte;
    uint32_t d_byte;
}Info;


typedef struct ethernet
{
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t type;
}Ethernet;

typedef struct ip
{
    uint8_t VHL;
    uint8_t TOS;
    uint16_t Total_LEN;
    uint16_t Id;
    uint16_t Fragment;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t s_ip;
    uint32_t d_ip;
}Ip;

typedef struct tcp
{
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t HLR;
    uint8_t flags;
    uint16_t win_size;
    uint16_t check_sum;
    uint16_t urg_pointer;
}Tcp;
