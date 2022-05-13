//
// Created by Eytan on 10/20/2021.
//

#ifndef SNIFFER_NETWORKHELPER_HPP
#define SNIFFER_NETWORKHELPER_HPP

#include <cstddef> // std::size_t
#include <arpa/inet.h>

#define ETHER_TYPE_IPV4      0x0800
#define ETHER_TYPE_ARP       0x0806
#define ETHER_TYPE_IEEE8021Q 0x8100
#define ETHER_TYPE_IPV6      0x86DD

struct EthernetHeaderStruct {
    unsigned char  destinationMac[6];
    unsigned char  sourceMac[6];
    unsigned short type;
};

struct IpHeaderStruct {
    unsigned char  ip_hl: 4;       // Header length
    unsigned char  ip_v: 4;        // IP protocol version
    unsigned char  ip_tos;         // Type of service
    unsigned short ip_len;         // Total length
    unsigned short ip_id;          // Identification
    unsigned short ip_off;         // Fragment offset field
    unsigned char  ip_ttl;         // Time to live
    unsigned char  ip_p;           // Protocol
    unsigned short ip_sum;         // Header checksum
    struct in_addr ip_src;         // Source address
    struct in_addr ip_dest;        // Destination address

    bool isFragmented() const {
        return (!isLastFragment() || offset() > 0);
    }

    bool isLastFragment() const {
        return fragmentFlags() % 2 == 0;
    }

    std::size_t payloadLen() const {
        return packetLen() - headerLen();
    }

    std::size_t offset() const {
        return ((ntohs(ip_off)) & 0x1FFF) << 3; // last 13 bits * 8
    }

    unsigned int fragmentFlags() const {
        return (ntohs(ip_off)) >> 13; // first 3 bits
    }

    std::size_t headerLen() const {
        return ip_hl * 4;
    }

    std::size_t packetLen() const {
        return ntohs(ip_len);
    }
};

struct TcpHeaderStruct {
    unsigned short source;        // source port
    unsigned short dest;          // destination port
    unsigned int   seq;           // sequence number
    unsigned int   ack;           // acknowledgement id
    unsigned char  x2: 4;         // unused
    unsigned char  off: 4;        // data offset
    unsigned char  flags;         // flags field
    unsigned short win;           // window size
    unsigned short sum;           // tcp checksum
    unsigned short urp;           // urgent pointer
};

struct UdpHeaderStruct {
    unsigned short source;        // Source port
    unsigned short dest;          // Destination port
    unsigned short len;           // UDP length
    unsigned short check;         // UDP Checksum
};

inline bool is_ipv4(IpHeaderStruct *ipHeader) {
    // sanity check, is it an IP packet v4
    if (ipHeader->ip_v != 4) {

        // If not, the IP packet might have been captured from multiple interfaces using the tcpdump -i switch
        ipHeader = (IpHeaderStruct *) ((u_char *) ipHeader + 2);
        if (ipHeader->ip_v != 4) {

            // If not, it might be wrapped into a 802.1Q VLAN or MPLS header (add 4 bytes, ie 2 bytes on top of previous 2)
            ipHeader = (IpHeaderStruct *) ((u_char *) ipHeader + 2);
            if (ipHeader->ip_v != 4) {

                // If not, it might be tcpdump -i as well as VLAN, add another 2 bytes
                ipHeader = (IpHeaderStruct *) ((u_char *) ipHeader + 2);
                if (ipHeader->ip_v != 4) {

                    // If not, it might be on 802.11
                    ipHeader = (IpHeaderStruct *) ((u_char *) ipHeader + 12);
                    if (ipHeader->ip_v != 4) {

                        // Still not IPv4, drop it
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

#endif //SNIFFER_NETWORKHELPER_HPP