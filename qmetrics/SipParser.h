//
// Created by Eytan on 10/20/2021.
//

#ifndef SNIFFER_SIPPARSER_H
#define SNIFFER_SIPPARSER_H

#include "NetworkHelper.hpp"
#include <pcap.h>

class SipParser {
    static bool TrySip200Ok(EthernetHeaderStruct *ethernetHeader, IpHeaderStruct *ipHeader, UdpHeaderStruct *udpHeader, u_char *udpPayload, u_char *packetEnd);
    static bool TrySipBye(EthernetHeaderStruct* ethernetHeader, IpHeaderStruct* ipHeader, UdpHeaderStruct* udpHeader, u_char* udpPayload, u_char* packetEnd);
    static bool TrySipInvite(EthernetHeaderStruct* ethernetHeader, IpHeaderStruct* ipHeader, UdpHeaderStruct* udpHeader, u_char* udpPayload, u_char* packetEnd);

public:
    static void handle(EthernetHeaderStruct *ethernetHeader, IpHeaderStruct *ipHeader, int ipHeaderLength, u_char *ipPacketEnd);
};


#endif //SNIFFER_SIPPARSER_H