//
// Created by Eytan on 9/19/2021.
//

#include "QMetrics.h"
#include "SipParser.h"
#include "NetworkHelper.hpp"
#include <cstring>
#include <fstream>
#include <cstddef> // std::size_t

inline char *clone(char *src, std::size_t len) {
    char *res = new char[len + 1];
    memcpy(res, src, len);
    res[len] = 0;
    return res;
}

std::ofstream snips("snips.log");

// for IP packet protocol numbers see: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
void QMetrics::handle_packet([[maybe_unused]] u_char *unused_param, const pcap_pkthdr *header, const u_char *pkt_data) {
    auto           ethernetHeader = (EthernetHeaderStruct *) pkt_data;
    IpHeaderStruct *ipHeader;

    if (ntohs(ethernetHeader->type) == ETHER_TYPE_IEEE8021Q) {
        ipHeader = (IpHeaderStruct *) ((char *) ethernetHeader + sizeof(EthernetHeaderStruct) + 4);
    }
    else if (ntohs(ethernetHeader->type) == ETHER_TYPE_IPV4 || ntohs(ethernetHeader->type) == ETHER_TYPE_ARP) {
        ipHeader = (IpHeaderStruct *) ((char *) ethernetHeader + sizeof(EthernetHeaderStruct));
    }
    else if (ntohs(ethernetHeader->type) == ETHER_TYPE_IPV6) {
        return;
    }
    else {//Maybe linux cooked pcap
        // If Linux cooked capture, we arbitrarily align the Ethernet header pointer so that its ETHER_TYPE is aligned with the ETHER_TYPE field of the Linux Cooked header.
        // This means that the source and destination MAC addresses of the obtained Ethernet header are totally wrong, but this is fine, as long as we are aware of this limitation
        ethernetHeader += 2;
        if (ntohs(ethernetHeader->type) == ETHER_TYPE_IEEE8021Q) {
            ipHeader = (IpHeaderStruct *) ((char *) ethernetHeader + sizeof(EthernetHeaderStruct) + 4);
        }
        else if (ntohs(ethernetHeader->type) == ETHER_TYPE_IPV6) {
            return;
        }
        else {
            ipHeader = (IpHeaderStruct *) ((char *) ethernetHeader + sizeof(EthernetHeaderStruct));
        }
    }

    // parse and validate
    if (!is_ipv4(ipHeader)) {
        return;
    }

    // check for UDP encapsulation
    if (ipHeader->ip_p == 17) {
        const auto udpHeader = (UdpHeaderStruct *) ((char *) ipHeader + sizeof(IpHeaderStruct));
        if (ntohs(udpHeader->dest) == 4789) {
            ipHeader = (IpHeaderStruct *) ((char *) ethernetHeader + sizeof(EthernetHeaderStruct) * 2 + sizeof(UdpHeaderStruct) + sizeof(IpHeaderStruct) + 8 /*VXLAN Size */);

            // parse and validate
            if (!is_ipv4(ipHeader)) {
                return;
            }
        }
    }

#ifdef SNIFFER_SIPPARSER_H
    // listen for UDP packets
    if (ipHeader->ip_p == 17) {
        // int ipHeaderLength, u_char *ipPacketEnd
        SipParser::handle(ethernetHeader, ipHeader, ipHeader->headerLen(), reinterpret_cast<unsigned char*>(ipHeader) + ipHeader->packetLen());
        return;
    }
#endif

    // only listen for TCP packets...
    if (ipHeader->ip_p != 6) {
        return;
    }

    // ...on port 5038
    const auto tcpHeader = (TcpHeaderStruct *) ((char *) ipHeader + sizeof(IpHeaderStruct));
    if (ntohs(tcpHeader->dest) != 5038) {
        return;
    }

    // this is ripped directly from VoIp.cpp, so it might not be needed here and might even be detrimental
    u_char *ipPacketEnd = (u_char *) ipHeader + ntohs(ipHeader->ip_len);
    u_char *captureEnd  = (u_char *) pkt_data + header->caplen;
    if (captureEnd < ipPacketEnd || ipPacketEnd <= ((u_char *) ipHeader + ipHeader->headerLen() + sizeof(TcpHeaderStruct))) {

        // log the snip; this is due to me being unsure if it's harmful
        snips << ntohs(ipHeader->ip_len) << " / (" << header->caplen << " and " << (ipHeader->headerLen() + sizeof(TcpHeaderStruct)) << ')' << std::endl;
        snips.write((char *) pkt_data, header->caplen);
        snips << std::endl << std::endl;
        printf("PCAP 5038: snipped or not enough payload\n");
        return;// The packet has been snipped or has not enough payload, drop it,
    }

    // ignore packets without data
    std::size_t len = ipHeader->payloadLen() - tcpHeader->off * 4;
    if (!len) {
        return;
    }

    // copy data into a buffer
    char *data = clone((char *)captureEnd - len, len);

    // only care about Originate actions
    if (strncmp("Action: Originate\r", data, 18)) {
        return;
    }

    char      *number_agent = nullptr, *number_exit = nullptr;
    for (char *token        = strtok(data, "\r\n"); token; token = strtok(nullptr, "\r\n")) {

        // get agent number
        if (!strncmp("Variable: AGENTCODE=", token, 20)) {
            if (!number_agent) {
                number_agent = clone(token + 20, strlen(token + 20));
            }
        }

            // get exit number
        else if (!strncmp("Variable: EXTTODIAL=", token, 20)) {
            if (!number_exit) {
                number_exit = clone(token + 20, strlen(token + 20));
            }
        }
    }
    delete[] data;

    // FIXME: now we need to do something
    if (number_agent && number_exit) {
        printf("Agent Number: %s\nExt Number: %s\n\n", number_agent, number_exit);
    }

    delete[] number_agent;
    delete[] number_exit;
}

/*void QMetrics::t_main(pcap_t *pcap_handle) {
#ifndef WIN32
    pthread_setname_np(pthread_self(), "qmetrics:pcap");
#endif

    if (pcap_handle) {
        pcap_loop(pcap_handle, 0, handle_packet, NULL);

        CStdString deviceName = VoIpSingleton::instance()->GetPcapDeviceName(pcap_handle);
        if (deviceName.size()) {
            while (1) {
                std::this_thread::sleep_for(std::chrono::seconds(60));

                pcap_handle = VoIpSingleton::instance()->OpenDevice(deviceName);
                if (pcap_handle) {
                    pcap_loop(pcap_handle, 0, handle_packet, NULL);
                }
            }
        }
    }
}*/