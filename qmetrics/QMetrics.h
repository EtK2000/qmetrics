//
// Created by Eytan on 9/19/2021.
//

#ifndef QMETRICS_H
#define QMETRICS_H

#include <pcap.h>

class QMetrics {
public:
    static void handle_packet([[maybe_unused]] u_char *param, const pcap_pkthdr *header, const u_char *pkt_data);
    //static void t_main();
};


#endif //QMETRICS_H