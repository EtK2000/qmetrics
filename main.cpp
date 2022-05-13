#include "qmetrics/QMetrics.h"
#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <thread>

int main(int argc, char **argv) {
    const char *device = argc > 1 ? argv[1] : "ens160";

    char   errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr = pcap_open_live(device, BUFSIZ, true, -1, errbuf);

    if (!descr) {
        printf("[ERROR] pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    std::thread([descr, device]() {
        printf("capturing on: %s\n", device);
        pcap_loop(descr, 0, QMetrics::handle_packet, nullptr);
        pcap_close(descr);
        printf("done capturing on: %s\n", device);
    }).detach();

    for (;; std::this_thread::sleep_for(std::chrono::seconds(10)));
    return 0;
}