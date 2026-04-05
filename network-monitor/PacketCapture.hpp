#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <pcap.h>
#include <functional>

using namespace std;

#include "PacketTypes.hpp"

class PacketCapture {
public:
    using PacketCallback = function<void(const PacketEvent&)>;

    PacketCapture();
    ~PacketCapture();

    bool start(const PacketCallback& callback);
    void stop();
    bool is_running() const;

private:
    static void pcap_callback(u_char* user,
                              const struct pcap_pkthdr* header,
                              const u_char* packet);

    void handle_packet(const struct pcap_pkthdr* header, const u_char* packet);

    pcap_t* handle_;
    PacketCallback callback_;
    bool running_;
};

#endif
