#include "PacketCapture.hpp"

#include <iostream>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

PacketCapture::PacketCapture() : handle_(nullptr), running_(false) {}

PacketCapture::~PacketCapture() {
    stop();
}

bool PacketCapture::start(const PacketCallback& callback) {
    callback_ = callback;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "pcap_findalldevs: " << errbuf << "\n";
        return false;
    }

    if (!alldevs) {
        cerr << "No network devices found\n";
        return false;
    }

    pcap_if_t* device = alldevs;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            device = d;
            break;
        }
    }

    cerr << "Using device: " << device->name << "\n";

    handle_ = pcap_open_live(device->name, 65535, 1, 100, errbuf);
    if (!handle_) {
        cerr << "pcap_open_live: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return false;
    }

    struct bpf_program fp {};
    if (pcap_compile(handle_, &fp, "ip and (tcp or udp)", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle_, &fp);
        pcap_freecode(&fp);
    }

    pcap_freealldevs(alldevs);

    running_ = true;
    cerr << "Listening for packets (Ctrl-C to stop)...\n";

    int rc = pcap_loop(handle_, 0, PacketCapture::pcap_callback,
                       reinterpret_cast<u_char*>(this));

    if (rc == -1) {
        cerr << "pcap_loop error: " << pcap_geterr(handle_) << "\n";
    }

    running_ = false;
    return true;
}

void PacketCapture::stop() {
    if (handle_) {
        pcap_breakloop(handle_);
    }
}

bool PacketCapture::is_running() const {
    return running_;
}

void PacketCapture::pcap_callback(u_char* user,
                                  const struct pcap_pkthdr* header,
                                  const u_char* packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    self->handle_packet(header, packet);
}

void PacketCapture::handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < 14 + 20) return;

    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + 14);
    if (ip_hdr->ip_v != 4) return;

    PacketEvent ev;
    ev.length = header->len;
    ev.proto = ip_hdr->ip_p;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

    ev.src_ip = src_ip;
    ev.dst_ip = dst_ip;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char* transport = packet + 14 + ip_hdr_len;
    size_t avail = header->caplen - 14 - ip_hdr_len;

    if (ev.proto == IPPROTO_TCP && avail >= 4) {
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(transport);
        ev.src_port = ntohs(tcp->th_sport);
        ev.dst_port = ntohs(tcp->th_dport);
        ev.protocol = "TCP";
    } else if (ev.proto == IPPROTO_UDP && avail >= 4) {
        const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(transport);
        ev.src_port = ntohs(udp->uh_sport);
        ev.dst_port = ntohs(udp->uh_dport);
        ev.protocol = "UDP";
    } else {
        ev.protocol = "other";
    }

    char ts_buf[32];
    time_t t = header->ts.tv_sec;
    strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
    ev.ts = ts_buf;

    if (callback_) {
        callback_(ev);
    }
}