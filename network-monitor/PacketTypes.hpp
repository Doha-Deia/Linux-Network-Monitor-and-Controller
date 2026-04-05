#ifndef PACKET_TYPES_HPP
#define PACKET_TYPES_HPP

#include <string>
#include <cstdint>

using namespace std;

struct PacketEvent {
    string ts;
    uint64_t length{0};

    string src_ip;
    uint16_t src_port{0};

    string dst_ip;
    uint16_t dst_port{0};

    uint8_t proto{0};
    string protocol{"other"};
};

struct ResolvedPacket {
    string ts;
    uint64_t length{0};

    string src_ip;
    uint16_t src_port{0};

    string dst_ip;
    uint16_t dst_port{0};

    uint8_t proto{0};
    string protocol{"other"};

    unsigned long inode{0};
    int pid{-1};
    string process_name{"unknown"};
    string user{"unknown"};
};

#endif
