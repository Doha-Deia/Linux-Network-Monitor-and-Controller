#ifndef CORRELATOR_HPP
#define CORRELATOR_HPP

#include <map>
#include <string>
#include <tuple>
#include <ctime>
#include <sys/types.h>

using namespace std;

#include "PacketTypes.hpp"

struct SockInfo {
    string local_ip;
    uint16_t local_port{};
    string remote_ip;
    uint16_t remote_port{};
    uid_t uid{};
    unsigned long inode{};
};

struct FlowKey {
    string ip1;
    uint16_t port1{};
    string ip2;
    uint16_t port2{};
    uint8_t proto{};

    bool operator<(const FlowKey& other) const {
        return tie(ip1, port1, ip2, port2, proto) <
               tie(other.ip1, other.port1, other.ip2, other.port2, other.proto);
    }
};

struct FlowOwner {
    unsigned long inode{};
    int pid{-1};
    uid_t uid{};
    string user{"unknown"};
    string process_name{"unknown"};
    time_t last_seen{};
};

class Correlator {
public:
    ResolvedPacket resolve(const PacketEvent& packet);
    void cleanup_cache(int ttl_seconds = 10);

private:
    string get_username(uid_t uid);
    string get_user_for_pid(int pid);
    string get_process_name(int pid);
    int find_pid_by_inode(unsigned long inode);

    map<unsigned long, SockInfo> parse_proc_net(const string& path);
    unsigned long find_inode(const map<unsigned long, SockInfo>& sock_map,
                             const string& src_ip, uint16_t src_port,
                             const string& dst_ip, uint16_t dst_port);

    FlowKey make_flow_key(const string& src_ip, uint16_t src_port,
                          const string& dst_ip, uint16_t dst_port,
                          uint8_t proto);

    map<FlowKey, FlowOwner> flow_cache_;
};

#endif
