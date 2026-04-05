#include "Correlator.hpp"

#include <fstream>
#include <sstream>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

static string hex_to_ip(const string& hex8) {
    unsigned int raw = 0;
    sscanf(hex8.c_str(), "%X", &raw);
    struct in_addr addr;
    addr.s_addr = raw;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return string(buf);
}

string Correlator::get_username(uid_t uid) {
    struct passwd* pw = getpwuid(uid);
    return pw ? string(pw->pw_name) : "unknown";
}

string Correlator::get_user_for_pid(int pid) {
    ifstream f("/proc/" + to_string(pid) + "/status");
    if (!f.is_open()) return "unknown";

    string line;
    while (getline(f, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            istringstream iss(line.substr(4));
            uid_t real, effective;
            iss >> real >> effective;
            return get_username(effective);
        }
    }
    return "unknown";
}

string Correlator::get_process_name(int pid) {
    ifstream cl("/proc/" + to_string(pid) + "/cmdline");
    if (cl) {
        string cmd;
        getline(cl, cmd, '\0');
        if (!cmd.empty()) {
            size_t slash = cmd.rfind('/');
            if (slash != string::npos) cmd = cmd.substr(slash + 1);
            return cmd;
        }
    }

    ifstream cf("/proc/" + to_string(pid) + "/comm");
    string comm;
    if (cf) getline(cf, comm);
    return comm.empty() ? "unknown" : comm;
}

int Correlator::find_pid_by_inode(unsigned long inode) {
    const string target = "socket:[" + to_string(inode) + "]";
    DIR* proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent* pe;
    while ((pe = readdir(proc))) {
        if (!isdigit(static_cast<unsigned char>(pe->d_name[0]))) continue;

        string fd_dir = "/proc/" + string(pe->d_name) + "/fd/";
        DIR* fdd = opendir(fd_dir.c_str());
        if (!fdd) continue;

        struct dirent* fe;
        while ((fe = readdir(fdd))) {
            if (fe->d_name[0] == '.') continue;

            char buf[256];
            ssize_t len = readlink((fd_dir + fe->d_name).c_str(), buf, sizeof(buf) - 1);
            if (len > 0) {
                buf[len] = '\0';
                if (target == buf) {
                    int pid = stoi(pe->d_name);
                    closedir(fdd);
                    closedir(proc);
                    return pid;
                }
            }
        }
        closedir(fdd);
    }

    closedir(proc);
    return -1;
}

map<unsigned long, SockInfo> Correlator::parse_proc_net(const string& path) {
    map<unsigned long, SockInfo> result;
    ifstream f(path);
    if (!f.is_open()) return result;

    string line;
    getline(f, line); // skip header

    while (getline(f, line)) {
        istringstream iss(line);

        string sl, local_hex, rem_hex, st, tx_rx, tr_tm, retrnsmt;
        string timeout_str;
        unsigned int uid_val = 0;
        unsigned long inode = 0;

        if (!(iss >> sl >> local_hex >> rem_hex >> st
                  >> tx_rx >> tr_tm >> retrnsmt
                  >> uid_val >> timeout_str >> inode)) {
            continue;
        }

        if (inode == 0) continue;

        auto split_addr = [](const string& s, string& ip, uint16_t& port) {
            size_t c = s.find(':');
            if (c == string::npos) return;
            ip = hex_to_ip(s.substr(0, c));
            unsigned int p = 0;
            sscanf(s.substr(c + 1).c_str(), "%X", &p);
            port = static_cast<uint16_t>(p);
        };

        SockInfo info;
        split_addr(local_hex, info.local_ip, info.local_port);
        split_addr(rem_hex, info.remote_ip, info.remote_port);
        info.uid = static_cast<uid_t>(uid_val);
        info.inode = inode;

        result[inode] = info;
    }

    return result;
}

unsigned long Correlator::find_inode(const map<unsigned long, SockInfo>& sock_map,
                                     const string& src_ip, uint16_t src_port,
                                     const string& dst_ip, uint16_t dst_port) {
    for (const auto& [inode, sk] : sock_map) {
        if (sk.local_ip == src_ip && sk.local_port == src_port &&
            sk.remote_ip == dst_ip && sk.remote_port == dst_port)
            return inode;

        if (sk.local_ip == dst_ip && sk.local_port == dst_port &&
            sk.remote_ip == src_ip && sk.remote_port == src_port)
            return inode;

        if (sk.local_ip == "0.0.0.0") {
            if (sk.local_port == src_port) return inode;
            if (sk.local_port == dst_port) return inode;
        }
    }
    return 0;
}

FlowKey Correlator::make_flow_key(const string& src_ip, uint16_t src_port,
                                  const string& dst_ip, uint16_t dst_port,
                                  uint8_t proto) {
    pair<string, uint16_t> a = {src_ip, src_port};
    pair<string, uint16_t> b = {dst_ip, dst_port};

    if (b < a) swap(a, b);

    return FlowKey{a.first, a.second, b.first, b.second, proto};
}

ResolvedPacket Correlator::resolve(const PacketEvent& packet) {
    auto tcp_map = parse_proc_net("/proc/net/tcp");
    auto udp_map = parse_proc_net("/proc/net/udp");

    const auto& sock_map = (packet.proto == IPPROTO_TCP) ? tcp_map : udp_map;

    FlowKey flow_key = make_flow_key(packet.src_ip, packet.src_port,
                                     packet.dst_ip, packet.dst_port,
                                     packet.proto);

    unsigned long inode = 0;
    int pid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    string user = "unknown";
    string process_name = "unknown";

    if (packet.proto == IPPROTO_TCP || packet.proto == IPPROTO_UDP) {
        inode = find_inode(sock_map, packet.src_ip, packet.src_port,
                           packet.dst_ip, packet.dst_port);
    }

    if (inode != 0) {
        auto it = sock_map.find(inode);
        if (it != sock_map.end()) {
            uid = it->second.uid;
            user = get_username(uid);
        }

        pid = find_pid_by_inode(inode);
        if (pid > 0) {
            user = get_user_for_pid(pid);
            process_name = get_process_name(pid);
        }

        flow_cache_[flow_key] = FlowOwner{
            inode, pid, uid, user, process_name, time(nullptr)
        };
    } else {
        auto cit = flow_cache_.find(flow_key);
        if (cit != flow_cache_.end()) {
            inode = cit->second.inode;
            pid = cit->second.pid;
            uid = cit->second.uid;
            user = cit->second.user;
            process_name = cit->second.process_name;
            cit->second.last_seen = time(nullptr);
        }
    }

    ResolvedPacket rp;
    rp.ts = packet.ts;
    rp.length = packet.length;
    rp.src_ip = packet.src_ip;
    rp.src_port = packet.src_port;
    rp.dst_ip = packet.dst_ip;
    rp.dst_port = packet.dst_port;
    rp.proto = packet.proto;
    rp.protocol = packet.protocol;
    rp.inode = inode;
    rp.pid = pid;
    rp.process_name = process_name;
    rp.user = user;

    return rp;
}

void Correlator::cleanup_cache(int ttl_seconds) {
    time_t now = time(nullptr);
    for (auto it = flow_cache_.begin(); it != flow_cache_.end();) {
        if (now - it->second.last_seen > ttl_seconds) {
            it = flow_cache_.erase(it);
        } else {
            ++it;
        }
    }
}
