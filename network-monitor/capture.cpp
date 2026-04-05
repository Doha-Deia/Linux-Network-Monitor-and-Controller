#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <map>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <tuple>
#include "Aggregator.hpp"
#include <csignal>

using json = nlohmann::json;
using namespace std;

pcap_t* g_handle = nullptr;

Aggregator g_aggregator;

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

map<FlowKey, FlowOwner> flow_cache;

FlowKey make_flow_key(const string& src_ip, uint16_t src_port,
                      const string& dst_ip, uint16_t dst_port,
                      uint8_t proto) {
    pair<string, uint16_t> a = {src_ip, src_port};
    pair<string, uint16_t> b = {dst_ip, dst_port};

    if (b < a) swap(a, b);

    return FlowKey{a.first, a.second, b.first, b.second, proto};
}

string get_username(uid_t uid) {
    struct passwd* pw = getpwuid(uid);
    return pw ? string(pw->pw_name) : "unknown";
}

string get_user_for_pid(int pid) {
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

// Get full process name from /proc/<pid>/cmdline
// Falls back to /proc/<pid>/comm if cmdline is empty (kernel threads)
string get_process_name(int pid) {
    // cmdline contains the full command line, null-byte separated
    // e.g. "/usr/lib/systemd/systemd-timesyncd\0--foo\0"
    ifstream cl("/proc/" + to_string(pid) + "/cmdline");
    if (cl) {
        string cmd;
        getline(cl, cmd, '\0');   // read up to first null = argv[0]
        if (!cmd.empty()) {
            // Strip full path, keep only binary name
            // e.g. "/usr/lib/systemd/systemd-timesyncd" ? "systemd-timesyncd"
            size_t slash = cmd.rfind('/');
            if (slash != string::npos)
                cmd = cmd.substr(slash + 1);
            return cmd;
        }
    }

    // Fallback: /proc/<pid>/comm (max 15 chars, but always present)
    ifstream cf("/proc/" + to_string(pid) + "/comm");
    string comm;
    if (cf) getline(cf, comm);
    return comm.empty() ? "unknown" : comm;
}

int find_pid_by_inode(unsigned long inode) {
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
                    closedir(fdd); closedir(proc);
                    return pid;
                }
            }
        }
        closedir(fdd);
    }
    closedir(proc);
    return -1;
}

struct SockInfo {
    string   local_ip;
    uint16_t local_port{};
    string   remote_ip;
    uint16_t remote_port{};
    uid_t    uid{};
    unsigned long inode{};
};

static string hex_to_ip(const string& hex8) {
    unsigned int raw = 0;
    sscanf(hex8.c_str(), "%X", &raw);
    struct in_addr addr;
    addr.s_addr = raw;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return string(buf);
}

map<unsigned long, SockInfo> parse_proc_net(const string& path) {
    map<unsigned long, SockInfo> result;
    ifstream f(path);
    if (!f.is_open()) return result;

    string line;
    getline(f, line); // skip header

    while (getline(f, line)) {
        istringstream iss(line);

        string sl, local_hex, rem_hex, st, tx_rx, tr_tm, retrnsmt;
        string timeout_str, more;
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

void cleanup_flow_cache(int ttl_seconds = 10) {
    time_t now = time(nullptr);
    for (auto it = flow_cache.begin(); it != flow_cache.end(); ) {
        if (now - it->second.last_seen > ttl_seconds) {
            it = flow_cache.erase(it);
        } else {
            ++it;
        }
    }
}

static unsigned long find_inode(
    const map<unsigned long, SockInfo>& sock_map,
    const string& src_ip, uint16_t src_port,
    const string& dst_ip, uint16_t dst_port)
{
    for (const auto& [inode, sk] : sock_map) {
        if (sk.local_ip == src_ip && sk.local_port == src_port &&
            sk.remote_ip == dst_ip && sk.remote_port == dst_port)
            return inode;

        if (sk.local_ip == dst_ip && sk.local_port == dst_port &&
            sk.remote_ip == src_ip && sk.remote_port == src_port)
            return inode;

        // fallback for listening or wildcard sockets
        if (sk.local_ip == "0.0.0.0") {
            if (sk.local_port == src_port) return inode;
            if (sk.local_port == dst_port) return inode;
        }
    }
    return 0;
}

void packet_handler(u_char* /*args*/,
    const struct pcap_pkthdr* header,
    const u_char* packet)
{
    if (header->caplen < 14 + 20) return;

    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + 14);
    if (ip_hdr->ip_v != 4) return;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

    uint8_t  proto = ip_hdr->ip_p;
    uint16_t src_port = 0, dst_port = 0;

    int           ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char* transport = packet + 14 + ip_hdr_len;
    size_t        avail = header->caplen - 14 - ip_hdr_len;

    if (proto == IPPROTO_TCP && avail >= 4) {
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(transport);
        src_port = ntohs(tcp->th_sport);
        dst_port = ntohs(tcp->th_dport);
    }
    else if (proto == IPPROTO_UDP && avail >= 4) {
        const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(transport);
        src_port = ntohs(udp->uh_sport);
        dst_port = ntohs(udp->uh_dport);
    }

    // Re-read socket tables fresh every packet to catch short-lived sockets
    auto tcp_map = parse_proc_net("/proc/net/tcp");
    auto udp_map = parse_proc_net("/proc/net/udp");

    const auto& sock_map = (proto == IPPROTO_TCP) ? tcp_map : udp_map;

    FlowKey flow_key = make_flow_key(src_ip, src_port, dst_ip, dst_port, proto);

    unsigned long inode = 0;
    int pid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    string user = "unknown";
    string process_name = "unknown";

    // 1) Try exact live lookup first
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        inode = find_inode(sock_map, src_ip, src_port, dst_ip, dst_port);
    }

    // 2) If inode found, resolve PID and user
    if (inode != 0) {
        auto it = sock_map.find(inode);
        if (it != sock_map.end()) {
            uid = it->second.uid;
            user = get_username(uid);   // fallback user from /proc/net/*
        }

        pid = find_pid_by_inode(inode);
        if (pid > 0) {
            user = get_user_for_pid(pid);        // better if available
            process_name = get_process_name(pid);
        }

        // cache successful or partial result
        flow_cache[flow_key] = FlowOwner{
            inode,
            pid,
            uid,
            user,
            process_name,
            time(nullptr)
        };
    }
    // 3) If live lookup failed, try cache
    else {
        auto cit = flow_cache.find(flow_key);
        if (cit != flow_cache.end()) {
            inode = cit->second.inode;
            pid = cit->second.pid;
            uid = cit->second.uid;
            user = cit->second.user;
            process_name = cit->second.process_name;
            cit->second.last_seen = time(nullptr);
        }
    }

    static int packet_count = 0;
    if (++packet_count % 100 == 0) {
        cleanup_flow_cache();
    }

    // Human readable timestamp
    char ts_buf[32];
    time_t t = header->ts.tv_sec;
    strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));

    // Protocol name
    string proto_name = "other";
    if (proto == IPPROTO_TCP) proto_name = "TCP";
    else if (proto == IPPROTO_UDP) proto_name = "UDP";

    ResolvedPacket rp;
    rp.ts = string(ts_buf);
    rp.length = header->len;
    rp.src_ip = src_ip;
    rp.src_port = src_port;
    rp.dst_ip = dst_ip;
    rp.dst_port = dst_port;
    rp.protocol = proto_name;
    rp.inode = inode;
    rp.pid = pid;
    rp.process_name = process_name;
    rp.user = user;

    g_aggregator.update(rp);

    json j;
    j["ts"] = rp.ts;
    j["length"] = rp.length;
    j["src_ip"] = rp.src_ip;
    j["src_port"] = rp.src_port;
    j["dst_ip"] = rp.dst_ip;
    j["dst_port"] = rp.dst_port;
    j["protocol"] = rp.protocol;
    j["inode"] = static_cast<unsigned long long>(rp.inode);
    j["pid"] = rp.pid;
    j["process_name"] = rp.process_name;
    j["user"] = rp.user;

    cout << j.dump() << "\n";
    cout.flush();
}

void handle_sigint(int) {
    if (g_handle) {
        pcap_breakloop(g_handle);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "pcap_findalldevs: " << errbuf << "\n"; return 1;
    }
    if (!alldevs) {
        cerr << "No network devices found (run as root)\n"; return 1;
    }

    pcap_if_t* device = alldevs;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) { device = d; break; }
    }
    cerr << "Using device: " << device->name << "\n";

    pcap_t* handle = pcap_open_live(device->name, 65535, 1, 100, errbuf);
    g_handle = handle;
    signal(SIGINT, handle_sigint);

    if (!handle) {
        cerr << "pcap_open_live: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct bpf_program fp {};
    if (pcap_compile(handle, &fp, "ip and (tcp or udp)", 1, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);

    cerr << "Listening for packets (Ctrl-C to stop)...\n";

    pcap_loop(handle, 0, packet_handler, nullptr);

    if (g_aggregator.has_data()) {
        g_aggregator.print_summary();
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}