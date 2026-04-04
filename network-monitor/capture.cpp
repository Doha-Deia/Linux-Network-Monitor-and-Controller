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

using json = nlohmann::json;
using namespace std;

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

struct SockKey {
    string   local_ip;
    uint16_t local_port;
    string   remote_ip;
    uint16_t remote_port;
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

map<unsigned long, SockKey> parse_proc_net(const string& path) {
    map<unsigned long, SockKey> result;
    ifstream f(path);
    if (!f.is_open()) return result;
    string line;
    getline(f, line); // skip header
    while (getline(f, line)) {
        istringstream iss(line);
        string sl, local_hex, rem_hex, st, tx_rx, tr_tm, retrnsmt, timeout_str;
        unsigned int uid_val;
        unsigned long inode;
        if (!(iss >> sl >> local_hex >> rem_hex >> st
            >> tx_rx >> tr_tm >> retrnsmt
            >> uid_val >> timeout_str >> inode))
            continue;
        if (inode == 0) continue;
        auto split_addr = [](const string& s, string& ip, uint16_t& port) {
            size_t c = s.find(':');
            if (c == string::npos) return;
            ip = hex_to_ip(s.substr(0, c));
            unsigned int p = 0;
            sscanf(s.substr(c + 1).c_str(), "%X", &p);
            port = static_cast<uint16_t>(p);
            };
        SockKey key;
        split_addr(local_hex, key.local_ip, key.local_port);
        split_addr(rem_hex, key.remote_ip, key.remote_port);
        result[inode] = key;
    }
    return result;
}

static unsigned long find_inode(
    const map<unsigned long, SockKey>& sock_map,
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

    unsigned long inode = 0;
    if (proto == IPPROTO_TCP)
        inode = find_inode(tcp_map, src_ip, src_port, dst_ip, dst_port);
    else if (proto == IPPROTO_UDP)
        inode = find_inode(udp_map, src_ip, src_port, dst_ip, dst_port);

    int    pid = -1;
    string user = "unknown";
    string process_name = "unknown";   // full name from cmdline

    if (inode != 0) {
        pid = find_pid_by_inode(inode);
        if (pid > 0) {
            user = get_user_for_pid(pid);
            process_name = get_process_name(pid);  // full name
        }
    }

    // Human readable timestamp
    char ts_buf[32];
    time_t t = header->ts.tv_sec;
    strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));

    // Protocol name
    string proto_name = "other";
    if (proto == IPPROTO_TCP) proto_name = "TCP";
    else if (proto == IPPROTO_UDP) proto_name = "UDP";

    json j;
    j["ts"] = string(ts_buf);
    j["length"] = header->len;
    j["src_ip"] = src_ip;
    j["src_port"] = src_port;
    j["dst_ip"] = dst_ip;
    j["dst_port"] = dst_port;
    j["protocol"] = proto_name;
    j["inode"] = static_cast<unsigned long long>(inode);
    j["pid"] = pid;
    j["process_name"] = process_name;   // full process name
    j["user"] = user;

    cout << j.dump() << "\n";
    cout.flush();
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

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}