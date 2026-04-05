#include "Aggregator.hpp"

#include <algorithm>
#include <iostream>

using namespace std;

void Aggregator::update(const ResolvedPacket& packet) {
    lock_guard<mutex> lock(mtx_);

    auto& p = process_stats_[packet.pid];
    p.pid = packet.pid;
    p.process_name = packet.process_name;
    p.user = packet.user;
    p.bytes += packet.length;
    p.packets += 1;

    auto& u = user_stats_[packet.user];
    u.user = packet.user;
    u.bytes += packet.length;
    u.packets += 1;

    auto& pr = protocol_stats_[packet.protocol];
    pr.protocol = packet.protocol;
    pr.bytes += packet.length;
    pr.packets += 1;
}

bool Aggregator::has_data() const {
    lock_guard<mutex> lock(mtx_);
    return !process_stats_.empty() || !user_stats_.empty() || !protocol_stats_.empty();
}

void Aggregator::print_summary() const {
    vector<ProcAgg> procs;
    vector<UserAgg> users;
    vector<ProtoAgg> protos;

    {
        lock_guard<mutex> lock(mtx_);

        if (process_stats_.empty() && user_stats_.empty() && protocol_stats_.empty()) {
            return;
        }

        for (const auto& [pid, stat] : process_stats_) {
            procs.push_back(stat);
        }

        for (const auto& [user, stat] : user_stats_) {
            users.push_back(stat);
        }

        for (const auto& [proto, stat] : protocol_stats_) {
            protos.push_back(stat);
        }
    }

    sort(procs.begin(), procs.end(),
              [](const ProcAgg& a, const ProcAgg& b) {
                  return a.bytes > b.bytes;
              });

    sort(users.begin(), users.end(),
              [](const UserAgg& a, const UserAgg& b) {
                  return a.bytes > b.bytes;
              });

    sort(protos.begin(), protos.end(),
              [](const ProtoAgg& a, const ProtoAgg& b) {
                  return a.bytes > b.bytes;
              });

    cerr << "\n========== Final Aggregation Summary ==========\n";

    cerr << "Top Processes:\n";
    for (size_t i = 0; i < min<size_t>(5, procs.size()); ++i) {
        cerr << "  PID=" << procs[i].pid
                  << "  PROC=" << procs[i].process_name
                  << "  USER=" << procs[i].user
                  << "  BYTES=" << procs[i].bytes
                  << "  PACKETS=" << procs[i].packets
                  << "\n";
    }

    cerr << "Top Users:\n";
    for (size_t i = 0; i < min<size_t>(5, users.size()); ++i) {
        cerr << "  USER=" << users[i].user
                  << "  BYTES=" << users[i].bytes
                  << "  PACKETS=" << users[i].packets
                  << "\n";
    }

    cerr << "Protocols:\n";
    for (const auto& proto : protos) {
        cerr << "  PROTO=" << proto.protocol
                  << "  BYTES=" << proto.bytes
                  << "  PACKETS=" << proto.packets
                  << "\n";
    }

    cerr << "===============================================\n";
}