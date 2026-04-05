#include "ConsolePresentation.hpp"
#include <iostream>
#include <algorithm>

using namespace std;

void ConsolePresentation::render(const AggregationSnapshot& snapshot) const {
    cerr << "\n========== Final Aggregation Summary ==========\n";

    cerr << "Top Processes:\n";
    for (size_t i = 0; i < min<size_t>(5, snapshot.top_processes.size()); ++i) {
        const auto& p = snapshot.top_processes[i];
        cerr << "  PID=" << p.pid
                  << "  PROC=" << p.process_name
                  << "  USER=" << p.user
                  << "  BYTES=" << p.bytes
                  << "  PACKETS=" << p.packets
                  << "\n";
    }

    cerr << "Top Users:\n";
    for (size_t i = 0; i < min<size_t>(5, snapshot.top_users.size()); ++i) {
        const auto& u = snapshot.top_users[i];
        cerr << "  USER=" << u.user
                  << "  BYTES=" << u.bytes
                  << "  PACKETS=" << u.packets
                  << "\n";
    }

    cerr << "Protocols:\n";
    for (const auto& pr : snapshot.protocol_stats) {
        cerr << "  PROTO=" << pr.protocol
                  << "  BYTES=" << pr.bytes
                  << "  PACKETS=" << pr.packets
                  << "\n";
    }

    cerr << "===============================================\n";
}
