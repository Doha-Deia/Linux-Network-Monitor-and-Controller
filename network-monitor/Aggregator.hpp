#ifndef AGGREGATOR_HPP
#define AGGREGATOR_HPP

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <cstdint>

using namespace std;

#include "PacketTypes.hpp"

struct ProcAgg {
    int pid{-1};
    string process_name{"unknown"};
    string user{"unknown"};
    uint64_t bytes{0};
    uint64_t packets{0};
};

struct UserAgg {
    string user{"unknown"};
    uint64_t bytes{0};
    uint64_t packets{0};
};

struct ProtoAgg {
    string protocol{"other"};
    uint64_t bytes{0};
    uint64_t packets{0};
};

class Aggregator {
public:
    void update(const ResolvedPacket& packet);
    void print_summary() const;
    bool has_data() const;

private:
    mutable mutex mtx_;
    map<int, ProcAgg> process_stats_;
    map<string, UserAgg> user_stats_;
    map<string, ProtoAgg> protocol_stats_;
};

#endif