#ifndef AGGREGATOR_HPP
#define AGGREGATOR_HPP

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <cstdint>

struct ResolvedPacket {
    std::string ts;
    uint64_t length{0};

    std::string src_ip;
    uint16_t src_port{0};

    std::string dst_ip;
    uint16_t dst_port{0};

    std::string protocol{"other"};

    unsigned long inode{0};
    int pid{-1};
    std::string process_name{"unknown"};
    std::string user{"unknown"};
};

struct ProcAgg {
    int pid{-1};
    std::string process_name{"unknown"};
    std::string user{"unknown"};
    uint64_t bytes{0};
    uint64_t packets{0};
};

struct UserAgg {
    std::string user{"unknown"};
    uint64_t bytes{0};
    uint64_t packets{0};
};

struct ProtoAgg {
    std::string protocol{"other"};
    uint64_t bytes{0};
    uint64_t packets{0};
};

class Aggregator {
public:
    void update(const ResolvedPacket& packet);
    void print_summary() const;
    bool has_data() const;

private:
    mutable std::mutex mtx_;
    std::map<int, ProcAgg> process_stats_;
    std::map<std::string, UserAgg> user_stats_;
    std::map<std::string, ProtoAgg> protocol_stats_;
};

#endif
