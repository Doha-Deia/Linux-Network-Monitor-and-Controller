#include <iostream>
#include <csignal>
#include <nlohmann/json.hpp>

#include "PacketCapture.hpp"
#include "Correlator.hpp"
#include "Aggregator.hpp"
#include "ConsolePresentation.hpp"

using json = nlohmann::json;

PacketCapture* g_capture = nullptr;
Aggregator g_aggregator;
Correlator g_correlator;

void handle_sigint(int) {
    if (g_capture) {
        g_capture->stop();
    }
}

int main() {
    signal(SIGINT, handle_sigint);

    PacketCapture capture;
    g_capture = &capture;

    bool ok = capture.start([](const PacketEvent& packet) {
        ResolvedPacket rp = g_correlator.resolve(packet);
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

        std::cout << j.dump() << "\n";
        std::cout.flush();
    });

    if (!ok) {
        return 1;
    }

    if (g_aggregator.has_data()) {
        AggregationSnapshot snap = g_aggregator.get_snapshot();
        ConsolePresentation presenter;
        presenter.render(snap);
    }

    return 0;
}
