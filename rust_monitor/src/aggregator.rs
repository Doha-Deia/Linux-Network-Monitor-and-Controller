use std::collections::BTreeMap;

use crate::packet_types::ResolvedPacket;

#[derive(Debug, Clone)]
pub struct ProcAgg {
    pub pid: i32,
    pub process_name: String,
    pub user: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Debug, Clone)]
pub struct UserAgg {
    pub user: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Debug, Clone)]
pub struct ProtoAgg {
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Debug, Default)]
pub struct Aggregator {
    process_stats: BTreeMap<i32, ProcAgg>,
    user_stats: BTreeMap<String, UserAgg>,
    protocol_stats: BTreeMap<String, ProtoAgg>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, packet: &ResolvedPacket) {
        let p = self.process_stats.entry(packet.pid).or_insert_with(|| ProcAgg {
            pid: packet.pid,
            process_name: packet.process_name.clone(),
            user: packet.user.clone(),
            bytes: 0,
            packets: 0,
        });
        p.process_name = packet.process_name.clone();
        p.user = packet.user.clone();
        p.bytes += packet.length;
        p.packets += 1;

        let u = self.user_stats.entry(packet.user.clone()).or_insert_with(|| UserAgg {
            user: packet.user.clone(),
            bytes: 0,
            packets: 0,
        });
        u.bytes += packet.length;
        u.packets += 1;

        let pr = self.protocol_stats.entry(packet.protocol.clone()).or_insert_with(|| ProtoAgg {
            protocol: packet.protocol.clone(),
            bytes: 0,
            packets: 0,
        });
        pr.bytes += packet.length;
        pr.packets += 1;
    }

    pub fn has_data(&self) -> bool {
        !(self.process_stats.is_empty() && self.user_stats.is_empty() && self.protocol_stats.is_empty())
    }

    pub fn print_summary(&self) {
        if !self.has_data() {
            return;
        }

        let mut procs: Vec<_> = self.process_stats.values().cloned().collect();
        let mut users: Vec<_> = self.user_stats.values().cloned().collect();
        let mut protos: Vec<_> = self.protocol_stats.values().cloned().collect();

        procs.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        users.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        protos.sort_by(|a, b| b.bytes.cmp(&a.bytes));

        eprintln!("\n========== Final Aggregation Summary ==========");
        eprintln!("Top Processes:");
        for p in procs.iter().take(5) {
            eprintln!(
                "  PID={}  PROC={}  USER={}  BYTES={}  PACKETS={}",
                p.pid, p.process_name, p.user, p.bytes, p.packets
            );
        }

        eprintln!("Top Users:");
        for u in users.iter().take(5) {
            eprintln!(
                "  USER={}  BYTES={}  PACKETS={}",
                u.user, u.bytes, u.packets
            );
        }

        eprintln!("Protocols:");
        for pr in &protos {
            eprintln!(
                "  PROTO={}  BYTES={}  PACKETS={}",
                pr.protocol, pr.bytes, pr.packets
            );
        }
        eprintln!("===============================================");
    }
}
