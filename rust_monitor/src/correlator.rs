use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet_types::{PacketEvent, ResolvedPacket};

#[derive(Debug, Clone)]
struct SockInfo {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    uid: u32,
    inode: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct FlowKey {
    ip1: String,
    port1: u16,
    ip2: String,
    port2: u16,
    proto: u8,
}

#[derive(Debug, Clone)]
struct FlowOwner {
    inode: u64,
    pid: i32,
    uid: u32,
    user: String,
    process_name: String,
    last_seen: u64,
}

#[derive(Debug, Default)]
pub struct Correlator {
    flow_cache: BTreeMap<FlowKey, FlowOwner>,
}

impl Correlator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve(&mut self, packet: &PacketEvent) -> ResolvedPacket {
    // 1. Parse all relevant socket tables from /proc/net
    let tcp_map = Self::parse_proc_net("/proc/net/tcp");
    let udp_map = Self::parse_proc_net("/proc/net/udp");
    let raw_map = Self::parse_proc_net("/proc/net/raw"); // Required for ICMP

    // 2. Select the appropriate map based on protocol
    let sock_map = match packet.proto {
        6 => &tcp_map,
        17 => &udp_map,
        1 => &raw_map,
        _ => &tcp_map, // Default fallback
    };

    let flow_key = Self::make_flow_key(
        &packet.src_ip,
        packet.src_port,
        &packet.dst_ip,
        packet.dst_port,
        packet.proto,
    );

    let mut inode = 0u64;
    let mut pid = -1i32;
    let mut user = String::from("unknown");
    let mut process_name = String::from("unknown");

    // 3. Find the Inode: Use ports for TCP/UDP, IP-only for ICMP
    if packet.proto == 6 || packet.proto == 17 {
        inode = Self::find_inode(sock_map, &packet.src_ip, packet.src_port, &packet.dst_ip, packet.dst_port);
    } else if packet.proto == 1 {
        inode = Self::find_inode_raw(sock_map, &packet.src_ip, &packet.dst_ip);
    }

    // 4. Resolve PID and Owner if an inode was found
    if inode != 0 {
        if let Some(info) = sock_map.get(&inode) {
            user = Self::get_username(info.uid);
        }

        pid = Self::find_pid_by_inode(inode);
        if pid > 0 {
            user = Self::get_user_for_pid(pid);
            process_name = self.get_process_name(pid);
        }

        // Cache the result
        self.flow_cache.insert(
            flow_key,
            FlowOwner {
                inode,
                pid,
                uid: if let Some(i) = sock_map.get(&inode) { i.uid } else { u32::MAX },
                user: user.clone(),
                process_name: process_name.clone(),
                last_seen: Self::now_secs(),
            },
        );
    } else if let Some(owner) = self.flow_cache.get_mut(&flow_key) {
        // Use cached data if available
        inode = owner.inode;
        pid = owner.pid;
        user = owner.user.clone();
        process_name = owner.process_name.clone();
        owner.last_seen = Self::now_secs();
    }

    // 5. Construct the final ResolvedPacket
    ResolvedPacket {
        ts: packet.ts.clone(),
        length: packet.length,
        src_ip: packet.src_ip.clone(),
        src_port: packet.src_port,
        dst_ip: packet.dst_ip.clone(),
        dst_port: packet.dst_port,
        proto: packet.proto,
        protocol: packet.protocol.clone(),
        inode,
        pid,
        process_name,
        user,
    }
    }

    pub fn cleanup_cache(&mut self, ttl_seconds: u64) {
        let now = Self::now_secs();
        self.flow_cache.retain(|_, owner| now.saturating_sub(owner.last_seen) <= ttl_seconds);
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn get_username(uid: u32) -> String {
        if let Ok(file) = File::open("/etc/passwd") {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(parsed_uid) = parts[2].parse::<u32>() {
                        if parsed_uid == uid {
                            return parts[0].to_string();
                        }
                    }
                }
            }
        }
        "unknown".to_string()
    }

    fn get_user_for_pid(pid: i32) -> String {
        let path = format!("/proc/{pid}/status");
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return "unknown".to_string(),
        };

        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(uid) = parts[1].parse::<u32>() {
                        return Self::get_username(uid);
                    }
                }
            }
        }
        "unknown".to_string()
    }

    fn get_process_name(&self, pid: i32) -> String {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(bytes) = fs::read(&cmdline_path) {
            if !bytes.is_empty() {
                let first = bytes.split(|b| *b == 0).next().unwrap_or(&[]);
                if !first.is_empty() {
                    let cmd = String::from_utf8_lossy(first).to_string();
                    if let Some(name) = Path::new(&cmd).file_name() {
                        return name.to_string_lossy().to_string();
                    }
                    return cmd;
                }
            }
        }

        let comm_path = format!("/proc/{}/comm", pid);
        match fs::read_to_string(comm_path) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() {
                    "unknown".to_string()
                } else {
                    trimmed
                }
            }
            Err(_) => "unknown".to_string(),
        }
    }

    fn find_pid_by_inode(inode: u64) -> i32 {
        let target = format!("socket:[{inode}]");
        let proc_dir = match fs::read_dir("/proc") {
            Ok(rd) => rd,
            Err(_) => return -1,
        };

        for entry in proc_dir.flatten() {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let fd_dir = entry.path().join("fd");
            let fds = match fs::read_dir(fd_dir) {
                Ok(rd) => rd,
                Err(_) => continue,
            };

            for fd_entry in fds.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    if link.to_string_lossy() == target {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            return pid;
                        }
                    }
                }
            }
        }
        -1
    }

    fn parse_proc_net(path: &str) -> BTreeMap<u64, SockInfo> {
        let mut result = BTreeMap::new();
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return result,
        };

        for (i, line) in BufReader::new(file).lines().map_while(Result::ok).enumerate() {
            if i == 0 {
                continue;
            }

            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }

            let local_hex = cols[1];
            let remote_hex = cols[2];
            let uid_val = cols[7].parse::<u32>().unwrap_or(0);
            let inode = cols[9].parse::<u64>().unwrap_or(0);
            if inode == 0 {
                continue;
            }

            let (local_ip, local_port) = match Self::split_addr(local_hex) {
                Some(v) => v,
                None => continue,
            };
            let (remote_ip, remote_port) = match Self::split_addr(remote_hex) {
                Some(v) => v,
                None => continue,
            };

            result.insert(
                inode,
                SockInfo {
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    uid: uid_val,
                    inode,
                },
            );
        }

        result
    }

    fn split_addr(s: &str) -> Option<(String, u16)> {
        let (ip_hex, port_hex) = s.split_once(':')?;
        let ip = Self::hex_to_ip(ip_hex)?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        Some((ip, port))
    }

    fn hex_to_ip(hex8: &str) -> Option<String> {
        let raw = u32::from_str_radix(hex8, 16).ok()?;
        let bytes = raw.to_le_bytes();
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
    }

    fn find_inode(
        sock_map: &BTreeMap<u64, SockInfo>,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> u64 {
        for (inode, sk) in sock_map {
            if sk.local_ip == src_ip
                && sk.local_port == src_port
                && sk.remote_ip == dst_ip
                && sk.remote_port == dst_port
            {
                return *inode;
            }

            if sk.local_ip == dst_ip
                && sk.local_port == dst_port
                && sk.remote_ip == src_ip
                && sk.remote_port == src_port
            {
                return *inode;
            }

            if sk.local_ip == "0.0.0.0" {
                if sk.local_port == src_port || sk.local_port == dst_port {
                    return *inode;
                }
            }
        }
        0
    }

    fn make_flow_key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16, proto: u8) -> FlowKey {
        let a = (src_ip.to_string(), src_port);
        let b = (dst_ip.to_string(), dst_port);
        let (ip1, port1, ip2, port2) = if b < a {
            (b.0, b.1, a.0, a.1)
        } else {
            (a.0, a.1, b.0, b.1)
        };

        FlowKey { ip1, port1, ip2, port2, proto }
    }

    fn find_inode_raw(
    sock_map: &BTreeMap<u64, SockInfo>,
    src_ip: &str,
    dst_ip: &str,
    ) -> u64 {
        for (inode, sk) in sock_map {
            // Raw sockets (ICMP) match if the local IP is the sender, receiver, or 0.0.0.0
            if sk.local_ip == src_ip || sk.local_ip == dst_ip || sk.local_ip == "0.0.0.0" {
                return *inode;
            }
        }
        0
    }
}