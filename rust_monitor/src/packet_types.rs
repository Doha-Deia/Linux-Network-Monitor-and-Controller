use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PacketEvent {
    pub ts: String,
    pub length: u64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: u8,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedPacket {
    pub ts: String,
    pub length: u64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: u8,
    pub protocol: String,
    pub inode: u64,
    pub pid: i32,
    pub process_name: String,
    pub user: String,
}
