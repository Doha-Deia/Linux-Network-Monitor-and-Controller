use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use chrono::{Local, TimeZone};
use pcap::{Active, Capture, Device};

use crate::packet_types::PacketEvent;

pub struct PacketCapture {
    cap: Option<Capture<Active>>,
    running: Arc<AtomicBool>,
}

impl PacketCapture {
    pub fn new(running: Arc<AtomicBool>) -> Self {
        Self { cap: None, running }
    }

    pub fn start<F>(&mut self, mut callback: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnMut(PacketEvent),
    {
        let devices = Device::list()?;
        let device = devices
            .into_iter()
            .find(|d| d.name != "lo")
            .ok_or("No non-loopback network device found")?;

        eprintln!("Using device: {}", device.name);

        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .timeout(100) 
            .open()?;
        
        // Non-blocking mode is what makes Ctrl+C instant
        cap = cap.setnonblock()?; 

        cap.filter("ip", true)?;
        self.cap = Some(cap);

        // --- The message is here ---
        eprintln!("Listening for packets (Ctrl-C to stop)...");

        while self.running.load(Ordering::SeqCst) {
            let packet_res = {
                let cap_ref = self.cap.as_mut().expect("capture should be initialized");
                cap_ref.next_packet()
            };

            match packet_res {
                Ok(packet) => {
                    // Safety check to exit immediately if Ctrl+C was pressed
                    if !self.running.load(Ordering::SeqCst) { break; }
                    
                    if let Some(ev) = Self::parse_packet(
                        packet.data, 
                        packet.header.len as u64, 
                        packet.header.ts.tv_sec, 
                        packet.header.ts.tv_usec
                    ) {
                        callback(ev);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // If no packet, sleep 10ms then check 'running' flag again
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(err) => return Err(Box::new(err)),
            }
        }
        
        Ok(())
    }

    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn parse_packet(data: &[u8], total_len: u64, ts_sec: i64, ts_usec: i64) -> Option<PacketEvent> {
        if data.len() < 14 + 20 {
            return None;
        }

        let ip_start = 14;
        let version = data[ip_start] >> 4;
        if version != 4 {
            return None;
        }

        let ihl = (data[ip_start] & 0x0f) as usize * 4;
        if data.len() < ip_start + ihl || ihl < 20 {
            return None;
        }

        let proto = data[ip_start + 9];
        let src_ip = format!(
            "{}.{}.{}.{}",
            data[ip_start + 12],
            data[ip_start + 13],
            data[ip_start + 14],
            data[ip_start + 15]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            data[ip_start + 16],
            data[ip_start + 17],
            data[ip_start + 18],
            data[ip_start + 19]
        );

        let transport_start = ip_start + ihl;
        let mut src_port = 0u16;
        let mut dst_port = 0u16;
        let protocol = match proto {
            6 => {
                if data.len() >= transport_start + 4 {
                    src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
                    dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
                }
                "TCP".to_string()
            }
            17 => {
                if data.len() >= transport_start + 4 {
                    src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
                    dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
                }
                "UDP".to_string()
            }
            1 => "ICMP".to_string(),
            _ => "other".to_string(),
        };

        let dt = Local.timestamp_opt(ts_sec, (ts_usec as u32) * 1000).single()?;
        let ts = dt.format("%Y-%m-%d %H:%M:%S").to_string();

        Some(PacketEvent {
            ts,
            length: total_len,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            protocol,
        })
    }
}
