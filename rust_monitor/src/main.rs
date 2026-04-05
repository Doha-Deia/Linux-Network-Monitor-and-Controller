mod aggregator;
mod correlator;
mod packet_capture;
mod packet_types;

use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use aggregator::Aggregator;
use correlator::Correlator;
use packet_capture::PacketCapture;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stop_flag = Arc::new(AtomicBool::new(true));
    let signal_flag = Arc::clone(&stop_flag);

    ctrlc::set_handler(move || {
        signal_flag.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut aggregator = Aggregator::new();
    let mut correlator = Correlator::new();
    let mut capture = PacketCapture::new(Arc::clone(&stop_flag));
    let mut packet_count: u64 = 0;

    let result = capture.start(|packet| {
        let resolved = correlator.resolve(&packet);
        aggregator.update(&resolved);

        println!("{}", serde_json::to_string(&resolved).unwrap());
    });

    if let Err(err) = result {
        eprintln!("capture error: {err}");
    }

    if aggregator.has_data() {
        aggregator.print_summary();
    }

    Ok(())
}
