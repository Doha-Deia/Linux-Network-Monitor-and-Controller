mod aggregator;
mod correlator;
mod packet_capture;
mod packet_types;
mod api;

use std::sync::{atomic::{AtomicBool, Ordering}, Arc,};

use aggregator::Aggregator;
use correlator::Correlator;
use packet_capture::PacketCapture;
use api::create_app;
use tokio::net::TcpListener;
use std::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Flag starts as TRUE (running)
    let stop_flag = Arc::new(AtomicBool::new(true));
    let signal_flag = Arc::clone(&stop_flag);

    ctrlc::set_handler(move || {
        // When Ctrl+C is hit, we set it to FALSE
        eprintln!("\n[!] Interrupt received, preparing summary...");
        signal_flag.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let aggregator = Arc::new(Mutex::new(Aggregator::new()));
    let mut correlator = Correlator::new();
    let mut capture = PacketCapture::new(Arc::clone(&stop_flag));

    // This will now return as soon as the flag becomes false 
    // thanks to non-blocking mode in packet_capture.rs
    // let result = capture.start(|packet| {
    //     let resolved = correlator.resolve(&packet);
    //     aggregator.update(&resolved);

    //     println!("{}", serde_json::to_string(&resolved).unwrap());
    // });

    // if let Err(err) = result {
    //     eprintln!("capture error: {err}");
    // }

    // // This block now executes immediately after the loop breaks
    // if aggregator.has_data() {
    //     aggregator.print_summary();
    // } else {
    //     eprintln!("No data captured.");
    // }

    // Spawn packet capture in background
    let agg_clone: Arc<Mutex<Aggregator>> = Arc::clone(&aggregator);

    std::thread::spawn(move || {
        let _ = capture.start(|packet| {
            let resolved = correlator.resolve(&packet);

            let mut agg = agg_clone.lock().unwrap();
            agg.update(&resolved);
        });
    });

    // Start API server
    let app = create_app(Arc::clone(&aggregator));

    println!("🌐 Open http://localhost:3000");

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}