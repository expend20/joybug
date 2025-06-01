use tracing::{info};

// Modules are now in lib.rs

use joy_bug::logging; // Added to use the library's logging module

fn main() {
    // Initialize logging from the library
    logging::init_subscriber();
    info!("Main function started. Logic moved to test_debugger_main_loop.");
    // main logic moved to test_debugger_main_loop
} 