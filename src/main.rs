use tracing::{info, error};

// Modules are now in lib.rs

use joybug::logging; // Added to use the library's logging module
use joybug::debug_server;

#[tokio::main]
async fn main() {
    // Initialize logging from the library
    logging::init_subscriber();
    info!("Main function started. Starting debug server...");

    let server_port = 8080;
    info!(port = server_port, "Starting debug server on port");

    // Run the debug server
    if let Err(e) = debug_server::run_server(server_port).await {
        error!("Server error: {}", e);
    }
} 