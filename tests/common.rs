use joybug::debug_server;
use tracing::{info, error};

pub fn start_debug_server() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    
    // Static counter to ensure each server gets a unique port
    static PORT_COUNTER: AtomicU32 = AtomicU32::new(8888);
    
    let server_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let server_url = format!("http://127.0.0.1:{}", server_port);

    info!(port = server_port, "Starting debug server on port");

    // Start the debug server in a background thread with single-threaded runtime
    // NOTE: Multi-threaded runtime is leading to a weird bugs, it looks like Debug Loop
    // is not working if CreateProcess and WaitForDebugEvent are called in different threads.
    // ref: https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop
    let _server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            if let Err(e) = debug_server::run_server(server_port).await {
                error!("Server error: {}", e);
            }
        });
    });

    server_url
} 