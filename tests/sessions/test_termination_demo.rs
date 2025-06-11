use joybug::debug_client::DebugClient;
use joybug::logging;
use joybug::debugger_interface::Debugger;
use tracing::info;

#[path = "../common.rs"]
mod common;
use common::start_debug_server;

#[test]
fn test_basic_process_termination() {
    logging::init_subscriber();
    
    let server_url = start_debug_server();
    let mut debugger = DebugClient::new(server_url);
    
    info!("🧪 Testing basic process termination");
    
    // Launch a long-running process
    let command = "cmd.exe /c timeout /t 1";
    info!("Launching process: {}", command);
    
    let process_info = debugger.launch(command).expect("Failed to launch process");
    info!("✓ Process launched with PID: {}", process_info.process_id);
    
    // Wait for the process creation event
    let event = debugger.wait_for_event().expect("Failed to wait for event");
    info!("✓ Received event: {:?}", event);
    
    // Terminate the process
    let exit_code = 123;
    info!("Terminating process with exit code: {}", exit_code);
    
    debugger.terminate(process_info.process_id, exit_code)
        .expect("Failed to terminate process");
    
    info!("✓ Process termination request sent successfully");
    info!("🎉 Basic process termination test completed");
} 