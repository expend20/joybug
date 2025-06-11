use joybug::debug_client::DebugClient;
use joybug::logging;
use joybug::debugger_interface::Debugger;
use tracing::{info, error, debug};

#[path = "../common.rs"]
mod common;
use common::start_debug_server;

fn test_sessions(server_url: &str) {
    info!("🧪 Testing multiple debug sessions management");
    
    // Create two debug clients
    let mut debugger1 = DebugClient::new(server_url.to_string());
    let mut debugger2 = DebugClient::new(server_url.to_string());
    
    let command_to_run = "cmd.exe /c echo test";  // Use timeout command to keep process alive longer
    
    info!("Launching first debug session...");
    let _process_info1 = match debugger1.launch(command_to_run) {
        Ok(info) => {
            info!(
                pid = info.process_id,
                tid = info.thread_id,
                "✓ First debug session launched successfully"
            );
            info
        }
        Err(e) => {
            error!(error = %e, "Failed to launch first debug session");
            panic!("Failed to launch first debug session: {}", e);
        }
    };
    
    info!("Launching second debug session...");
    let _process_info2 = match debugger2.launch(command_to_run) {
        Ok(info) => {
            info!(
                pid = info.process_id,
                tid = info.thread_id,
                "✓ Second debug session launched successfully"
            );
            info
        }
        Err(e) => {
            error!(error = %e, "Failed to launch second debug session");
            panic!("Failed to launch second debug session: {}", e);
        }
    };
    
    // Verify both sessions are active
    info!("Verifying both sessions are active...");
    match debugger1.list_sessions() {
        Ok(sessions) => {
            info!(sessions = ?sessions, "Active debug sessions retrieved");
            
            // Should have exactly 2 sessions
            assert_eq!(
                sessions.len(), 
                2, 
                "Expected exactly 2 active debug sessions, but found: {:?}", 
                sessions
            );
            
            // Verify both session IDs are in the list
            if let Some(session1_id) = debugger1.get_session_id() {
                assert!(
                    sessions.contains(session1_id),
                    "Expected session 1 ID '{}' to be in active sessions: {:?}",
                    session1_id, sessions
                );
                info!(session_id = session1_id, "✓ Session 1 verified in active list");
            } else {
                panic!("Expected debugger1 to have a session ID");
            }
            
            if let Some(session2_id) = debugger2.get_session_id() {
                assert!(
                    sessions.contains(session2_id),
                    "Expected session 2 ID '{}' to be in active sessions: {:?}",
                    session2_id, sessions
                );
                info!(session_id = session2_id, "✓ Session 2 verified in active list");
            } else {
                panic!("Expected debugger2 to have a session ID");
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to list debug sessions");
            panic!("Failed to list debug sessions: {}", e);
        }
    }
    
    info!("✓ Both debug sessions verified successfully");
    
    // Kill/detach both sessions
    info!("Detaching first debug session...");
    if let Err(e) = debugger1.detach() {
        error!(error = %e, "Failed to detach first debug session");
        panic!("Failed to detach first debug session: {}", e);
    }
    info!("✓ First debug session detached");
    
    info!("Detaching second debug session...");
    if let Err(e) = debugger2.detach() {
        error!(error = %e, "Failed to detach second debug session");
        panic!("Failed to detach second debug session: {}", e);
    }
    info!("✓ Second debug session detached");
    
    // Verify no sessions remain active
    info!("Verifying no sessions remain active...");
    
    // Create a new client to check sessions (since the previous ones are detached)
    let check_client = DebugClient::new(server_url.to_string());
    match check_client.list_sessions() {
        Ok(sessions) => {
            info!(sessions = ?sessions, "Debug sessions after cleanup");
            assert!(
                sessions.is_empty(),
                "Expected no active debug sessions after cleanup, but found: {:?}",
                sessions
            );
            info!("✓ Verified no active sessions remain");
        }
        Err(e) => {
            error!(error = %e, "Failed to list debug sessions during cleanup verification");
            panic!("Failed to list debug sessions during cleanup: {}", e);
        }
    }
    
    info!("🎉 Multiple debug sessions test completed successfully");
}

fn test_process_termination(server_url: &str) {
    info!("🧪 Testing process termination functionality");
    
    // Create a debug client
    let mut debugger = DebugClient::new(server_url.to_string());
    
    let command_to_run = "cmd.exe /c echo test";  // Use timeout command that will run for 1 second
    
    info!("Launching debug session for termination test...");
    let process_info = match debugger.launch(command_to_run) {
        Ok(info) => {
            info!(
                pid = info.process_id,
                tid = info.thread_id,
                "✓ Debug session launched successfully"
            );
            info
        }
        Err(e) => {
            error!(error = %e, "Failed to launch debug session");
            panic!("Failed to launch debug session: {}", e);
        }
    };
    
    // Wait for the process created event to ensure the process is running
    info!("Waiting for process created event...");
    match debugger.wait_for_event() {
        Ok(event) => {
            debug!("Received debug event: {:?}", event);
            match event {
                joybug::debugger_interface::DebugEvent::ProcessCreated { .. } => {
                    info!("✓ Process created event received");
                }
                _ => {
                    info!("Received event (not process created): {:?}", event);
                }
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to wait for debug event");
            panic!("Failed to wait for debug event: {}", e);
        }
    }
    
    info!("Terminating process...");
    let exit_code = 42; // Custom exit code to verify termination worked
    
    match debugger.terminate(process_info.process_id, exit_code) {
        Ok(()) => {
            info!(pid = process_info.process_id, exit_code = exit_code, "✓ Process terminated successfully");
        }
        Err(e) => {
            error!(error = %e, "Failed to terminate process");
            panic!("Failed to terminate process: {}", e);
        }
    }

    // make sure session is detached
    match debugger.list_sessions() {
        Ok(sessions) => {
            assert!(sessions.is_empty(), "Expected no active debug sessions after cleanup, but found: {:?}", sessions);
        }
        Err(e) => {
            panic!("Failed to list debug sessions during cleanup verification: {}", e); 
        }
    }

    info!("🎉 Process termination test completed successfully");
}

#[test]
fn test_multiple_debug_sessions() {
    logging::init_subscriber();

    let server_url = start_debug_server();

    test_sessions(&server_url);
}

#[test]
fn test_process_termination_feature() {
    logging::init_subscriber();

    let server_url = start_debug_server();

    test_process_termination(&server_url);
} 