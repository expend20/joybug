use joy_bug::debugger_interface::{Debugger, DebugEvent, ContinueDecision, LaunchedProcessInfo};
use joy_bug::windows_debugger::WindowsDebugger;
use joy_bug::logging;
use tracing::{info, error, warn, debug};

fn main_loop(debugger: &mut dyn Debugger, initial_process_info: LaunchedProcessInfo) {
    info!(
        pid = initial_process_info.process_id,
        tid = initial_process_info.thread_id,
        "Process launched successfully, entering debug loop"
    );

    loop {
        match debugger.wait_for_event() {
            Ok(event) => {
                debug!(?event, "Debug event received");
                let mut continue_decision = ContinueDecision::Continue;
                let mut should_break_loop = false;

                match event {
                    DebugEvent::ExceptionOccurred { process_id, thread_id, exception_code, exception_address, is_first_chance } => {
                        warn!(
                            event_type = "ExceptionOccurred",
                            pid = process_id,
                            tid = thread_id,
                            code = format_args!("0x{:08X}", exception_code),
                            address = format_args!("0x{:X}", exception_address),
                            first_chance = is_first_chance,
                            "Exception occurred in debuggee"
                        );
                        continue_decision = ContinueDecision::UnhandledException;
                    }
                    DebugEvent::BreakpointHit { process_id, thread_id, address } => {
                        warn!(
                            event_type = "BreakpointHit",
                            pid = process_id,
                            tid = thread_id,
                            address = format_args!("0x{:X}", address),
                            "Breakpoint hit in debuggee"
                        );
                        continue_decision = ContinueDecision::HandledException;
                    }
                    DebugEvent::ProcessCreated { process_id, thread_id, ref image_file_name, base_of_image } => {
                        info!(
                            event_type = "ProcessCreated",
                            pid = process_id,
                            tid = thread_id,
                            image_name = image_file_name.as_deref().unwrap_or("<unknown>"),
                            base = format_args!("0x{:X}", base_of_image),
                            "Debuggee process created"
                        );
                    }
                    DebugEvent::ProcessExited { process_id, thread_id, exit_code } => {
                        info!(
                            event_type = "ProcessExited",
                            pid = process_id,
                            tid = thread_id,
                            code = exit_code,
                            "Debuggee process exited"
                        );
                        should_break_loop = true;
                    }
                    DebugEvent::ThreadCreated { process_id, thread_id, start_address } => {
                        info!(
                            event_type = "ThreadCreated",
                            pid = process_id,
                            tid = thread_id,
                            start_addr = format_args!("0x{:X}", start_address),
                            "Thread created in debuggee"
                        );
                    }
                    DebugEvent::ThreadExited { process_id, thread_id, exit_code } => {
                        info!(
                            event_type = "ThreadExited",
                            pid = process_id,
                            tid = thread_id,
                            code = exit_code,
                            "Thread exited in debuggee"
                        );
                    }
                    DebugEvent::DllLoaded { process_id, thread_id, ref dll_name, base_of_dll } => {
                        info!(
                            event_type = "DllLoaded",
                            pid = process_id,
                            tid = thread_id,
                            name = dll_name.as_deref().unwrap_or("<unknown>"),
                            base = format_args!("0x{:X}", base_of_dll),
                            "DLL loaded in debuggee"
                        );
                    }
                    DebugEvent::DllUnloaded { process_id, thread_id, base_of_dll } => {
                        info!(
                            event_type = "DllUnloaded",
                            pid = process_id,
                            tid = thread_id,
                            base = format_args!("0x{:X}", base_of_dll),
                            "DLL unloaded in debuggee"
                        );
                    }
                    DebugEvent::OutputDebugString { process_id, thread_id, ref message } => {
                        info!(
                            event_type = "OutputDebugString",
                            pid = process_id,
                            tid = thread_id,
                            output = message,
                            "Debuggee output debug string"
                        );
                    }
                    DebugEvent::RipEvent { process_id, thread_id, error, event_type } => {
                        error!(
                            event_type = "RipEvent",
                            pid = process_id,
                            tid = thread_id,
                            err_code = error,
                            type_code = event_type,
                            "System integrity event (RIP) in debuggee"
                        );
                        should_break_loop = true;
                    }
                    DebugEvent::Unknown => {
                        warn!("Unknown debug event received from debugger interface.");
                    }
                }

                if should_break_loop {
                    break;
                }

                let (pid_to_continue, tid_to_continue) = match event {
                    DebugEvent::ExceptionOccurred { process_id, thread_id, .. } |
                    DebugEvent::BreakpointHit { process_id, thread_id, .. } |
                    DebugEvent::ProcessCreated { process_id, thread_id, .. } |
                    DebugEvent::ThreadCreated { process_id, thread_id, .. } |
                    DebugEvent::DllLoaded { process_id, thread_id, .. } |
                    DebugEvent::DllUnloaded { process_id, thread_id, .. } |
                    DebugEvent::OutputDebugString { process_id, thread_id, .. } |
                    DebugEvent::ThreadExited { process_id, thread_id, .. } => (process_id, thread_id),
                    _ => {
                        warn!("Unknown debug event received from debugger interface. ({:?})", event);
                        (initial_process_info.process_id, initial_process_info.thread_id)
                    }
                };

                if let Err(e) = debugger.continue_event(pid_to_continue, tid_to_continue, continue_decision) {
                    error!(error = %e, "Failed to continue debuggee");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "Error waiting for debug event");
                break;
            }
        }
    }
}

#[test]
fn test_debugger_main_loop() {
    logging::init_subscriber();

    let mut debugger: Box<dyn Debugger> = Box::new(WindowsDebugger::new());
    let command_to_run = "cmd.exe /c echo Hello, World! I\'m a cmd.exe process";

    info!(command = command_to_run, "Attempting to launch process");

    match debugger.launch(command_to_run) {
        Ok(process_info) => {
            main_loop(debugger.as_mut(), process_info);
        }
        Err(e) => {
            error!(error = %e, "Failed to launch process");
            // In a test, we might want to panic or assert here
            panic!("Failed to launch process: {}", e);
        }
    }
    
    info!("Cleaning up debugger.");
    if let Err(e) = debugger.detach() {
        error!(error = %e, "Error detaching debugger");
        // Optionally assert or panic in a test
    }

    info!("Debugger test finished.");
} 