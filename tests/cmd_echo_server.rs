use joybug::debugger_interface::{DebugEvent, ContinueDecision, LaunchedProcessInfo, ProcessId, Address};
use joybug::debug_client::DebugClient;
use joybug::debug_server;
use joybug::logging;
use joybug::arch::Architecture;
use tracing::{info, error, warn, debug, trace};
use std::collections::HashMap;
use joybug::debugger_interface::Debugger;

fn disassemble_around_address(
    debugger: &DebugClient,
    process_id: ProcessId,
    address: Address,
    arch: &Architecture,
    symbol_info: &str,
) {
    // Use the remote disassembly interface via the debug server
    let memory_size = 64;
    let start_address = address;
    
    info!(
        address = format_args!("0x{:X}", address),
        start = format_args!("0x{:X}", start_address),
        size = memory_size,
        symbol = %symbol_info,
        "📋 Requesting disassembly from debug server"
    );

    // Use the remote disassembly API (limit to 10 instructions for readability)
    match debugger.disassemble(process_id, start_address, memory_size, Some(10), Some(*arch)) {
        Ok(result) => {
            info!(
                instructions_found = result.instructions.len(),
                bytes_disassembled = result.bytes_disassembled,
                start_address = format_args!("0x{:X}", result.start_address),
                "🔍 Remote disassembly results:"
            );

            for instruction in result.instructions {
                let marker = if instruction.address == address {
                    " <-- BREAKPOINT"
                } else {
                    ""
                };
                
                info!("    {}{}", instruction, marker);
            }
        }
        Err(e) => {
            warn!(
                address = format_args!("0x{:X}", address),
                error = %e,
                "Failed to disassemble memory via remote interface"
            );
        }
    }
}

fn handle_breakpoint_instruction(
    debugger: &mut DebugClient, 
    process_id: ProcessId, 
    address: Address, 
    arch: &Architecture,
    loaded_modules: &HashMap<String, (Address, Option<usize>)>
) {
    let bp_instruction = arch.breakpoint_instruction();
    let nop_instruction = arch.nop_instruction();
    
    // Try to resolve symbol for the breakpoint address
    let mut symbol_info = String::from("Symbol not resolved");
    
    // Try to find which module this address belongs to
    for (module_name, (base_address, module_size)) in loaded_modules {
        if let Some(size) = module_size {
            let module_end = base_address + size;
            if address >= *base_address && address < module_end {
                let rva = (address - base_address) as u32;
                info!(
                    address = format_args!("0x{:X}", address),
                    module = module_name,
                    base = format_args!("0x{:X}", base_address),
                    rva = format_args!("0x{:X}", rva),
                    "Breakpoint address belongs to module"
                );
                
                // Try to resolve symbol via server
                match debugger.resolve_rva_to_symbol(process_id, module_name, rva) {
                    Ok(Some(symbol)) => {
                        if symbol.rva == rva {
                            symbol_info = format!("{}!{}", module_name, symbol.name);
                        } else {
                            let distance = rva - symbol.rva;
                            symbol_info = format!("{}!{}+0x{:X}", module_name, symbol.name, distance);
                        }
                    }
                    Ok(None) => {
                        symbol_info = format!("{}!<no symbol>", module_name);
                    }
                    Err(e) => {
                        warn!(
                            module = module_name,
                            error = %e,
                            "Failed to resolve symbol for RVA via server"
                        );
                        symbol_info = format!("{}!<symbol resolution failed>", module_name);
                    }
                }
                break;
            }
        }
    }
    
    info!(
        address = format_args!("0x{:X}", address),
        symbol = %symbol_info,
        "🎯 Breakpoint hit with symbol information"
    );

    // TODO: github arm machine has a wrongly resolved symbol
    if !symbol_info.contains("LdrpDoDebuggerBreak") {
        warn!(
            "Expected breakpoint symbol to contain LdrpDoDebuggerBreak, but got: {}",
            symbol_info
        );
    }
    
    // Disassemble memory around the breakpoint for analysis
    disassemble_around_address(debugger, process_id, address, arch, &symbol_info);
    
    // Read memory at breakpoint address to verify it's a breakpoint instruction
    match debugger.read_process_memory(process_id, address, bp_instruction.len()) {
        Ok(memory_bytes) => {
            if arch.is_breakpoint(&memory_bytes) {
                info!(
                    address = format_args!("0x{:X}", address),
                    bytes = format!("{:02X?}", memory_bytes),
                    symbol = %symbol_info,
                    "✓ Confirmed breakpoint instruction at address"
                );
                
                // Write nop instruction to replace the breakpoint
                match debugger.write_process_memory(process_id, address, nop_instruction) {
                    Ok(()) => {
                        info!(
                            address = format_args!("0x{:X}", address),
                            nop_bytes = format!("{:02X?}", nop_instruction),
                            "✓ Successfully wrote NOP instruction to replace breakpoint"
                        );
                    }
                    Err(e) => {
                        error!(
                            address = format_args!("0x{:X}", address),
                            error = %e,
                            "Failed to write NOP instruction"
                        );
                    }
                }
            } else {
                panic!(
                    "Memory at breakpoint address 0x{:X} does not contain expected breakpoint instruction. Expected: {:02X?}, Actual: {:02X?}",
                    address, bp_instruction, memory_bytes
                );
            }
        }
        Err(e) => {
            error!(
                address = format_args!("0x{:X}", address),
                error = %e,
                "Failed to read memory at breakpoint address"
            );
        }
    }
}

fn main_loop_sync(debugger: &mut DebugClient, initial_process_info: LaunchedProcessInfo) -> Vec<String> {
    info!(
        pid = initial_process_info.process_id,
        tid = initial_process_info.thread_id,
        "Process launched successfully, entering debug loop"
    );

    let mut loaded_dlls: Vec<String> = Vec::new();
    let mut loaded_modules: HashMap<String, (Address, Option<usize>)> = HashMap::new();
    
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
                        info!(
                            event_type = "BreakpointHit",
                            pid = process_id,
                            tid = thread_id,
                            address = format_args!("0x{:X}", address),
                            "Breakpoint hit in debuggee"
                        );
                        
                        // Get current architecture
                        let arch = Architecture::current();
                        
                        handle_breakpoint_instruction(debugger, process_id, address, &arch, &loaded_modules);
                        
                        continue_decision = ContinueDecision::HandledException;
                    }
                    DebugEvent::ProcessCreated { process_id, thread_id, ref image_file_name, base_of_image, size_of_image } => {
                        info!(
                            event_type = "ProcessCreated",
                            pid = process_id,
                            tid = thread_id,
                            image_name = image_file_name.as_deref().unwrap_or("<unknown>"),
                            base = format_args!("0x{:X}", base_of_image),
                            size = size_of_image.map(|s| format!("0x{:X}", s)).as_deref().unwrap_or("<unknown>"),
                            "Debuggee process created"
                        );
                        
                        // Track the main process module
                        if let Some(image_name) = image_file_name {
                            loaded_modules.insert(image_name.clone(), (base_of_image, size_of_image));
                            
                            // Try to load symbols for the main process via server
                            if let Err(e) = debugger.load_symbols_for_module(process_id, image_name, base_of_image, size_of_image) {
                                debug!(
                                    module = image_name,
                                    error = %e,
                                    "Failed to load symbols for main process module via server"
                                );
                            } else {
                                info!(
                                    module = image_name,
                                    "✓ Symbols loaded successfully for main process module via server"
                                );
                            }
                        }
                        
                        // Verify that we got a valid module size for the main process
                        if let Some(size) = size_of_image {
                            assert!(size > 0, "Process module size should be greater than 0, got: {}", size);
                            info!("✓ Process module size verified: 0x{:X} bytes", size);
                        } else {
                            warn!("Process module size not available");
                        }
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
                    DebugEvent::DllLoaded { process_id, thread_id, ref dll_name, base_of_dll, size_of_dll } => {
                        let dll_name_str = dll_name.as_deref().unwrap_or("<unknown>");
                        info!(
                            event_type = "DllLoaded",
                            pid = process_id,
                            tid = thread_id,
                            name = dll_name_str,
                            base = format_args!("0x{:X}", base_of_dll),
                            size = size_of_dll.map(|s| format!("0x{:X}", s)).as_deref().unwrap_or("<unknown>"),
                            "DLL loaded in debuggee"
                        );

                        // Verify that we got a valid module size for DLLs
                        if let Some(size) = size_of_dll {
                            assert!(size > 0, "DLL '{}' module size should be greater than 0, got: {}", dll_name_str, size);
                            info!("✓ DLL '{}' module size verified: 0x{:X} bytes", dll_name_str, size);
                        } else {
                            warn!("DLL '{}' module size not available", dll_name_str);
                        }

                        // Track loaded modules
                        loaded_modules.insert(dll_name_str.to_string(), (base_of_dll, size_of_dll));
                        
                        // Try to load symbols for this module via server
                        if let Err(e) = debugger.load_symbols_for_module(process_id, dll_name_str, base_of_dll, size_of_dll) {
                            debug!(
                                module = dll_name_str,
                                error = %e,
                                "Failed to load symbols for module via server (this is often expected for system DLLs)"
                            );
                        } else {
                            info!(
                                module = dll_name_str,
                                "✓ Symbols loaded successfully for module via server"
                            );
                        }

                        // Track loaded DLLs
                        loaded_dlls.push(dll_name_str.to_string());

                        verify_dos_header_sync(debugger, process_id, base_of_dll);
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

    loaded_dlls
}

fn verify_dos_header_sync(debugger: &DebugClient, process_id: ProcessId, base_of_dll: Address) {
    trace!(
        pid = process_id,
        dll_base = format_args!("0x{:X}", base_of_dll),
        "Verifying DOS header for loaded DLL."
    );
    match debugger.read_process_memory(process_id, base_of_dll, 2) {
        Ok(header_bytes) => {
            if header_bytes.len() == 2 && header_bytes[0] == b'M' && header_bytes[1] == b'Z' {
                trace!(
                    pid = process_id,
                    dll_base = format_args!("0x{:X}", base_of_dll),
                    magic = format!("{}{}", header_bytes[0] as char, header_bytes[1] as char),
                    "DOS magic 'MZ' confirmed for loaded DLL."
                );
            } else {
                error!(
                    pid = process_id,
                    dll_base = format_args!("0x{:X}", base_of_dll),
                    header = ?header_bytes,
                    "Invalid or unexpected DOS magic for loaded DLL."
                );
                panic!(
                    "DOS header magic mismatch for DLL at 0x{:X}. Expected 'MZ', got {:?}",
                    base_of_dll, header_bytes
                );
            }
        }
        Err(e) => {
            error!(
                pid = process_id,
                dll_base = format_args!("0x{:X}", base_of_dll),
                error = %e,
                "Failed to read DOS header of loaded DLL."
            );
            panic!("Failed to read DOS header for DLL at 0x{:X}: {}", base_of_dll, e);
        }
    }
}

#[test]
fn test_debugger_server_interface() {
    logging::init_subscriber();

    let server_port = 8888;
    let server_url = format!("http://127.0.0.1:{}", server_port);

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

    // Create a debug client
    let mut debugger = DebugClient::new(server_url);

    // Ping the server to ensure it's up
    info!("Pinging server to ensure it is available...");
    if let Err(e) = debugger.ping() {
        error!(error = %e, "Failed to ping debug server");
        panic!("Failed to ping debug server: {}", e);
    }
    info!("✓ Server ping successful.");

    let command_to_run = "cmd.exe /c echo Hello, World! I\'m a cmd.exe process";

    info!(command = command_to_run, "Attempting to launch process via debug server");

    match debugger.launch(command_to_run) {
        Ok(process_info) => {
            // Query debug sessions after launching the process
            info!("Querying debug sessions from server...");
            match debugger.list_sessions() {
                Ok(sessions) => {
                    info!(sessions = ?sessions, "Active debug sessions retrieved from server");
                    
                    // Assert that there is at least one session
                    assert!(!sessions.is_empty(), "Expected at least one active debug session after launching process");
                    
                    // Assert that our current session is in the list
                    if let Some(current_session_id) = debugger.get_session_id() {
                        assert!(
                            sessions.contains(current_session_id),
                            "Expected current session ID '{}' to be in the list of active sessions: {:?}",
                            current_session_id,
                            sessions
                        );
                        info!(
                            session_id = current_session_id,
                            "✓ Verified current session is listed in active sessions"
                        );
                    } else {
                        panic!("Expected debugger to have a session ID after successful launch");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to query debug sessions from server");
                    panic!("Failed to query debug sessions: {}", e);
                }
            }

            let loaded_dlls = main_loop_sync(&mut debugger, process_info);
            
            info!(dlls = ?loaded_dlls, "Loaded DLLs during execution");
            
            // Check that we have at least one DLL loaded
            assert!(!loaded_dlls.is_empty(), "Expected at least one DLL to be loaded");
            
            // Check that the first loaded DLL is ntdll.dll (case insensitive)
            let first_dll = &loaded_dlls[0];
            let first_dll_lower = first_dll.to_lowercase();
            assert!(
                first_dll_lower.contains("ntdll.dll") || first_dll_lower.ends_with("ntdll.dll"),
                "Expected first loaded DLL to be ntdll.dll, but got: {}",
                first_dll
            );
            
            info!("✓ Verified that ntdll.dll is the first loaded module via server interface");
        }
        Err(e) => {
            error!(error = %e, "Failed to launch process via debug server");
            panic!("Failed to launch process: {}", e);
        }
    }
    
    info!("Cleaning up debugger client.");
    if let Err(e) = debugger.detach() {
        error!(error = %e, "Error detaching debugger client");
    }

    info!("Debug server interface test finished.");
    
    // Note: The server thread will be terminated when the test ends
} 