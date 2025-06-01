use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, TRUE, GetLastError, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT, WaitForDebugEvent, OUTPUT_DEBUG_STRING_EVENT,
    CREATE_THREAD_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    RIP_EVENT,
};
use windows_sys::Win32::System::Threading::{
    PROCESS_INFORMATION, STARTUPINFOW, CreateProcessW, DEBUG_PROCESS, INFINITE,
};

fn to_wide_chars(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn main() {
    let cmd_line = to_wide_chars("cmd.exe /c echo test");

    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    println!("Attempting to launch process: cmd.exe /c echo test");

    let create_process_success = unsafe {
        CreateProcessW(
            ptr::null(),
            cmd_line.as_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE,
            DEBUG_PROCESS,
            ptr::null_mut(),
            ptr::null(),
            &mut startup_info,
            &mut process_info,
        )
    };

    if create_process_success == FALSE {
        let error = unsafe { GetLastError() };
        eprintln!("CreateProcessW failed with error: {}", error);
        return;
    }

    println!(
        "Process launched successfully. PID: {}, Main Thread ID: {}",
        process_info.dwProcessId, process_info.dwThreadId
    );

    let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    let mut continue_status: i32 = DBG_CONTINUE;

    loop {
        // Wait for a debugging event
        if unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) } == FALSE {
            let error = unsafe { GetLastError() };
            eprintln!("WaitForDebugEvent failed with error: {}", error);
            break;
        }

        println!("Debug event received: Code = {}", debug_event.dwDebugEventCode);

        match debug_event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                println!("  EXCEPTION_DEBUG_EVENT");
                // Process the exception code
                let exception_record = unsafe { debug_event.u.Exception.ExceptionRecord };
                println!(
                    "    ExceptionCode: {:#0x}",
                    exception_record.ExceptionCode
                );
                println!(
                    "    ExceptionAddress: {:?}",
                    exception_record.ExceptionAddress
                );
                if unsafe {debug_event.u.Exception.dwFirstChance} == 1 {
                    println!("    First chance exception.");
                } else {
                    println!("    Last chance exception.");
                }
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                println!("  CREATE_PROCESS_DEBUG_EVENT");
                let info = unsafe { debug_event.u.CreateProcessInfo };
                println!("    Process ID: {}", debug_event.dwProcessId);
                println!("    Thread ID: {}", debug_event.dwThreadId);
                println!("    Image File Handle: {:?}", info.hFile);
                if !info.hFile.is_null() {
                     unsafe { CloseHandle(info.hFile) };
                }
                continue_status = DBG_CONTINUE;
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                println!("  EXIT_PROCESS_DEBUG_EVENT");
                let info = unsafe { debug_event.u.ExitProcess };
                println!(
                    "    Process ID: {} exited with code: {}",
                    debug_event.dwProcessId, info.dwExitCode
                );
                break;
            }
            CREATE_THREAD_DEBUG_EVENT => {
                println!("  CREATE_THREAD_DEBUG_EVENT");
                 let info = unsafe { debug_event.u.CreateThread };
                println!(
                    "    Thread ID: {} (Handle: {:?}) created in process {}",
                    debug_event.dwThreadId, info.hThread, debug_event.dwProcessId
                );
                continue_status = DBG_CONTINUE;
            }
            EXIT_THREAD_DEBUG_EVENT => {
                println!("  EXIT_THREAD_DEBUG_EVENT");
                let info = unsafe { debug_event.u.ExitThread };
                println!(
                    "    Thread ID: {} exited with code: {}",
                    debug_event.dwThreadId, info.dwExitCode
                );
                continue_status = DBG_CONTINUE;
            }
            LOAD_DLL_DEBUG_EVENT => {
                println!("  LOAD_DLL_DEBUG_EVENT");
                let info = unsafe { debug_event.u.LoadDll };
                println!(
                    "    DLL loaded at base: {:?}, Handle: {:?}",
                    info.lpBaseOfDll, info.hFile
                );
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
                continue_status = DBG_CONTINUE;
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                println!("  UNLOAD_DLL_DEBUG_EVENT");
                let info = unsafe { debug_event.u.UnloadDll };
                println!("    DLL at base: {:?} unloaded", info.lpBaseOfDll);
                continue_status = DBG_CONTINUE;
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                println!("  OUTPUT_DEBUG_STRING_EVENT");
                let info = unsafe { debug_event.u.DebugString };
                 println!(
                    "    Output string event: Length {} ({} wide chars), from {:p}",
                    info.nDebugStringLength,
                    if info.fUnicode as i32 == TRUE { "unicode" } else { "ansi" },
                    info.lpDebugStringData
                );
                continue_status = DBG_CONTINUE;
            }
            RIP_EVENT => {
                println!("  RIP_EVENT (System Error)");
                let info = unsafe { debug_event.u.RipInfo };
                println!("    Error: {:#0x}", info.dwError);
                println!("    Type: {:#0x}", info.dwType);
                break;
            }
            _ => {
                println!("  Unknown debug event: {}", debug_event.dwDebugEventCode);
                continue_status = DBG_CONTINUE;
            }
        }

        if unsafe {
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status,
            )
        } == FALSE
        {
            let error = unsafe { GetLastError() };
            eprintln!("ContinueDebugEvent failed with error: {}", error);
            break;
        }

        if debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            println!("Debuggee process exited. Exiting debugger.");
            break;
        }
    }

    println!("Cleaning up handles.");
    if !process_info.hProcess.is_null() {
        unsafe { CloseHandle(process_info.hProcess) };
    }
    if !process_info.hThread.is_null() {
        unsafe { CloseHandle(process_info.hThread) };
    }

    println!("Debugger finished.");
} 