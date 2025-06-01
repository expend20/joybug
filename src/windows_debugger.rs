use super::debugger_interface::*;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, /* TRUE, */ GetLastError, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT, WaitForDebugEvent, OUTPUT_DEBUG_STRING_EVENT,
    CREATE_THREAD_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    RIP_EVENT,
};
#[allow(unused_imports)] use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::{
    PROCESS_INFORMATION, STARTUPINFOW, CreateProcessW, DEBUG_PROCESS, INFINITE,
};
#[allow(unused_imports)] use windows_sys::Win32::System::ProcessStatus::GetProcessImageFileNameW;

#[allow(dead_code)] // Allow dead code for this function
fn to_wide_chars_debugger(s: &str) -> Vec<u16> { 
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[allow(dead_code)] // Allow dead code for this function
fn from_wide_ptr(ptr: *const u16, max_len: usize) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 && len < max_len {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16(slice).ok()
    }
}

pub struct WindowsDebugger {
    process_info: Option<PROCESS_INFORMATION>, // Store process info from CreateProcessW
    // We might need to store other state here, e.g., a list of open file handles for DLLs
    // if we decide not to close them immediately in CREATE_PROCESS_DEBUG_EVENT or LOAD_DLL_DEBUG_EVENT.
}

impl WindowsDebugger {
    pub fn new() -> Self {
        WindowsDebugger {
            process_info: None,
        }
    }

    #[allow(dead_code)] // Allow dead code for this method
    #[allow(unused_variables)] // Allow unused variables for this method
    fn read_debuggee_string(&self, process_handle: HANDLE, address: *const u16, is_unicode: bool, length_chars: u16) -> Option<String> {
        // Reading from debuggee memory is temporarily disabled by user request.
        None
    }
    
    #[allow(unused_variables)] // Allow unused variables for this method
    fn get_file_name_from_handle(&self, file_handle: HANDLE) -> Option<String> {
        // Reading file name from handle is temporarily disabled by user request.
        None
    }

}

impl Debugger for WindowsDebugger {
    fn launch(&mut self, command: &str) -> Result<LaunchedProcessInfo, DebuggerError> {
        let cmd_line_wide = to_wide_chars_debugger(command);
        let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info_raw: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let success = unsafe {
            CreateProcessW(
                ptr::null(),
                cmd_line_wide.as_ptr() as *mut _,
                ptr::null_mut(),
                ptr::null_mut(),
                FALSE, // Inherit handles
                DEBUG_PROCESS,
                ptr::null_mut(), // Environment
                ptr::null(),     // Current directory
                &mut startup_info,
                &mut process_info_raw,
            )
        };

        if success == FALSE {
            let error = unsafe { GetLastError() };
            return Err(DebuggerError::ProcessLaunchFailed(format!(
                "CreateProcessW failed with error: {}",
                error
            )));
        }

        self.process_info = Some(process_info_raw);

        Ok(LaunchedProcessInfo {
            process_id: process_info_raw.dwProcessId,
            thread_id: process_info_raw.dwThreadId,
        })
    }

    #[allow(unused_variables)] // For process_handle
    fn wait_for_event(&mut self) -> Result<DebugEvent, DebuggerError> {
        let mut debug_event_raw: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut debug_event_raw, INFINITE) } == FALSE {
            let error = unsafe { GetLastError() };
            return Err(DebuggerError::WaitForEventFailed(format!(
                "WaitForDebugEvent failed: {}",
                error
            )));
        }

        let current_pid = debug_event_raw.dwProcessId;
        let current_tid = debug_event_raw.dwThreadId;
        let process_handle = self.process_info.as_ref().map_or(ptr::null_mut(), |pi| pi.hProcess);

        match debug_event_raw.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let ex_info = unsafe { debug_event_raw.u.Exception };
                let ex_record = ex_info.ExceptionRecord;
                // Check for EXCEPTION_BREAKPOINT (0x80000003) and EXCEPTION_SINGLE_STEP (0x80000004)
                if ex_record.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_BREAKPOINT {
                    Ok(DebugEvent::BreakpointHit {
                        process_id: current_pid,
                        thread_id: current_tid,
                        address: ex_record.ExceptionAddress as Address,
                    })
                } else {
                     Ok(DebugEvent::ExceptionOccurred {
                        process_id: current_pid,
                        thread_id: current_tid,
                        exception_code: ex_record.ExceptionCode as i32, // Assuming i32 is appropriate
                        exception_address: ex_record.ExceptionAddress as Address,
                        is_first_chance: ex_info.dwFirstChance == 1,
                    })
                }
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { debug_event_raw.u.CreateProcessInfo };
                // It's important to store the hProcess from CreateProcessInfo if it's different
                // from the one returned by CreateProcessW, or if we didn't have one yet.
                // For now, assume self.process_info is the primary one.
                // However, the info.hProcess from CREATE_PROCESS_DEBUG_EVENT is vital for some operations like ReadProcessMemory.
                // For simplicity, we might need to pass this specific hProcess to helper functions if needed.
                
                let image_name = self.get_file_name_from_handle(info.hFile);
                
                // The hFile in CreateProcessInfo should be closed.
                if !info.hFile.is_null() && info.hFile != ptr::null_mut() {
                    unsafe { CloseHandle(info.hFile) };
                }

                Ok(DebugEvent::ProcessCreated {
                    process_id: current_pid,
                    thread_id: current_tid,
                    image_file_name: image_name, 
                    base_of_image: info.lpBaseOfImage as Address,
                })
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let info = unsafe { debug_event_raw.u.ExitProcess };
                Ok(DebugEvent::ProcessExited {
                    process_id: current_pid,
                    thread_id: current_tid, // This is the thread that reported the event
                    exit_code: info.dwExitCode,
                })
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let info = unsafe { debug_event_raw.u.CreateThread };
                // Note: info.hThread is a handle to the new thread. It also needs to be closed eventually.
                // For a minimal abstraction, we might not expose this handle directly.
                // If we did, the user of the trait would be responsible for closing it, or the trait would manage it.
                Ok(DebugEvent::ThreadCreated {
                    process_id: current_pid,
                    thread_id: current_tid, // This is the ID of the new thread
                    start_address: info.lpStartAddress.map_or(0 as Address, |addr| addr as Address),
                })
            }
            EXIT_THREAD_DEBUG_EVENT => {
                let info = unsafe { debug_event_raw.u.ExitThread };
                Ok(DebugEvent::ThreadExited {
                    process_id: current_pid,
                    thread_id: current_tid, // This is the ID of the exiting thread
                    exit_code: info.dwExitCode,
                })
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { debug_event_raw.u.LoadDll };
                let dll_name = None; // Disabled by user request
                // The hFile in LoadDllInfo should be closed.
                if !info.hFile.is_null() && info.hFile != ptr::null_mut() {
                    unsafe { CloseHandle(info.hFile) };
                }
                Ok(DebugEvent::DllLoaded {
                    process_id: current_pid,
                    thread_id: current_tid,
                    dll_name,
                    base_of_dll: info.lpBaseOfDll as Address,
                })
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { debug_event_raw.u.UnloadDll };
                Ok(DebugEvent::DllUnloaded {
                    process_id: current_pid,
                    thread_id: current_tid,
                    base_of_dll: info.lpBaseOfDll as Address,
                })
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                #[allow(unused_variables)] // For info
                let info = unsafe { debug_event_raw.u.DebugString }; 
                let message = "<debug string reading disabled>".to_string(); 
                Ok(DebugEvent::OutputDebugString {
                    process_id: current_pid,
                    thread_id: current_tid,
                    message,
                })
            }
            RIP_EVENT => {
                let info = unsafe { debug_event_raw.u.RipInfo };
                 Ok(DebugEvent::RipEvent {
                    process_id: current_pid,
                    thread_id: current_tid,
                    error: info.dwError,
                    event_type: info.dwType,
                })
            }
            _ => Ok(DebugEvent::Unknown),
        }
    }

    fn continue_event(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        decision: ContinueDecision,
    ) -> Result<(), DebuggerError> {
        let continue_status = match decision {
            ContinueDecision::Continue => DBG_CONTINUE,
            ContinueDecision::HandledException => DBG_CONTINUE, // For Windows, DBG_CONTINUE also implies handled for exceptions
            ContinueDecision::UnhandledException => DBG_EXCEPTION_NOT_HANDLED,
        };

        if unsafe {
            ContinueDebugEvent(
                process_id, // dwProcessId from the original event
                thread_id,  // dwThreadId from the original event
                continue_status,
            )
        } == FALSE
        {
            let error = unsafe { GetLastError() };
            Err(DebuggerError::ContinueEventFailed(format!(
                "ContinueDebugEvent failed: {}",
                error
            )))
        } else {
            Ok(())
        }
    }

    fn detach(&mut self) -> Result<(), DebuggerError> {
        if let Some(pi) = self.process_info.take() { // take() to consume and invalidate
            // We should also detach from debugging if possible, though for DEBUG_PROCESS created processes,
            // termination of the debugger often terminates the debuggee unless specifically detached earlier.
            // DebugActiveProcessStop(pi.dwProcessId); // Needs DebugActiveProcessStop feature

            // Close main process and thread handles obtained from CreateProcessW
            if !pi.hProcess.is_null() && pi.hProcess != ptr::null_mut(){
                unsafe { CloseHandle(pi.hProcess) };
            }
            if !pi.hThread.is_null() && pi.hThread != ptr::null_mut() {
                unsafe { CloseHandle(pi.hThread) };
            }
        }
        // Any other cleanup specific to WindowsDebugger
        Ok(())
    }
}
