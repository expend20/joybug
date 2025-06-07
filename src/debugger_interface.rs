use serde::{Deserialize};
use async_trait::async_trait; // Added for SymbolProvider trait

// Platform-agnostic Process and Thread IDs
pub type ProcessId = u32;
pub type ThreadId = u32;
pub type Address = usize; // Using usize for memory addresses

/// Basic information about the launched process.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct LaunchedProcessInfo {
    pub process_id: ProcessId,
    pub thread_id: ThreadId,
}

/// Platform-agnostic representation of a debug event.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DebugEvent {
    ProcessCreated {
        process_id: ProcessId,
        thread_id: ThreadId,
        image_file_name: Option<String>, // Name of the executable file
        #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
        base_of_image: Address,          // Base address of the executable in memory
        size_of_image: Option<usize>,    // Size of the executable in memory
        // Note: Windows provides a file handle here, which we might abstract or ignore for minimality
    },
    ThreadCreated {
        process_id: ProcessId,
        thread_id: ThreadId,
        #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
        start_address: Address, // Starting address of the thread
    },
    ExceptionOccurred {
        process_id: ProcessId,
        thread_id: ThreadId,
        exception_code: i32,         // Platform-specific exception code
        #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
        exception_address: Address,
        is_first_chance: bool,
    },
    BreakpointHit {
        // This is a specific type of exception, often treated specially
        process_id: ProcessId,
        thread_id: ThreadId,
        #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
        address: Address,
    },
    OutputDebugString {
        process_id: ProcessId,
        thread_id: ThreadId,
        message: String,
    },
    DllLoaded {
        process_id: ProcessId,
        thread_id: ThreadId,
        dll_name: Option<String>,
        #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
        base_of_dll: Address,
        size_of_dll: Option<usize>,     // Size of the DLL in memory
    },
    DllUnloaded {
        process_id: ProcessId,
        thread_id: ThreadId,
        #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
        base_of_dll: Address,
    },
    ThreadExited {
        process_id: ProcessId,
        thread_id: ThreadId,
        exit_code: u32,
    },
    ProcessExited {
        process_id: ProcessId,
        thread_id: ThreadId, // Typically the main thread or the thread reporting the event
        exit_code: u32,
    },
    RipEvent { // System integrity event (Windows specific, but good to have a generic placeholder)
        process_id: ProcessId,
        thread_id: ThreadId,
        error: u32,
        event_type: u32,
    },
    Unknown,
}

// Custom serialization functions for addresses
fn serialize_address<S>(addr: &Address, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{addr:X}"))
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).map_err(serde::de::Error::custom)
    } else {
        s.parse::<usize>().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for DebugEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugEvent::ProcessCreated { process_id, thread_id, image_file_name, base_of_image, size_of_image } => f
                .debug_struct("ProcessCreated")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("image_file_name", image_file_name)
                .field("base_of_image", &format_args!("0x{base_of_image:X}"))
                .field("size_of_image", &size_of_image.map(|s| format!("0x{s:X}")))
                .finish(),
            DebugEvent::ThreadCreated { process_id, thread_id, start_address } => f
                .debug_struct("ThreadCreated")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("start_address", &format_args!("0x{start_address:X}"))
                .finish(),
            DebugEvent::ExceptionOccurred { process_id, thread_id, exception_code, exception_address, is_first_chance } => f
                .debug_struct("ExceptionOccurred")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("exception_code", &format_args!("0x{exception_code:08X}"))
                .field("exception_address", &format_args!("0x{exception_address:X}"))
                .field("is_first_chance", is_first_chance)
                .finish(),
            DebugEvent::BreakpointHit { process_id, thread_id, address } => f
                .debug_struct("BreakpointHit")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("address", &format_args!("0x{address:X}"))
                .finish(),
            DebugEvent::OutputDebugString { process_id, thread_id, message } => f
                .debug_struct("OutputDebugString")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("message", message)
                .finish(),
            DebugEvent::DllLoaded { process_id, thread_id, dll_name, base_of_dll, size_of_dll } => f
                .debug_struct("DllLoaded")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("dll_name", dll_name)
                .field("base_of_dll", &format_args!("0x{base_of_dll:X}"))
                .field("size_of_dll", &size_of_dll.map(|s| format!("0x{s:X}")))
                .finish(),
            DebugEvent::DllUnloaded { process_id, thread_id, base_of_dll } => f
                .debug_struct("DllUnloaded")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("base_of_dll", &format_args!("0x{base_of_dll:X}"))
                .finish(),
            DebugEvent::ThreadExited { process_id, thread_id, exit_code } => f
                .debug_struct("ThreadExited")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("exit_code", exit_code)
                .finish(),
            DebugEvent::ProcessExited { process_id, thread_id, exit_code } => f
                .debug_struct("ProcessExited")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("exit_code", exit_code)
                .finish(),
            DebugEvent::RipEvent { process_id, thread_id, error, event_type } => f
                .debug_struct("RipEvent")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("error", error) // Typically a u32, might want hex too if it represents a code
                .field("event_type", event_type) // Typically a u32, might want hex too if it represents a code
                .finish(),
            DebugEvent::Unknown => f.write_str("Unknown"),
        }
    }
}

/// Decision for how to continue after a debug event.
pub enum ContinueDecision {
    Continue,
    HandledException,
    UnhandledException,
}

/// Errors that can occur during debugging operations.
#[derive(Debug)]
#[allow(dead_code)] // Allow unused variants for now
pub enum DebuggerError {
    ProcessLaunchFailed(String),
    WaitForEventFailed(String),
    ContinueEventFailed(String),
    ReadProcessMemoryFailed(String),
    WriteProcessMemoryFailed(String),
    Other(String),
}

impl std::fmt::Display for DebuggerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebuggerError::ProcessLaunchFailed(s) => write!(f, "Process launch failed: {s}"),
            DebuggerError::WaitForEventFailed(s) => write!(f, "Wait for event failed: {s}"),
            DebuggerError::ContinueEventFailed(s) => write!(f, "Continue event failed: {s}"),
            DebuggerError::ReadProcessMemoryFailed(s) => write!(f, "Read process memory failed: {s}"),
            DebuggerError::WriteProcessMemoryFailed(s) => write!(f, "Write process memory failed: {s}"),
            DebuggerError::Other(s) => write!(f, "Debugger error: {s}"),
        }
    }
}

impl std::error::Error for DebuggerError {}

// --- Additions for Symbol Handling ---

/// Errors that can occur during symbol resolution.
#[derive(Debug)]
pub enum SymbolError {
    ProviderNotInitialized,
    ModuleNotLoaded(String), // Module name or path
    SymbolsNotFound(String), // Module name or path for which symbols could not be found/loaded
    SymbolResolutionFailed(String), // Symbol name that failed to resolve
    PdbNotFound(String), // PDB file name or identifier
    PdbParsingFailed(String), // PDB file name or path
    PeParsingFailed(String), // PE file parsing issue
    SymSrvError(String), // Error from symbol server interaction
    IoError(std::io::Error),
    Other(String),
}

impl std::fmt::Display for SymbolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolError::ProviderNotInitialized => write!(f, "Symbol provider not initialized"),
            SymbolError::ModuleNotLoaded(module) => write!(f, "Module not loaded: {module}"),
            SymbolError::SymbolsNotFound(module) => write!(f, "Symbols not found for module: {module}"),
            SymbolError::SymbolResolutionFailed(symbol) => write!(f, "Failed to resolve symbol: {symbol}"),
            SymbolError::PdbNotFound(pdb) => write!(f, "PDB file not found: {pdb}"),
            SymbolError::PdbParsingFailed(pdb) => write!(f, "Failed to parse PDB file: {pdb}"),
            SymbolError::PeParsingFailed(file) => write!(f, "Failed to parse PE file: {file}"),
            SymbolError::SymSrvError(s) => write!(f, "Symbol server error: {s}"),
            SymbolError::IoError(e) => write!(f, "I/O error during symbol operation: {e}"),
            SymbolError::Other(s) => write!(f, "Symbol error: {s}"),
        }
    }
}

impl std::error::Error for SymbolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SymbolError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

/// Represents a symbol with its name and Relative Virtual Address (RVA).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    pub name: String,
    pub rva: u32, // Relative Virtual Address
}

/// Trait defining the interface for a symbol provider.
/// A symbol provider is responsible for loading and querying symbols for modules.
#[async_trait]
pub trait SymbolProvider {
    /// Ensures that symbols for a given module (identified by its path and base address) are loaded.
    /// This might involve downloading PDBs or parsing symbol files.
    async fn load_symbols_for_module(
        &mut self,
        module_path: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), SymbolError>;

    /// Finds a symbol by its name for a specific module.
    async fn find_symbol(
        &self,
        module_path: &str,
        symbol_name: &str,
    ) -> Result<Option<Symbol>, SymbolError>;

    /// Lists all known symbols for a specific module.
    async fn list_symbols(&self, module_path: &str) -> Result<Vec<Symbol>, SymbolError>;

    /// Resolves an RVA to a symbol name for a specific module.
    async fn resolve_rva_to_symbol(
        &self,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<Symbol>, SymbolError>;

    // Optional: Method to get module base address if provider stores it and it's useful.
    // async fn get_module_base(&self, module_path: &str) -> Result<Option<Address>, SymbolError>;
}

// --- End of Additions for Symbol Handling ---

/// Trait defining the debugger interface.
pub trait Debugger {
    /// Launches the specified command as a debuggee.
    /// Returns process information or an error.
    fn launch(&mut self, command: &str) -> Result<LaunchedProcessInfo, DebuggerError>;

    /// Waits for the next debug event from the debuggee.
    /// Returns a platform-agnostic DebugEvent or an error.
    fn wait_for_event(&mut self) -> Result<DebugEvent, DebuggerError>;

    /// Continues the execution of the debuggee after a debug event.
    /// Takes the process ID, thread ID, and a continue decision.
    /// Returns success or an error.
    fn continue_event(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        decision: ContinueDecision,
    ) -> Result<(), DebuggerError>;

    /// Detaches from the debugged process.
    /// This might involve cleaning up handles or sending a detach command.
    /// Optional for a minimal implementation, but good practice.
    fn detach(&mut self) -> Result<(), DebuggerError>;

    /// Reads memory from the debugged process.
    /// Returns a vector of bytes or an error.
    fn read_process_memory(
        &self,
        process_id: ProcessId,
        address: Address,
        size: usize,
    ) -> Result<Vec<u8>, DebuggerError>;

    /// Writes memory to the debugged process.
    /// Returns success or an error.
    fn write_process_memory(
        &mut self,
        process_id: ProcessId,
        address: Address,
        data: &[u8],
    ) -> Result<(), DebuggerError>;

    // Potentially other methods like:
    // fn set_breakpoint(&mut self, process_id: ProcessId, address: Address) -> Result<(), DebuggerError>;
    // fn remove_breakpoint(&mut self, process_id: ProcessId, address: Address) -> Result<(), DebuggerError>;
    // fn get_registers(&self, thread_id: ThreadId) -> Result<Registers, DebuggerError>; // Registers would be another struct
    // fn set_registers(&mut self, thread_id: ThreadId, registers: &Registers) -> Result<(), DebuggerError>;
} 