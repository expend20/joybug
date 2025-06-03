pub mod debugger;
pub mod utils;
// pub mod symbols; // Commenting out the old symbols module as per instructions
pub mod windows_symbol_provider; // Added new symbol provider

// Re-export the main types for easier access
pub use debugger::WindowsDebugger;
pub use windows_symbol_provider::WindowsSymbolProvider; // Added re-export 