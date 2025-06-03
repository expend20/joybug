/// Architecture-specific constants and functionality
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X64,
    Arm64,
}

impl Architecture {
    /// Detect the current system architecture
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Architecture::X64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Architecture::Arm64
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            compile_error!("Unsupported architecture: only x86_64 and aarch64 are supported");
        }
    }

    /// Get the breakpoint instruction bytes for this architecture
    pub fn breakpoint_instruction(&self) -> &'static [u8] {
        match self {
            Architecture::X64 => &[0xCC], // int3
            Architecture::Arm64 => &[0x00, 0x00, 0x3E, 0xD4], // brk #0xF000 in little-endian (updated based on user feedback)
        }
    }

    /// Get the nop instruction bytes for this architecture
    pub fn nop_instruction(&self) -> &'static [u8] {
        match self {
            Architecture::X64 => &[0x90], // nop
            Architecture::Arm64 => &[0x1F, 0x20, 0x03, 0xD5], // nop in little-endian
        }
    }

    /// Check if the given bytes match a breakpoint instruction
    pub fn is_breakpoint(&self, bytes: &[u8]) -> bool {
        let bp_instruction = self.breakpoint_instruction();
        bytes.len() >= bp_instruction.len() && bytes[..bp_instruction.len()] == *bp_instruction
    }

    /// Check if the given bytes match a nop instruction
    pub fn is_nop(&self, bytes: &[u8]) -> bool {
        let nop_instruction = self.nop_instruction();
        bytes.len() >= nop_instruction.len() && bytes[..nop_instruction.len()] == *nop_instruction
    }
}
