use crate::arch::Architecture;
use crate::debugger_interface::Address;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use capstone::arch::BuildsCapstone;
use capstone::arch::BuildsCapstoneSyntax;

/// Errors that can occur during disassembly operations.
#[derive(Debug, Error)]
pub enum DisassemblyError {
    #[error("Unsupported architecture: {0:?}")]
    UnsupportedArchitecture(Architecture),
    #[error("Disassembly engine error: {0}")]
    EngineError(String),
    #[error("Invalid instruction at address 0x{address:x}: {reason}")]
    InvalidInstruction { address: Address, reason: String },
    #[error("Insufficient data: need at least {needed} bytes, got {available}")]
    InsufficientData { needed: usize, available: usize },
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("Engine initialization failed: {0}")]
    InitializationFailed(String),
}

/// Represents a single disassembled instruction with all its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInstruction {
    /// Address of the instruction
    #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
    pub address: Address,
    /// Raw bytes of the instruction
    pub bytes: Vec<u8>,
    /// Mnemonic (e.g., "mov", "jmp")
    pub mnemonic: String,
    /// Operands (e.g., "rax, rbx")
    pub operands: String,
    /// Size of the instruction in bytes
    pub size: usize,
}

/// Result of a disassembly operation containing multiple instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// Starting address of the disassembly
    #[serde(serialize_with = "serialize_address", deserialize_with = "deserialize_address")]
    pub start_address: Address,
    /// List of disassembled instructions
    pub instructions: Vec<DisassemblyInstruction>,
    /// Total bytes disassembled
    pub bytes_disassembled: usize,
}

/// Trait defining the interface for disassemblers.
/// 
/// This trait provides a platform-agnostic interface for disassembling machine code
/// across different architectures. Implementations should handle architecture-specific
/// details while providing a consistent API.
pub trait Disassembler {
    /// Disassemble a single instruction from the given bytes.
    /// 
    /// # Arguments
    /// * `bytes` - The bytes to disassemble
    /// * `address` - The virtual address of the first byte
    /// 
    /// # Returns
    /// A tuple containing the disassembled instruction and the number of bytes consumed,
    /// or a DisassemblyError if the operation fails.
    fn disassemble_single(
        &self,
        bytes: &[u8],
        address: Address,
    ) -> Result<(DisassemblyInstruction, usize), DisassemblyError>;

    /// Disassemble multiple instructions from the given bytes.
    /// 
    /// # Arguments
    /// * `bytes` - The bytes to disassemble
    /// * `start_address` - The starting address of the first byte
    /// * `max_instructions` - Maximum number of instructions to disassemble (None for all)
    /// 
    /// # Returns
    /// A DisassemblyResult containing all successfully disassembled instructions,
    /// or a DisassemblyError if the operation fails.
    fn disassemble(
        &self,
        bytes: &[u8],
        start_address: Address,
        max_instructions: Option<usize>,
    ) -> Result<DisassemblyResult, DisassemblyError>;

    /// Get the architecture this disassembler supports.
    fn architecture(&self) -> Architecture;

    /// Get the maximum instruction size for this architecture in bytes.
    fn max_instruction_size(&self) -> usize;

    /// Check if this disassembler can handle the given architecture.
    fn supports_architecture(&self, arch: Architecture) -> bool {
        self.architecture() == arch
    }
}

/// Capstone-based disassembler implementation.
/// 
/// This implementation uses the Capstone disassembly framework to provide
/// high-quality disassembly for multiple architectures.
pub struct CapstoneDisassembler {
    engine: capstone::Capstone,
    arch: Architecture,
}

impl CapstoneDisassembler {
    /// Create a new disassembler for the specified architecture.
    /// 
    /// # Arguments
    /// * `arch` - The target architecture
    /// 
    /// # Returns
    /// A new CapstoneDisassembler instance or a DisassemblyError if initialization fails.
    pub fn new(arch: Architecture) -> Result<Self, DisassemblyError> {
        let engine = Self::create_capstone_engine(arch)?;
        Ok(Self { engine, arch })
    }

    /// Create a disassembler for the current system architecture.
    pub fn current_arch() -> Result<Self, DisassemblyError> {
        Self::new(Architecture::current())
    }

    /// Create a Capstone engine for the specified architecture.
    fn create_capstone_engine(arch: Architecture) -> Result<capstone::Capstone, DisassemblyError> {
        let engine = match arch {
            Architecture::X64 => {
                capstone::Capstone::new()
                    .x86()
                    .mode(capstone::arch::x86::ArchMode::Mode64)
                    .syntax(capstone::arch::x86::ArchSyntax::Intel)
                    .detail(true)
                    .build()
                    .map_err(|e| DisassemblyError::InitializationFailed(
                        format!("Failed to create x64 engine: {e}")
                    ))?
            }
            Architecture::Arm64 => {
                capstone::Capstone::new()
                    .arm64()
                    .mode(capstone::arch::arm64::ArchMode::Arm)
                    .detail(true)
                    .build()
                    .map_err(|e| DisassemblyError::InitializationFailed(
                        format!("Failed to create arm64 engine: {e}")
                    ))?
            }
        };

        Ok(engine)
    }

    /// Convert a Capstone instruction to our DisassemblyInstruction format.
    fn convert_instruction(&self, insn: &capstone::Insn) -> DisassemblyInstruction {
        DisassemblyInstruction {
            address: insn.address() as Address,
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
            size: insn.bytes().len(),
        }
    }
}

impl Disassembler for CapstoneDisassembler {
    fn disassemble_single(
        &self,
        bytes: &[u8],
        address: Address,
    ) -> Result<(DisassemblyInstruction, usize), DisassemblyError> {
        if bytes.is_empty() {
            return Err(DisassemblyError::InsufficientData {
                needed: 1,
                available: 0,
            });
        }

        let instructions = self.engine
            .disasm_count(bytes, address as u64, 1)
            .map_err(|e| DisassemblyError::EngineError(format!("Disassembly failed: {e}")))?;

        if instructions.is_empty() {
            return Err(DisassemblyError::InvalidInstruction {
                address,
                reason: "No valid instruction found".to_string(),
            });
        }

        let insn = &instructions[0];
        let instruction = self.convert_instruction(insn);
        let size = instruction.size;
        
        Ok((instruction, size))
    }

    fn disassemble(
        &self,
        bytes: &[u8],
        start_address: Address,
        max_instructions: Option<usize>,
    ) -> Result<DisassemblyResult, DisassemblyError> {
        if bytes.is_empty() {
            return Ok(DisassemblyResult {
                start_address,
                instructions: Vec::new(),
                bytes_disassembled: 0,
            });
        }

        let instructions = match max_instructions {
            Some(count) if count > 0 => {
                self.engine
                    .disasm_count(bytes, start_address as u64, count)
                    .map_err(|e| DisassemblyError::EngineError(format!("Disassembly failed: {e}")))?
            }
            _ => {
                self.engine
                    .disasm_all(bytes, start_address as u64)
                    .map_err(|e| DisassemblyError::EngineError(format!("Disassembly failed: {e}")))?
            }
        };

        let mut result_instructions = Vec::new();
        let mut total_bytes = 0;

        for insn in instructions.iter() {
            let instruction = self.convert_instruction(insn);
            total_bytes += instruction.size;
            result_instructions.push(instruction);
        }

        Ok(DisassemblyResult {
            start_address,
            instructions: result_instructions,
            bytes_disassembled: total_bytes,
        })
    }

    fn architecture(&self) -> Architecture {
        self.arch
    }

    fn max_instruction_size(&self) -> usize {
        match self.arch {
            Architecture::X64 => 15,  // Maximum x86-64 instruction size
            Architecture::Arm64 => 4, // ARM64 instructions are always 4 bytes
        }
    }
}

/// Factory for creating disassemblers.
/// 
/// This factory provides a convenient way to create disassembler instances
/// without needing to know the specific implementation details.
pub struct DisassemblerFactory;

impl DisassemblerFactory {
    /// Create a disassembler for the specified architecture.
    /// 
    /// # Arguments
    /// * `arch` - The target architecture
    /// 
    /// # Returns
    /// A boxed disassembler trait object or a DisassemblyError if creation fails.
    pub fn create(arch: Architecture) -> Result<Box<dyn Disassembler>, DisassemblyError> {
        Ok(Box::new(CapstoneDisassembler::new(arch)?))
    }

    /// Create a disassembler for the current system architecture.
    pub fn create_current_arch() -> Result<Box<dyn Disassembler>, DisassemblyError> {
        Self::create(Architecture::current())
    }

    /// Get a list of supported architectures.
    pub fn supported_architectures() -> Vec<Architecture> {
        vec![Architecture::X64, Architecture::Arm64]
    }

    /// Check if an architecture is supported.
    pub fn is_supported(arch: Architecture) -> bool {
        Self::supported_architectures().contains(&arch)
    }
}

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

impl fmt::Display for DisassemblyInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes_str: String = self.bytes.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        
        write!(f, "0x{:08x}: {:16} {} {}", 
               self.address, 
               bytes_str, 
               self.mnemonic, 
               self.operands)
    }
} 