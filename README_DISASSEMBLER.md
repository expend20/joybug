# Disassembler API Documentation

The JoyBug debugger includes a powerful disassembler that supports both x64 and ARM64 architectures using the Capstone disassembly framework. The disassembler module follows the same design patterns as the debugger interface, providing consistent error handling, serialization, and API design.

## Features

- **Multi-Architecture Support**: x64 and ARM64/AArch64
- **Consistent Interface**: Follows the same patterns as `debugger_interface.rs`
- **Robust Error Handling**: Comprehensive error types with detailed messages
- **HTTP API Integration**: Seamless integration with the debug server
- **Detailed Output**: Instruction addresses, bytes, mnemonics, and operands
- **Configurable**: Limit number of instructions, specify architecture
- **Serialization Support**: Consistent address serialization with the rest of the system

## Architecture Support

### x64 (Intel/AMD 64-bit)
- Intel syntax by default
- Maximum instruction size: 15 bytes
- Supports all modern x64 instruction sets
- Uses Capstone x86-64 engine

### ARM64/AArch64
- ARM syntax
- Fixed instruction size: 4 bytes
- Supports ARMv8 instruction set
- Uses Capstone ARM64 engine

## Error Handling

The disassembler provides comprehensive error handling consistent with the debugger interface:

```rust
use joybug::disassembler::DisassemblyError;

match disasm.disassemble(bytes, address, None) {
    Ok(result) => { /* handle success */ },
    Err(DisassemblyError::UnsupportedArchitecture(arch)) => {
        eprintln!("Architecture {:?} not supported", arch);
    },
    Err(DisassemblyError::EngineError(msg)) => {
        eprintln!("Disassembly engine error: {}", msg);
    },
    Err(DisassemblyError::InvalidInstruction { address, reason }) => {
        eprintln!("Invalid instruction at 0x{:X}: {}", address, reason);
    },
    Err(DisassemblyError::InsufficientData { needed, available }) => {
        eprintln!("Need {} bytes, got {}", needed, available);
    },
    Err(DisassemblyError::InitializationFailed(msg)) => {
        eprintln!("Engine initialization failed: {}", msg);
    },
    Err(e) => eprintln!("Other error: {}", e),
}
```

## HTTP API Usage

### Disassemble Memory

**Endpoint**: `POST /sessions/{session_id}/disassemble`

**Request Body**:
```json
{
    "process_id": 1234,
    "address": "0x401000",
    "size": 64,
    "max_instructions": 10,
    "architecture": "X64"
}
```

**Parameters**:
- `process_id`: Process ID to read memory from
- `address`: Starting address (hex string with consistent serialization)
- `size`: Number of bytes to read
- `max_instructions`: Maximum instructions to disassemble (optional)
- `architecture`: "X64" or "Arm64" (optional, auto-detects if not specified)

**Response**:
```json
{
    "result": {
        "start_address": "0x401000",
        "instructions": [
            {
                "address": "0x401000",
                "bytes": [72, 137, 216],
                "mnemonic": "mov",
                "operands": "rax, rbx",
                "size": 3
            },
            {
                "address": "0x401003",
                "bytes": [144],
                "mnemonic": "nop",
                "operands": "",
                "size": 1
            }
        ],
        "bytes_disassembled": 4
    }
}
```

## Programmatic Usage

### Creating a Disassembler

```rust
use joybug::disassembler::{CapstoneDisassembler, DisassemblerFactory};
use joybug::arch::Architecture;

// Create for specific architecture
let disasm = CapstoneDisassembler::new(Architecture::X64)?;

// Use factory pattern (recommended)
let disasm = DisassemblerFactory::create(Architecture::X64)?;

// Auto-detect current architecture
let disasm = CapstoneDisassembler::current_arch()?;
let disasm = DisassemblerFactory::create_current_arch()?;

// Check supported architectures
let supported = DisassemblerFactory::supported_architectures();
let is_supported = DisassemblerFactory::is_supported(Architecture::X64);
```

### Disassembling Instructions

```rust
// Disassemble all instructions
let bytes = &[0x48, 0x89, 0xd8, 0x90]; // mov rax, rbx; nop
let result = disasm.disassemble(bytes, 0x401000, None)?;

// Disassemble limited number of instructions
let result = disasm.disassemble(bytes, 0x401000, Some(1))?;

// Disassemble single instruction
let (instruction, consumed) = disasm.disassemble_single(bytes, 0x401000)?;

// Check disassembler capabilities
let arch = disasm.architecture();
let max_size = disasm.max_instruction_size();
let supports_x64 = disasm.supports_architecture(Architecture::X64);
```

### Working with Results

```rust
for instruction in result.instructions {
    println!("{}", instruction); // Uses Display trait for formatted output
    println!("Address: 0x{:X}", instruction.address);
    println!("Mnemonic: {}", instruction.mnemonic);
    println!("Operands: {}", instruction.operands);
    println!("Bytes: {:?}", instruction.bytes);
    println!("Size: {} bytes", instruction.size);
}

// Access metadata
println!("Start address: 0x{:X}", result.start_address);
println!("Total bytes disassembled: {}", result.bytes_disassembled);
println!("Instructions found: {}", result.instructions.len());
```

## Trait Implementation

The `Disassembler` trait provides a clean, architecture-agnostic interface:

```rust
use joybug::disassembler::Disassembler;

fn analyze_code(disasm: &dyn Disassembler, bytes: &[u8], addr: usize) {
    println!("Using {} disassembler", disasm.architecture());
    println!("Max instruction size: {} bytes", disasm.max_instruction_size());
    
    match disasm.disassemble(bytes, addr, Some(5)) {
        Ok(result) => {
            for insn in result.instructions {
                println!("{}", insn);
            }
        },
        Err(e) => eprintln!("Disassembly failed: {}", e),
    }
}
```

## Integration with Debug Client

```rust
use joybug::debug_client::AsyncDebugClient;
use joybug::arch::Architecture;

let mut client = AsyncDebugClient::new("http://127.0.0.1:8080".to_string());

// Launch and attach to process
let process_info = client.launch("notepad.exe").await?;

// Disassemble memory at entry point
let result = client.disassemble(
    process_info.process_id,
    0x401000,           // address
    64,                 // size in bytes
    Some(10),           // max 10 instructions
    Some(Architecture::X64)
).await?;

for instruction in result.instructions {
    println!("{}", instruction);
}
```

## Serialization

The disassembler uses consistent address serialization with the debugger interface:

- Addresses are serialized as hex strings (e.g., "0x401000")
- Both "0x" and "0X" prefixes are supported for deserialization
- Consistent with `debugger_interface.rs` patterns

## Example Output

```
0x00401000: 48 89 d8         mov rax, rbx
0x00401003: 90               nop
0x00401004: 48 83 c0 01      add rax, 1
0x00401008: c3               ret
```

## Testing

Run the disassembler tests:

```bash
cargo test --test disassembler_test
```

The test suite includes:
- Basic x64 and ARM64 disassembly
- Single instruction disassembly
- Instruction count limiting
- Comprehensive multi-instruction sequences
- Error handling scenarios
- Display formatting validation
- Factory pattern usage
- Architecture support verification

## Design Patterns

The disassembler module follows the same design patterns as `debugger_interface.rs`:

1. **Error-First Design**: Comprehensive error types defined first
2. **Consistent Documentation**: Detailed rustdoc comments
3. **Trait-Based Architecture**: Clean separation of interface and implementation
4. **Factory Pattern**: Convenient creation without implementation details
5. **Serialization Support**: Consistent with the rest of the system
6. **Platform Abstraction**: Architecture-agnostic interface

## Dependencies

- **Capstone**: Industry-standard disassembly framework
- **Serde**: JSON serialization for HTTP API
- **Thiserror**: Consistent error handling patterns

## Performance

The disassembler is optimized for debugging scenarios:
- Fast instruction decoding using Capstone
- Minimal memory allocation
- Efficient byte-to-instruction conversion
- Thread-safe design for concurrent usage
- Consistent with debugger interface performance characteristics 