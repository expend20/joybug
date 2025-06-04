use joybug::disassembler::{
    CapstoneDisassembler, DisassemblerFactory, DisassemblyError, Disassembler
};
use joybug::arch::Architecture;

#[test]
fn test_x64_disassembly() {
    let disasm = CapstoneDisassembler::new(Architecture::X64).unwrap();
    
    // mov rax, rbx (0x48 0x89 0xd8)
    let bytes = &[0x48, 0x89, 0xd8];
    let result = disasm.disassemble(bytes, 0x1000, None).unwrap();
    
    assert_eq!(result.instructions.len(), 1);
    assert_eq!(result.instructions[0].mnemonic, "mov");
    assert_eq!(result.instructions[0].size, 3);
}

#[test]
fn test_arm64_disassembly() {
    let disasm = CapstoneDisassembler::new(Architecture::Arm64).unwrap();
    
    // nop instruction (0x1f 0x20 0x03 0xd5)
    let bytes = &[0x1f, 0x20, 0x03, 0xd5];
    let result = disasm.disassemble(bytes, 0x1000, None).unwrap();
    
    assert_eq!(result.instructions.len(), 1);
    assert_eq!(result.instructions[0].mnemonic, "nop");
    assert_eq!(result.instructions[0].size, 4);
}

#[test]
fn test_disassemble_single() {
    let disasm = CapstoneDisassembler::new(Architecture::X64).unwrap();
    
    let bytes = &[0x48, 0x89, 0xd8, 0x90]; // mov rax, rbx; nop
    let (instruction, consumed) = disasm.disassemble_single(bytes, 0x1000).unwrap();
    
    assert_eq!(instruction.mnemonic, "mov");
    assert_eq!(consumed, 3);
}

#[test]
fn test_max_instructions_limit() {
    let disasm = CapstoneDisassembler::new(Architecture::X64).unwrap();
    
    let bytes = &[0x48, 0x89, 0xd8, 0x90]; // mov rax, rbx; nop
    let result = disasm.disassemble(bytes, 0x1000, Some(1)).unwrap();
    
    assert_eq!(result.instructions.len(), 1);
    assert_eq!(result.instructions[0].mnemonic, "mov");
}

#[test]
fn test_comprehensive_x64_disassembly() {
    let disasm = CapstoneDisassembler::new(Architecture::X64).unwrap();
    
    // A sequence of x64 instructions
    let bytes = &[
        0x48, 0x89, 0xd8,       // mov rax, rbx
        0x90,                   // nop
        0x48, 0x83, 0xc0, 0x01, // add rax, 1
        0xc3,                   // ret
    ];
    
    let result = disasm.disassemble(bytes, 0x401000, None).unwrap();
    
    assert_eq!(result.instructions.len(), 4);
    assert_eq!(result.start_address, 0x401000);
    
    // Check first instruction
    assert_eq!(result.instructions[0].address, 0x401000);
    assert_eq!(result.instructions[0].mnemonic, "mov");
    assert_eq!(result.instructions[0].operands, "rax, rbx");
    assert_eq!(result.instructions[0].size, 3);
    
    // Check second instruction
    assert_eq!(result.instructions[1].address, 0x401003);
    assert_eq!(result.instructions[1].mnemonic, "nop");
    assert_eq!(result.instructions[1].size, 1);
    
    // Check third instruction
    assert_eq!(result.instructions[2].address, 0x401004);
    assert_eq!(result.instructions[2].mnemonic, "add");
    assert_eq!(result.instructions[2].operands, "rax, 1");
    assert_eq!(result.instructions[2].size, 4);
    
    // Check fourth instruction
    assert_eq!(result.instructions[3].address, 0x401008);
    assert_eq!(result.instructions[3].mnemonic, "ret");
    assert_eq!(result.instructions[3].size, 1);
    
    // Check total bytes
    assert_eq!(result.bytes_disassembled, 9);
}

#[test]
fn test_factory_creation() {
    let disasm_x64 = DisassemblerFactory::create(Architecture::X64).unwrap();
    assert_eq!(disasm_x64.architecture(), Architecture::X64);
    assert_eq!(disasm_x64.max_instruction_size(), 15);
    
    let disasm_arm64 = DisassemblerFactory::create(Architecture::Arm64).unwrap();
    assert_eq!(disasm_arm64.architecture(), Architecture::Arm64);
    assert_eq!(disasm_arm64.max_instruction_size(), 4);
}

#[test]
fn test_display_formatting() {
    let disasm = CapstoneDisassembler::new(Architecture::X64).unwrap();
    
    let bytes = &[0x48, 0x89, 0xd8]; // mov rax, rbx
    let result = disasm.disassemble(bytes, 0x401000, None).unwrap();
    
    let instruction_str = format!("{}", result.instructions[0]);
    assert!(instruction_str.contains("0x00401000"));
    assert!(instruction_str.contains("48 89 d8"));
    assert!(instruction_str.contains("mov"));
    assert!(instruction_str.contains("rax, rbx"));
}

#[test]
fn test_error_handling() {
    let disasm = CapstoneDisassembler::new(Architecture::X64).unwrap();
    
    // Test empty bytes
    let result = disasm.disassemble_single(&[], 0x1000);
    assert!(matches!(result, Err(DisassemblyError::InsufficientData { .. })));
    
    // Test invalid instruction bytes
    let invalid_bytes = &[0xff, 0xff, 0xff, 0xff];
    let result = disasm.disassemble_single(invalid_bytes, 0x1000);
    // This might succeed or fail depending on the architecture, but shouldn't panic
    let _ = result;
} 