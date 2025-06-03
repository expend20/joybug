use std::path::{Path, PathBuf};
use tokio;
use joybug::debugger_interface::{SymbolProvider, Symbol};
use joybug::windows::windows_symbol_provider::WindowsSymbolProvider;
use joybug::logging;
use std::fs::{File, create_dir_all};
use std::io::{BufWriter, Write};
use tracing::info;
use std::sync::Once;

static INIT_LOGGER: Once = Once::new();

const TEST_MODULE_PATH_STR: &str = "C:\\Windows\\System32\\ntdll.dll";
const TEST_MODULE_BASE_ADDRESS: usize = 0x7ff700000000;

#[tokio::test]
async fn test_notepad_pdb_symbols_to_file() {
    INIT_LOGGER.call_once(|| {
        logging::init_subscriber();
    });

    let module_path = Path::new(TEST_MODULE_PATH_STR);
    let output_symbols_file_path = PathBuf::from("target/ntdll_public_symbols.txt");

    info!(
        module_path = %module_path.display(),
        output_path = %output_symbols_file_path.display(),
        "Starting PDB symbol extraction to file test"
    );

    let mut symbol_provider = WindowsSymbolProvider::new().expect("Failed to create WindowsSymbolProvider");
    info!("WindowsSymbolProvider initialized");

    info!(module_path = %module_path.display(), "Attempting to load symbols for module");
    symbol_provider
        .load_symbols_for_module(TEST_MODULE_PATH_STR, TEST_MODULE_BASE_ADDRESS, None)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Failed to load symbols for '{}': {}",
                module_path.display(),
                e
            );
        });
    info!(module_path = %module_path.display(), "Symbols loaded successfully");
    
    let symbols: Vec<Symbol> = symbol_provider
        .list_symbols(TEST_MODULE_PATH_STR)
        .await
        .unwrap_or_else(|e| {
            panic!("Failed to list symbols for '{}': {}", module_path.display(), e);
        });

    info!(
        count = symbols.len(),
        output_path = %output_symbols_file_path.display(),
        "Writing listed symbols to file"
    );

    if let Some(parent) = output_symbols_file_path.parent() {
        create_dir_all(parent).expect("Failed to create target directory for symbols file");
    }
    let output_file = File::create(&output_symbols_file_path).unwrap_or_else(|e| {
        panic!(
            "Failed to create symbol output file {}: {:?}",
            output_symbols_file_path.display(),
            e
        );
    });
    let mut writer = BufWriter::new(output_file);
    let mut symbol_count = 0;

    for symbol in symbols {
        writeln!(writer, "0x{:08X}: {}", symbol.rva, symbol.name).unwrap_or_else(|e| {
            panic!("Failed to write symbol to output file: {:?}", e);
        });
        symbol_count += 1;
    }

    writer.flush().unwrap_or_else(|e| {
        panic!("Failed to flush symbol output file: {:?}", e);
    });

    info!(
        symbol_count = %symbol_count,
        output_path = %output_symbols_file_path.display(),
        "Symbol extraction to file completed"
    );

    assert!(
        output_symbols_file_path.exists(),
        "Symbol output file should exist at {}", output_symbols_file_path.display()
    );
    assert!(symbol_count > 0, "Expected to write some symbols to the file.");

    info!(module_path = %module_path.display(), "Symbol extraction test completed successfully");
} 