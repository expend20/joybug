use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, debug};
use uuid::Uuid;

use crate::debugger_interface::{
    Debugger, DebugEvent, ContinueDecision, LaunchedProcessInfo, Symbol, Address, SymbolProvider
};
use crate::windows::{WindowsDebugger, windows_symbol_provider::WindowsSymbolProvider};
use crate::arch::Architecture;
use crate::disassembler::{DisassemblerFactory, DisassemblyResult};

// Data structures for API
#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchRequest {
    pub command: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchResponse {
    pub session_id: String,
    pub process_info: LaunchedProcessInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WaitForEventResponse {
    pub event: DebugEvent,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContinueEventRequest {
    pub process_id: u32,
    pub thread_id: u32,
    pub decision: ContinueDecisionRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadMemoryRequest {
    pub process_id: u32,
    pub address: String, // hex string like "0x12345678"
    pub size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadMemoryResponse {
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteMemoryRequest {
    pub process_id: u32,
    pub address: String, // hex string like "0x12345678"
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisassembleRequest {
    pub process_id: u32,
    pub address: String, // hex string like "0x12345678"
    pub size: usize,
    pub max_instructions: Option<usize>,
    pub architecture: Option<Architecture>, // None for auto-detect from current system
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisassembleResponse {
    pub result: DisassemblyResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoadSymbolsRequest {
    pub process_id: u32,
    pub module_path: String,
    pub module_base: Address,
    pub module_size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveRvaRequest {
    pub process_id: u32,
    pub module_path: String,
    pub rva: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveRvaResponse {
    pub symbol: Option<Symbol>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ContinueDecisionRequest {
    Continue,
    HandledException,
    UnhandledException,
}

impl From<ContinueDecisionRequest> for ContinueDecision {
    fn from(decision: ContinueDecisionRequest) -> Self {
        match decision {
            ContinueDecisionRequest::Continue => ContinueDecision::Continue,
            ContinueDecisionRequest::HandledException => ContinueDecision::HandledException,
            ContinueDecisionRequest::UnhandledException => ContinueDecision::UnhandledException,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {
    pub status: String,
}

// Session management
struct DebugSession {
    debugger: Box<dyn Debugger>,
    symbol_provider: Arc<Mutex<WindowsSymbolProvider>>,
}

// We need to manually implement Send for DebugSession because WindowsDebugger contains
// raw pointers from Windows API that are actually safe to send between threads
// since we're only accessing them from the server thread context
unsafe impl Send for DebugSession {}

type Sessions = Arc<Mutex<HashMap<String, DebugSession>>>;

#[derive(Clone)]
pub struct AppState {
    sessions: Sessions,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// API handlers
#[axum::debug_handler]
async fn launch_process(
    State(state): State<AppState>,
    Json(request): Json<LaunchRequest>,
) -> Result<Json<LaunchResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Launch request received: {:?}", request);
    
    let session_id = Uuid::new_v4().to_string();
    let mut debugger: Box<dyn Debugger> = Box::new(WindowsDebugger::new());
    
    match debugger.launch(&request.command) {
        Ok(process_info) => {
            let symbol_provider = match WindowsSymbolProvider::new() {
                Ok(provider) => Arc::new(Mutex::new(provider)),
                Err(e) => {
                    error!("Failed to create symbol provider: {}", e);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to create symbol provider: {e}"),
                        }),
                    ));
                }
            };

            let session = DebugSession {
                debugger,
                symbol_provider,
            };
            
            {
                let mut sessions = state.sessions.lock().await;
                sessions.insert(session_id.clone(), session);
            }
            
            info!("Process launched successfully, session: {}", session_id);
            Ok(Json(LaunchResponse {
                session_id,
                process_info,
            }))
        }
        Err(e) => {
            error!("Failed to launch process: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to launch process: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn wait_for_event(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<WaitForEventResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Wait for event request for session: {}", session_id);
    
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            ));
        }
    };
    
    match session.debugger.wait_for_event() {
        Ok(event) => {
            debug!("Debug event received in session {}: {:?}", session_id, event);
            Ok(Json(WaitForEventResponse {
                event,
            }))
        }
        Err(e) => {
            error!("Failed to wait for event in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to wait for event: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn continue_event(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<ContinueEventRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Continue event request for session {}: {:?}", session_id, request);
    
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            ));
        }
    };
    
    match session.debugger.continue_event(
        request.process_id,
        request.thread_id,
        ContinueDecision::from(request.decision),
    ) {
        Ok(()) => {
            debug!("Continue event successful for session {}", session_id);
            Ok(Json(()))
        }
        Err(e) => {
            error!("Failed to continue event in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to continue event: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn detach_debugger(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    info!("Detach request for session: {}", session_id);
    
    let mut sessions = state.sessions.lock().await;
    let mut session = match sessions.remove(&session_id) {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            ));
        }
    };
    
    match session.debugger.detach() {
        Ok(()) => {
            info!("Detached successfully from session {}", session_id);
            Ok(Json(()))
        }
        Err(e) => {
            error!("Failed to detach in session {}: {}", session_id, e);
            // Even if detach fails, the session is removed.
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to detach: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn read_memory(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<ReadMemoryRequest>,
) -> Result<Json<ReadMemoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Reading memory for session {}: {:?}", session_id, request);
    
    let addr = match usize::from_str_radix(request.address.trim_start_matches("0x"), 16) {
        Ok(a) => a,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            ));
        }
    };

    let sessions = state.sessions.lock().await;
    let session = match sessions.get(&session_id) {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            ));
        }
    };
    
    match session.debugger.read_process_memory(request.process_id, addr, request.size) {
        Ok(data) => {
            debug!("Read {} bytes successfully from session {}", data.len(), session_id);
            Ok(Json(ReadMemoryResponse {
                data,
            }))
        }
        Err(e) => {
            error!("Failed to read memory in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to read memory: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn write_memory(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<WriteMemoryRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Writing memory for session {}: {:?}", session_id, request);
    
    let addr = match usize::from_str_radix(request.address.trim_start_matches("0x"), 16) {
        Ok(a) => a,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            ));
        }
    };
    
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            ));
        }
    };

    match session.debugger.write_process_memory(request.process_id, addr, &request.data) {
        Ok(()) => {
            debug!("Wrote {} bytes successfully to session {}", request.data.len(), session_id);
            Ok(Json(()))
        }
        Err(e) => {
            error!("Failed to write memory in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to write memory: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn disassemble_memory(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<DisassembleRequest>,
) -> Result<Json<DisassembleResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Disassembling memory for session {}: {:?}", session_id, request);

    let addr = match usize::from_str_radix(request.address.trim_start_matches("0x"), 16) {
        Ok(a) => a,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            ));
        }
    };

    // Read memory from the debugged process
    let memory_to_disassemble = {
        let sessions = state.sessions.lock().await;
        let session = match sessions.get(&session_id) {
            Some(s) => s,
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Session not found".to_string(),
                    }),
                ));
            }
        };

        match session.debugger.read_process_memory(request.process_id, addr, request.size) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to read memory for disassembly in session {}: {}", session_id, e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to read memory for disassembly: {e}"),
                    }),
                ));
            }
        }
    };

    // Create disassembler
    let arch = request.architecture.unwrap_or_else(Architecture::current);
    let disassembler = DisassemblerFactory::create(arch).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() }))
    })?;

    // Disassemble the memory
    match disassembler.disassemble(&memory_to_disassemble, addr, request.max_instructions) {
        Ok(result) => {
            Ok(Json(DisassembleResponse {
                result,
            }))
        }
        Err(e) => {
            error!("Failed to disassemble memory in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to disassemble memory: {e}"),
                }),
            ))
        }
    }
}

async fn list_sessions(
    State(state): State<AppState>,
) -> Json<Vec<String>> {
    let sessions = state.sessions.lock().await;
    Json(sessions.keys().cloned().collect())
}

#[axum::debug_handler]
async fn load_symbols(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<LoadSymbolsRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Load symbols request for session {}: {:?}", session_id, request);
    
    let symbol_provider_arc = {
        let sessions = state.sessions.lock().await;
        match sessions.get(&session_id) {
            Some(s) => s.symbol_provider.clone(),
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Session not found".to_string(),
                    }),
                ));
            }
        }
    };
    
    let mut symbol_provider = symbol_provider_arc.lock().await;
    
    match symbol_provider.load_symbols_for_module(&request.module_path, request.module_base, request.module_size).await {
        Ok(()) => {
            debug!("Symbols loaded successfully for module {}", request.module_path);
            Ok(Json(()))
        }
        Err(e) => {
            error!("Failed to load symbols for module {}: {}", request.module_path, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to load symbols: {e}"),
                }),
            ))
        }
    }
}

#[axum::debug_handler]
async fn resolve_rva(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<ResolveRvaRequest>,
) -> Result<Json<ResolveRvaResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Resolve RVA request for session {}: {:?}", session_id, request);
    
    let symbol_provider_arc = {
        let sessions = state.sessions.lock().await;
        match sessions.get(&session_id) {
            Some(s) => s.symbol_provider.clone(),
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Session not found".to_string(),
                    }),
                ));
            }
        }
    };
    
    let symbol_provider = symbol_provider_arc.lock().await;
    
    match symbol_provider.resolve_rva_to_symbol(&request.module_path, request.rva).await {
        Ok(symbol) => {
            Ok(Json(ResolveRvaResponse { symbol }))
        }
        Err(e) => {
            error!("Failed to resolve RVA for module {}: {}", request.module_path, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to resolve RVA: {e}"),
                }),
            ))
        }
    }
}

async fn ping_handler() -> Json<PingResponse> {
    Json(PingResponse {
        status: "ok".to_string(),
    })
}

pub fn create_router() -> Router {
    let state = AppState::new();

    Router::new()
        .route("/ping", get(ping_handler))
        .route("/launch", post(launch_process))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:session_id/wait_event", get(wait_for_event))
        .route("/sessions/:session_id/continue", post(continue_event))
        .route("/sessions/:session_id/detach", post(detach_debugger))
        .route("/sessions/:session_id/read_memory", post(read_memory))
        .route("/sessions/:session_id/write_memory", post(write_memory))
        .route("/sessions/:session_id/disassemble", post(disassemble_memory))
        .route("/sessions/:session_id/load_symbols", post(load_symbols))
        .route("/sessions/:session_id/resolve_rva", post(resolve_rva))
        .with_state(state)
}

pub async fn run_server(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = create_router();
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    info!("Debug server listening on 0.0.0.0:{}", port);
    axum::serve(listener, app).await.unwrap();
    Ok(())
} 