use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
    Debugger, DebugEvent, ContinueDecision, LaunchedProcessInfo
};
use crate::windows::WindowsDebugger;
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

// Session management
struct DebugSession {
    debugger: Box<dyn Debugger>,
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

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// API handlers
async fn launch_process(
    State(state): State<AppState>,
    Json(request): Json<LaunchRequest>,
) -> Result<Json<LaunchResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Launch request received: {:?}", request);
    
    let session_id = Uuid::new_v4().to_string();
    let mut debugger: Box<dyn Debugger> = Box::new(WindowsDebugger::new());
    
    match debugger.launch(&request.command) {
        Ok(process_info) => {
            let session = DebugSession {
                debugger,
            };
            
            {
                let mut sessions = state.sessions.lock().unwrap();
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
                    error: format!("Failed to launch process: {}", e),
                }),
            ))
        }
    }
}

async fn wait_for_event(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<WaitForEventResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Wait for event request for session: {}", session_id);
    
    let mut sessions = state.sessions.lock().unwrap();
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
                    error: format!("Failed to wait for event: {}", e),
                }),
            ))
        }
    }
}

async fn continue_event(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<ContinueEventRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Continue event request for session {}: {:?}", session_id, request);
    
    let mut sessions = state.sessions.lock().unwrap();
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
                    error: format!("Failed to continue event: {}", e),
                }),
            ))
        }
    }
}

async fn detach_debugger(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    info!("Detach request for session: {}", session_id);
    
    let mut sessions = state.sessions.lock().unwrap();
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
            info!("Debugger detached successfully for session {}", session_id);
            Ok(Json(()))
        }
        Err(e) => {
            error!("Failed to detach debugger in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to detach debugger: {}", e),
                }),
            ))
        }
    }
}

async fn read_memory(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<ReadMemoryRequest>,
) -> Result<Json<ReadMemoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Read memory request for session {}: {:?}", session_id, request);
    
    // Parse address from hex string
    let address = if request.address.starts_with("0x") || request.address.starts_with("0X") {
        usize::from_str_radix(&request.address[2..], 16)
    } else {
        request.address.parse::<usize>()
    };
    
    let address = match address {
        Ok(addr) => addr,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            ));
        }
    };
    
    let sessions = state.sessions.lock().unwrap();
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
    
    match session.debugger.read_process_memory(request.process_id, address, request.size) {
        Ok(data) => {
            debug!("Read {} bytes from address 0x{:X} in session {}", data.len(), address, session_id);
            Ok(Json(ReadMemoryResponse { data }))
        }
        Err(e) => {
            error!("Failed to read memory in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to read memory: {}", e),
                }),
            ))
        }
    }
}

async fn write_memory(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<WriteMemoryRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Write memory request for session {}: {:?}", session_id, request);
    
    // Parse address from hex string
    let address = if request.address.starts_with("0x") || request.address.starts_with("0X") {
        usize::from_str_radix(&request.address[2..], 16)
    } else {
        request.address.parse::<usize>()
    };
    
    let address = match address {
        Ok(addr) => addr,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            ));
        }
    };
    
    let mut sessions = state.sessions.lock().unwrap();
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
    
    match session.debugger.write_process_memory(request.process_id, address, &request.data) {
        Ok(()) => {
            debug!("Wrote {} bytes to address 0x{:X} in session {}", request.data.len(), address, session_id);
            Ok(Json(()))
        }
        Err(e) => {
            error!("Failed to write memory in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to write memory: {}", e),
                }),
            ))
        }
    }
}

async fn disassemble_memory(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<DisassembleRequest>,
) -> Result<Json<DisassembleResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Disassemble memory request for session {}: {:?}", session_id, request);
    
    // Parse address from hex string
    let address = if request.address.starts_with("0x") || request.address.starts_with("0X") {
        usize::from_str_radix(&request.address[2..], 16)
    } else {
        request.address.parse::<usize>()
    };
    
    let address = match address {
        Ok(addr) => addr,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            ));
        }
    };

    // Get the architecture to use
    let arch = request.architecture.unwrap_or_else(Architecture::current);

    // Create disassembler
    let disassembler = match DisassemblerFactory::create(arch) {
        Ok(dis) => dis,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create disassembler: {}", e),
                }),
            ));
        }
    };

    // Read memory from the debugged process
    let sessions = state.sessions.lock().unwrap();
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

    let memory_data = match session.debugger.read_process_memory(request.process_id, address, request.size) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to read memory for disassembly in session {}: {}", session_id, e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to read memory: {}", e),
                }),
            ));
        }
    };

    // Disassemble the memory
    match disassembler.disassemble(&memory_data, address, request.max_instructions) {
        Ok(result) => {
            debug!("Disassembled {} instructions starting at 0x{:X} in session {}", 
                   result.instructions.len(), address, session_id);
            Ok(Json(DisassembleResponse { result }))
        }
        Err(e) => {
            error!("Failed to disassemble memory in session {}: {}", session_id, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to disassemble memory: {}", e),
                }),
            ))
        }
    }
}

async fn list_sessions(
    State(state): State<AppState>,
) -> Json<Vec<String>> {
    let sessions = state.sessions.lock().unwrap();
    let session_ids: Vec<String> = sessions.keys().cloned().collect();
    Json(session_ids)
}

pub fn create_router() -> Router {
    let state = AppState::new();
    
    Router::new()
        .route("/launch", post(launch_process))
        .route("/sessions/:session_id/wait_event", get(wait_for_event))
        .route("/sessions/:session_id/continue", post(continue_event))
        .route("/sessions/:session_id/detach", post(detach_debugger))
        .route("/sessions/:session_id/read_memory", post(read_memory))
        .route("/sessions/:session_id/write_memory", post(write_memory))
        .route("/sessions/:session_id/disassemble", post(disassemble_memory))
        .route("/sessions", get(list_sessions))
        .with_state(state)
}

pub async fn run_server(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = create_router();
    
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("Debug server running on http://127.0.0.1:{}", port);
    
    axum::serve(listener, app).await?;
    Ok(())
} 