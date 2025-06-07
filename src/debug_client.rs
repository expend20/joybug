use reqwest::Client;
use tracing::{debug, error, info};

use crate::debugger_interface::{
    Debugger, DebugEvent, ContinueDecision, LaunchedProcessInfo, 
    ProcessId, ThreadId, Address, DebuggerError, Symbol
};
use crate::debug_server::{
    LaunchRequest, LaunchResponse, WaitForEventResponse, ContinueEventRequest,
    ReadMemoryRequest, ReadMemoryResponse, WriteMemoryRequest, ContinueDecisionRequest,
    DisassembleRequest, DisassembleResponse, LoadSymbolsRequest, ResolveRvaRequest, ResolveRvaResponse, PingResponse
};
use crate::arch::Architecture;
use crate::disassembler::DisassemblyResult;

/// A debugger client that communicates with a debug server via HTTP
pub struct DebugClient {
    client: Client,
    base_url: String,
    session_id: Option<String>,
}

/// An async-compatible version of the debugger client
pub struct AsyncDebugClient {
    client: Client,
    base_url: String,
    session_id: Option<String>,
}

impl DebugClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            session_id: None,
        }
    }

    fn convert_local_decision_to_server(decision: ContinueDecision) -> ContinueDecisionRequest {
        match decision {
            ContinueDecision::Continue => ContinueDecisionRequest::Continue,
            ContinueDecision::HandledException => ContinueDecisionRequest::HandledException,
            ContinueDecision::UnhandledException => ContinueDecisionRequest::UnhandledException,
        }
    }
}

impl AsyncDebugClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            session_id: None,
        }
    }

    pub async fn ping(&self) -> Result<(), DebuggerError> {
        debug!("Pinging debug server");

        let response = self.client
            .get(format!("{}/ping", self.base_url))
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send ping request: {}", e);
                DebuggerError::Other(format!("Network error during ping: {e}"))
            })?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Ping request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::Other(format!(
                "Server returned non-success status for ping {status}: {error_text}"
            )));
        }

        let ping_response: PingResponse = response.json().await.map_err(|e| {
            error!("Failed to parse ping response: {}", e);
            DebuggerError::Other(format!("Failed to parse ping response: {e}"))
        })?;

        if ping_response.status == "ok" {
            debug!("Server ping successful.");
            Ok(())
        } else {
            let err_msg = format!("Ping response status was not 'ok': {}", ping_response.status);
            error!("{}", err_msg);
            Err(DebuggerError::Other(err_msg))
        }
    }

    pub async fn launch(&mut self, command: &str) -> Result<LaunchedProcessInfo, DebuggerError> {
        let request = LaunchRequest {
            command: command.to_string(),
        };

        info!("Sending launch request to server: {}", command);

        let response = self.client
            .post(format!("{}/launch", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send launch request: {}", e);
                DebuggerError::ProcessLaunchFailed(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Launch request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::ProcessLaunchFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let launch_response: LaunchResponse = response.json().await.map_err(|e| {
            error!("Failed to parse launch response: {}", e);
            DebuggerError::ProcessLaunchFailed(format!("Failed to parse response: {e}"))
        })?;

        self.session_id = Some(launch_response.session_id.clone());
        info!("Process launched successfully, session: {}", launch_response.session_id);

        Ok(launch_response.process_info)
    }

    pub async fn wait_for_event(&mut self) -> Result<DebugEvent, DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        debug!("Waiting for event in session: {}", session_id);

        let response = self.client
            .get(format!("{}/sessions/{}/wait_event", self.base_url, session_id))
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send wait_for_event request: {}", e);
                DebuggerError::WaitForEventFailed(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Wait for event request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::WaitForEventFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let event_response: WaitForEventResponse = response.json().await.map_err(|e| {
            error!("Failed to parse wait_for_event response: {}", e);
            DebuggerError::WaitForEventFailed(format!("Failed to parse response: {e}"))
        })?;

        debug!("Received debug event: {:?}", event_response.event);

        Ok(event_response.event)
    }

    pub async fn continue_event(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        decision: ContinueDecision,
    ) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let request = ContinueEventRequest {
            process_id,
            thread_id,
            decision: DebugClient::convert_local_decision_to_server(decision),
        };

        debug!("Sending continue event request: {:?}", request);

        let response = self.client
            .post(format!("{}/sessions/{}/continue", self.base_url, session_id))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send continue_event request: {}", e);
                DebuggerError::ContinueEventFailed(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Continue event request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::ContinueEventFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        debug!("Continue event successful");
        Ok(())
    }

    pub async fn detach(&mut self) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        info!("Detaching from session: {}", session_id);

        let response = self.client
            .post(format!("{}/sessions/{}/detach", self.base_url, session_id))
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send detach request: {}", e);
                DebuggerError::Other(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Detach request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::Other(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        self.session_id = None;
        info!("Detached successfully");
        Ok(())
    }

    pub async fn read_process_memory(
        &self,
        process_id: ProcessId,
        address: Address,
        size: usize,
    ) -> Result<Vec<u8>, DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let request = ReadMemoryRequest {
            process_id,
            address: format!("0x{address:X}"),
            size,
        };

        debug!("Sending read memory request: {:?}", request);

        let response = self.client
            .post(format!("{}/sessions/{}/read_memory", self.base_url, session_id))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send read_memory request: {}", e);
                DebuggerError::ReadProcessMemoryFailed(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Read memory request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::ReadProcessMemoryFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let memory_response: ReadMemoryResponse = response.json().await.map_err(|e| {
            error!("Failed to parse read_memory response: {}", e);
            DebuggerError::ReadProcessMemoryFailed(format!("Failed to parse response: {e}"))
        })?;

        debug!("Read {} bytes from memory", memory_response.data.len());
        Ok(memory_response.data)
    }

    pub async fn write_process_memory(
        &mut self,
        process_id: ProcessId,
        address: Address,
        data: &[u8],
    ) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let request = WriteMemoryRequest {
            process_id,
            address: format!("0x{address:X}"),
            data: data.to_vec(),
        };

        debug!("Sending write memory request: {:?}", request);

        let response = self.client
            .post(format!("{}/sessions/{}/write_memory", self.base_url, session_id))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send write_memory request: {}", e);
                DebuggerError::WriteProcessMemoryFailed(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Write memory request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::WriteProcessMemoryFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        debug!("Wrote {} bytes to memory", data.len());
        Ok(())
    }

    pub async fn disassemble(
        &self,
        process_id: ProcessId,
        address: Address,
        size: usize,
        max_instructions: Option<usize>,
        architecture: Option<Architecture>,
    ) -> Result<DisassemblyResult, DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let request = DisassembleRequest {
            process_id,
            address: format!("0x{address:X}"),
            size,
            max_instructions,
            architecture,
        };

        debug!("Sending disassemble request: {:?}", request);

        let response = self.client
            .post(format!("{}/sessions/{}/disassemble", self.base_url, session_id))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send disassemble request: {}", e);
                DebuggerError::Other(format!("Network error: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Disassemble request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::Other(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let disassemble_response: DisassembleResponse = response.json().await.map_err(|e| {
            error!("Failed to parse disassemble response: {}", e);
            DebuggerError::Other(format!("Failed to parse response: {e}"))
        })?;

        debug!("Disassembled {} instructions", disassemble_response.result.instructions.len());
        Ok(disassemble_response.result)
    }

    pub async fn load_symbols_for_module(
        &self,
        process_id: ProcessId,
        module_path: &str,
        module_base: Address,
        module_size: Option<usize>,
    ) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let request = LoadSymbolsRequest {
            process_id,
            module_path: module_path.to_string(),
            module_base,
            module_size,
        };

        debug!("Sending load symbols request: {:?}", request);

        let response = self.client
            .post(format!("{}/sessions/{}/load_symbols", self.base_url, session_id))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send load_symbols request: {}", e);
                DebuggerError::Other(format!("Network error: {e}"))
            })?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Load symbols request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::Other(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        Ok(())
    }

    pub async fn resolve_rva_to_symbol(
        &self,
        process_id: ProcessId,
        module_path: &str,
        rva: u32,
    ) -> Result<Option<Symbol>, DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let request = ResolveRvaRequest {
            process_id,
            module_path: module_path.to_string(),
            rva,
        };

        debug!("Sending resolve rva request: {:?}", request);

        let response = self.client
            .post(format!("{}/sessions/{}/resolve_rva", self.base_url, session_id))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send resolve_rva request: {}", e);
                DebuggerError::Other(format!("Network error: {e}"))
            })?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Resolve rva request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::Other(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let resolve_response: ResolveRvaResponse = response.json().await.map_err(|e| {
            error!("Failed to parse resolve_rva response: {}", e);
            DebuggerError::Other(format!("Failed to parse response: {e}"))
        })?;

        Ok(resolve_response.symbol)
    }
}

impl Debugger for DebugClient {
    fn launch(&mut self, command: &str) -> Result<LaunchedProcessInfo, DebuggerError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DebuggerError::Other(format!("Failed to create runtime: {e}")))?;
        
        let request = LaunchRequest {
            command: command.to_string(),
        };

        info!("Sending launch request to server: {}", command);

        let response = rt.block_on(async {
            self.client
                .post(format!("{}/launch", self.base_url))
                .json(&request)
                .send()
                .await
        });

        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send launch request: {}", e);
                return Err(DebuggerError::ProcessLaunchFailed(format!("Network error: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = rt.block_on(async { response.text().await.unwrap_or_default() });
            error!("Launch request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::ProcessLaunchFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let launch_response: LaunchResponse = rt.block_on(async {
            response.json().await
        }).map_err(|e| {
            error!("Failed to parse launch response: {}", e);
            DebuggerError::ProcessLaunchFailed(format!("Failed to parse response: {e}"))
        })?;

        self.session_id = Some(launch_response.session_id.clone());
        info!("Process launched successfully, session: {}", launch_response.session_id);

        Ok(launch_response.process_info)
    }

    fn wait_for_event(&mut self) -> Result<DebugEvent, DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DebuggerError::Other(format!("Failed to create runtime: {e}")))?;

        debug!("Waiting for event in session: {}", session_id);

        let response = rt.block_on(async {
            self.client
                .get(format!("{}/sessions/{}/wait_event", self.base_url, session_id))
                .send()
                .await
        });

        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send wait_for_event request: {}", e);
                return Err(DebuggerError::WaitForEventFailed(format!("Network error: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = rt.block_on(async { response.text().await.unwrap_or_default() });
            error!("Wait for event request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::WaitForEventFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let event_response: WaitForEventResponse = rt.block_on(async {
            response.json().await
        }).map_err(|e| {
            error!("Failed to parse wait_for_event response: {}", e);
            DebuggerError::WaitForEventFailed(format!("Failed to parse response: {e}"))
        })?;

        debug!("Received debug event: {:?}", event_response.event);

        Ok(event_response.event)
    }

    fn continue_event(
        &mut self,
        process_id: ProcessId,
        thread_id: ThreadId,
        decision: ContinueDecision,
    ) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DebuggerError::Other(format!("Failed to create runtime: {e}")))?;

        let request = ContinueEventRequest {
            process_id,
            thread_id,
            decision: Self::convert_local_decision_to_server(decision),
        };

        debug!("Sending continue event request: {:?}", request);

        let response = rt.block_on(async {
            self.client
                .post(format!("{}/sessions/{}/continue", self.base_url, session_id))
                .json(&request)
                .send()
                .await
        });

        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send continue_event request: {}", e);
                return Err(DebuggerError::ContinueEventFailed(format!("Network error: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = rt.block_on(async { response.text().await.unwrap_or_default() });
            error!("Continue event request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::ContinueEventFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        debug!("Continue event successful");
        Ok(())
    }

    fn detach(&mut self) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DebuggerError::Other(format!("Failed to create runtime: {e}")))?;

        info!("Detaching from session: {}", session_id);

        let response = rt.block_on(async {
            self.client
                .post(format!("{}/sessions/{}/detach", self.base_url, session_id))
                .send()
                .await
        });

        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send detach request: {}", e);
                return Err(DebuggerError::Other(format!("Network error: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = rt.block_on(async { response.text().await.unwrap_or_default() });
            error!("Detach request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::Other(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        self.session_id = None;
        info!("Detached successfully");
        Ok(())
    }

    fn read_process_memory(
        &self,
        process_id: ProcessId,
        address: Address,
        size: usize,
    ) -> Result<Vec<u8>, DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DebuggerError::Other(format!("Failed to create runtime: {e}")))?;

        let request = ReadMemoryRequest {
            process_id,
            address: format!("0x{address:X}"),
            size,
        };

        debug!("Sending read memory request: {:?}", request);

        let response = rt.block_on(async {
            self.client
                .post(format!("{}/sessions/{}/read_memory", self.base_url, session_id))
                .json(&request)
                .send()
                .await
        });

        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send read_memory request: {}", e);
                return Err(DebuggerError::ReadProcessMemoryFailed(format!("Network error: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = rt.block_on(async { response.text().await.unwrap_or_default() });
            error!("Read memory request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::ReadProcessMemoryFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        let memory_response: ReadMemoryResponse = rt.block_on(async {
            response.json().await
        }).map_err(|e| {
            error!("Failed to parse read_memory response: {}", e);
            DebuggerError::ReadProcessMemoryFailed(format!("Failed to parse response: {e}"))
        })?;

        debug!("Read {} bytes from memory", memory_response.data.len());
        Ok(memory_response.data)
    }

    fn write_process_memory(
        &mut self,
        process_id: ProcessId,
        address: Address,
        data: &[u8],
    ) -> Result<(), DebuggerError> {
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| DebuggerError::Other("No active session".to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DebuggerError::Other(format!("Failed to create runtime: {e}")))?;

        let request = WriteMemoryRequest {
            process_id,
            address: format!("0x{address:X}"),
            data: data.to_vec(),
        };

        debug!("Sending write memory request: {:?}", request);

        let response = rt.block_on(async {
            self.client
                .post(format!("{}/sessions/{}/write_memory", self.base_url, session_id))
                .json(&request)
                .send()
                .await
        });

        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send write_memory request: {}", e);
                return Err(DebuggerError::WriteProcessMemoryFailed(format!("Network error: {e}")));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = rt.block_on(async { response.text().await.unwrap_or_default() });
            error!("Write memory request failed with status {}: {}", status, error_text);
            return Err(DebuggerError::WriteProcessMemoryFailed(format!(
                "Server returned status {status}: {error_text}"
            )));
        }

        debug!("Wrote {} bytes to memory", data.len());
        Ok(())
    }
} 