# Debug Server Interface

This project now includes a debug server interface that exposes all debugger functionality via a REST API with JSON communication.

## Architecture

The debug server interface consists of three main components:

1. **Debug Server** (`src/debug_server.rs`) - A web server that exposes debugger functionality via REST API
2. **Debug Client** (`src/debug_client.rs`) - A client that communicates with the debug server via HTTP
3. **Session Management** - The server manages multiple debugging sessions with unique session IDs

## API Endpoints

### Launch Process
- **POST** `/launch`
- **Body**: `{"command": "cmd.exe /c echo Hello World"}`
- **Response**: `{"session_id": "uuid", "process_info": {"process_id": 1234, "thread_id": 5678}}`

### Wait for Debug Event
- **GET** `/sessions/{session_id}/wait_event`
- **Response**: `{"event": {...}}`

### Continue Execution
- **POST** `/sessions/{session_id}/continue`
- **Body**: `{"process_id": 1234, "thread_id": 5678, "decision": "Continue"}`

### Read Process Memory
- **POST** `/sessions/{session_id}/read_memory`
- **Body**: `{"process_id": 1234, "address": "0x12345678", "size": 256}`
- **Response**: `{"data": [...]}`

### Detach Debugger
- **POST** `/sessions/{session_id}/detach`

### List Sessions
- **GET** `/sessions`
- **Response**: `["session-id-1", "session-id-2"]`

## Usage Examples

### Starting the Server

```rust
use joy_bug::debug_server;

#[tokio::main]
async fn main() {
    debug_server::run_server(8080).await.unwrap();
}
```

### Using the Async Client

```rust
use joy_bug::debug_client::AsyncDebugClient;

#[tokio::main]
async fn main() {
    let mut client = AsyncDebugClient::new("http://127.0.0.1:8080".to_string());
    
    // Launch a process
    let process_info = client.launch("cmd.exe /c echo Hello").await.unwrap();
    
    // Debug loop
    loop {
        let event = client.wait_for_event().await.unwrap();
        match event {
            DebugEvent::ProcessExited { .. } => break,
            _ => {
                client.continue_event(
                    process_info.process_id,
                    process_info.thread_id,
                    ContinueDecision::Continue
                ).await.unwrap();
            }
        }
    }
    
    client.detach().await.unwrap();
}
```

### Using the Sync Client (implements Debugger trait)

```rust
use joy_bug::debug_client::DebugClient;
use joy_bug::debugger_interface::Debugger;

fn main() {
    let mut client: Box<dyn Debugger> = Box::new(DebugClient::new("http://127.0.0.1:8080".to_string()));
    
    // Use like any other debugger implementation
    let process_info = client.launch("cmd.exe /c echo Hello").unwrap();
    // ... rest of debugging logic
}
```

## Data Structures

All debug events are serialized to JSON with the following structure:

```json
{
  "type": "ProcessCreated",
  "data": {
    "process_id": 1234,
    "thread_id": 5678,
    "image_file_name": "cmd.exe",
    "base_of_image": "0x7FF123456000",
    "size_of_image": 65536
  }
}
```

Continue decisions are represented as:
- `"Continue"` - Continue normal execution
- `"HandledException"` - Mark exception as handled
- `"UnhandledException"` - Mark exception as unhandled

## Testing

The project includes comprehensive tests:

- `tests/cmd_echo.rs` - Tests direct debugger interface
- `tests/cmd_echo_server.rs` - Tests debug server interface

Both tests perform identical operations to verify that the server interface provides the same functionality as the direct interface.

Run tests with:
```bash
cargo test -- --nocapture
```

## Benefits

1. **Remote Debugging** - Debug processes on remote machines
2. **Language Agnostic** - Any language that can make HTTP requests can use the debugger
3. **Session Management** - Multiple debugging sessions can run concurrently
4. **Scalability** - Server can handle multiple clients
5. **Protocol Independence** - Easy to extend with additional protocols (WebSocket, gRPC, etc.)

## Security Considerations

- The server currently runs on localhost only
- No authentication is implemented
- Consider adding authentication and authorization for production use
- Validate all input parameters to prevent injection attacks 