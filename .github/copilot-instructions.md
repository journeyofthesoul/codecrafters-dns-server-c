# CodeCrafters DNS Server - AI Agent Instructions

This document provides essential context for AI agents working with this DNS server implementation in C.

## Project Overview

This is a DNS server implementation challenge that follows the CodeCrafters curriculum. The server is being built incrementally to support DNS packet parsing, query handling, and recursive resolution.

## Key Components

- **Entry Point**: `src/main.c` contains the core server implementation
- **Build System**: Uses CMake with C23 standard
- **Network Protocol**: UDP-based DNS server running on port 2053

## Development Workflow

1. **Building the Project**:
   ```bash
   cmake -B build
   cmake --build build
   ```

2. **Running the Server**:
   ```bash
   ./your_program.sh
   ```

3. **Testing Changes**:
   ```bash
   git commit -am "describe your changes"
   git push origin master
   ```

## Code Conventions

1. **Error Handling**: All socket operations and memory allocations must check for errors and provide appropriate error messages using `printf` with `strerror(errno)`.

2. **Buffer Management**: The program uses output buffering disabled (`setbuf(stdout, NULL)`) for immediate log visibility during testing.

3. **Socket Configuration**: Always set `SO_REUSEPORT` option on sockets to handle frequent server restarts during testing.

## Key Integration Points

1. **DNS Packet Handling**:
   - Header parsing/creation in network byte order
   - Query/response message formatting
   - Record type handling (A, AAAA, CNAME, etc.)

2. **Network Interface**:
   - UDP socket binding to all interfaces (INADDR_ANY)
   - Port 2053 for testing (standard DNS uses 53)

## Common Patterns

- Use `printf()` for debug logging - logs are visible in test output
- Memory management should use explicit allocation/deallocation
- Network byte order conversion using `htons`/`htonl` for protocol conformance

## Reference Files

- `src/main.c`: Primary implementation file with main server loop and packet handling
- `CMakeLists.txt`: Build configuration and project settings
- `your_program.sh`: Wrapper script for building and running the server