# Simple STUN/TURN Server

## Overview

This project implements a simple STUN (Session Traversal Utilities for NAT) and TURN (Traversal Using Relays around NAT) server using Go. It's designed to facilitate NAT traversal for peer-to-peer communications, making it easier for applications to establish direct connections between clients behind NATs.

## Features

- Combined STUN and TURN functionality
- Support for both IPv4 and IPv6
- Configurable via command-line flags and config file
- Customizable authentication endpoint
- Logging with adjustable log levels

## Prerequisites

- Go 1.16 or higher
- Make (for using the provided Makefile)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/simple-turn.git
   cd simple-turn
   ```

2. Install dependencies:
   ```
   make deps
   ```

3. Build the project:
   ```
   make build
   ```

## Usage

Run the server using the following command:

```
./simple-turn [flags]
```

Available flags:

- `-config`: Path to configuration file (default "config.json")
- `-realm`: Realm for the TURN/STUN server (default "example.stunserver.com")
- `-ipv4`: IPv4 address and port to bind to (default "0.0.0.0:3478")
- `-ipv6`: IPv6 address and port to bind to (default "[::]:3478")
- `-loglevel`: Log level (debug, info, warn, error) (default "info")
- `-auth-endpoint`: URL to the authentication endpoint
- `-v` or `-version`: Print version and exit

Example:

```
./simple-turn -realm myserver.com -ipv4 0.0.0.0:3478 -loglevel debug -auth-endpoint https://myauth.com/validate
```

## Configuration

You can configure the server using a JSON configuration file. Create a `config.json` file with the following structure:

```json
{
  "realm": "example.stunserver.com",
  "ipv4_bind": "0.0.0.0:3478",
  "ipv6_bind": "[::]:3478",
  "log_level": "info",
  "auth_endpoint": "https://myauth.com/validate"
}
```

## Authentication

The server supports external authentication. Set up your authentication endpoint and provide its URL using the `-auth-endpoint` flag or in the configuration file. The endpoint should accept GET requests with a `token` query parameter and return a 200 OK status for valid tokens.

## Development

- Run tests: `make test`
- Clean build artifacts: `make clean`
- Cross-compile:
  - For Linux: `make build-linux`
  - For Windows: `make build-windows`
  - For macOS: `make build-mac`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
