# lightymux

A lightweight (1 file), dynamic reverse proxy server with live configuration reloading capabilities. The code can be copied around easily and is good at maintaining long-lived sessions like WebSockets to subdaemons while other upstreams may be restarting like view servers.

## Description

`lightymux` is a lightweight, efficient reverse proxy server written in Go that allows for dynamic configuration updates without requiring server restarts. It's designed to handle HTTP traffic routing with real-time configuration changes, making it ideal for development environments and production systems that require flexible routing rules.

## Features

- Live configuration reloading
- Support for both local and remote proxy targets
- Configurable logging options
- HTTP/HTTPS support
- Path-based routing
- Automatic configuration file watching
- Verbose logging options for debugging

## Installation

```bash
go get github.com/presbrey/lightymux
```

Or clone the repository and build from source:

```bash
git clone https://github.com/presbrey/lightymux.git
cd lightymux
go build
```

## Usage

Basic usage:

```bash
./lightymux [flags] <config_file>
```

### Command Line Flags

- `-http`: HTTP listen address (e.g., ":8080")
- `-verbose`: Enable verbose logging
- `-log-requests`: Log incoming requests
- `-log-responses`: Log outgoing responses
- `-log-errors`: Log proxy errors (default: true)
- `-log-file`: Log to file instead of stderr

### Configuration File Format

The configuration file uses a simple space-separated format where each line contains a path and target:

```
/path target_url_or_path
/api http://api.example.com
/static /var/www/static
```

The configuration file is watched for changes and automatically reloaded when modified.

## Example

1. Create a configuration file `proxy.conf`:
```
/api http://localhost:3000
/static http://localhost:8080
```

2. Start the proxy:
```bash
./lightymux -http :8000 proxy.conf
```

3. The proxy will now forward requests:
   - `/api/*` → `http://localhost:3000/*`
   - `/static/*` → `http://localhost:8080/*`

## License

See [LICENSE](LICENSE) file for details.