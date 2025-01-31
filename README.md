[![Go Report Card](https://goreportcard.com/badge/github.com/presbrey/lightymux)](https://goreportcard.com/report/github.com/presbrey/lightymux)
[![codecov](https://codecov.io/gh/presbrey/lightymux/graph/badge.svg?token=17BSEJBWVZ)](https://codecov.io/gh/presbrey/lightymux)
[![Go](https://github.com/presbrey/lightymux/actions/workflows/go.yml/badge.svg)](https://github.com/presbrey/lightymux/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/presbrey/lightymux.svg)](https://pkg.go.dev/github.com/presbrey/lightymux)

# lightymux

A lightweight (1 file), dynamic reverse proxy server with live configuration reloading capabilities. The code can be copied around easily and is good at maintaining long-lived sessions like WebSockets to subdaemons while other upstreams may be restarting like view servers.

## Description

`lightymux` is a lightweight, efficient reverse proxy server written in Go that allows for dynamic configuration updates without requiring server restarts. It's designed to handle HTTP traffic routing with real-time configuration changes, making it ideal for development environments and production systems that require flexible routing rules.

## Features

- Live configuration reloading with file watching
- Support for HTTP/HTTPS proxy targets
- Static file and directory serving
- Request/Response header modification
- Configurable timeouts and retries
- Comprehensive logging options
- Graceful shutdown support
- Health check endpoint
- Environment variable configuration

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

## Configuration

### Environment Variables

- `HTTP_ADDR`: HTTP listen address (default: "")
- `READ_TIMEOUT`: Read timeout duration (default: 30s)
- `WRITE_TIMEOUT`: Write timeout duration (default: 30s)
- `IDLE_TIMEOUT`: Idle timeout duration (default: 60s)
- `PROXY_TIMEOUT`: Proxy timeout duration (default: 60s)
- `VERBOSE`: Enable verbose logging (default: false)
- `LOG_REQUESTS`: Log incoming requests (default: false)
- `LOG_RESPONSES`: Log outgoing responses (default: false)
- `LOG_ERRORS`: Log proxy errors (default: true)
- `LOG_FILE`: Log to file instead of stderr
- `HEALTH_ROUTE`: Health check route path (default: "/health")

### Configuration File Format

The configuration file uses YAML format. Each route is defined by its path and target configuration:

```yaml
routes:
  /api:
    target: http://api.example.com
    rules:
      - request:
          headers:
            X-API-Key: secret-key
      - response:
          headers:
            Access-Control-Allow-Origin: "*"

  /static:
    target: /var/www/static

  /files:
    target: /path/to/files
```

Routes can be configured for:
- Remote HTTP/HTTPS endpoints
- Local directories (static file serving)
- Single files

#### Header Modification

You can modify request and response headers for each route using three operations:

- `header-add`: Add values to existing headers (supports multiple values)
- `header-set`: Set headers to specific values, replacing any existing ones
- `header-del`: Remove headers completely

Example:

```yaml
/api:
  target: http://api.example.com
  rules:
    - request:
        headers:
          header-add:
            Accept: ["application/json", "text/plain"]
            X-Custom: ["value1", "value2"]
          header-set:
            Authorization: "Bearer token123"
            Content-Type: "application/json"
          header-del:
            - "X-Old-Header"
            - "X-Deprecated"
    - response:
        headers:
          header-add:
            Access-Control-Allow-Methods: ["GET", "POST", "OPTIONS"]
          header-set:
            Access-Control-Allow-Origin: "*"
            Cache-Control: "max-age=3600"
          header-del:
            - "X-Internal-Header"
```

In this example:
- Request modifications:
  - Adds multiple values to `Accept` and `X-Custom` headers
  - Sets `Authorization` and `Content-Type` headers to specific values
  - Removes `X-Old-Header` and `X-Deprecated` headers
- Response modifications:
  - Adds multiple CORS methods
  - Sets CORS origin and caching headers
  - Removes an internal header

## Usage

Basic usage:

```bash
lightymux [config_file]
```

Example with environment variables:

```bash
HTTP_ADDR=:8080 VERBOSE=true LOG_REQUESTS=true lightymux config.yaml
```

The configuration file is watched for changes and automatically reloaded when modified.

## Example

1. Create a configuration file `config.yaml`:
```yaml
/api:
  target: http://localhost:3000
  rules:
    - response:
        headers:
          Access-Control-Allow-Origin: "*"

/static:
  target: /var/www/static

/docs:
  target: http://localhost:8080
```

2. Start the proxy:
```bash
lightymux config.yaml
```

3. The proxy will now:
   - Forward `/api/*` to `http://localhost:3000/*` with CORS headers
   - Serve static files from `/var/www/static` at `/static/*`
   - Forward `/docs/*` to `http://localhost:8080/*`

## License

See [LICENSE](LICENSE) file for details.