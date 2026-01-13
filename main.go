package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Options holds the application configuration (env vars and flags)
type Options struct {
	HTTPAddr              string        `env:"HTTP_ADDR" envDefault:""`
	ReadTimeout           time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout          time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	IdleTimeout           time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`
	ProxyTimeout          time.Duration `env:"PROXY_TIMEOUT" envDefault:"60s"`
	ConfigRefreshInterval time.Duration `env:"CONFIG_REFRESH_INTERVAL" envDefault:"1m"`
}

// LogConfig represents logging configuration in YAML
type LogConfig struct {
	Requests  bool   `yaml:"requests,omitempty"`  // Log incoming requests
	Responses bool   `yaml:"responses,omitempty"` // Log outgoing responses
	Errors    bool   `yaml:"errors,omitempty"`    // Log proxy errors
	Verbose   bool   `yaml:"verbose,omitempty"`   // Enable verbose logging
	File      string `yaml:"file,omitempty"`      // Log to file instead of stdout
}

// MuxConfig represents the full YAML configuration
type LightyConfig struct {
	Listen      string                 `yaml:"listen,omitempty"` // Listen address (e.g., "0.0.0.0")
	Port        int                    `yaml:"port,omitempty"`   // Port to listen on
	HealthRoute string                 `yaml:"health,omitempty"` // Health check route path
	Log         LogConfig              `yaml:"log,omitempty"`    // Logging configuration
	Routes      map[string]RouteConfig `yaml:"routes"`
}

// RouteConfig represents a single route configuration
type RouteConfig struct {
	Target string       `yaml:"target"`
	Rules  []RuleConfig `yaml:"rules,omitempty"`
}

// RuleConfig represents rules for request/response modification
type RuleConfig struct {
	Request  RequestConfig  `yaml:"request,omitempty"`
	Response ResponseConfig `yaml:"response,omitempty"`
}

// RequestConfig represents request modification rules
type RequestConfig struct {
	Headers HeaderOperations `yaml:"headers,omitempty"`
}

// ResponseConfig represents response modification rules
type ResponseConfig struct {
	Headers HeaderOperations `yaml:"headers,omitempty"`
}

// HeaderOperations represents the different types of header modifications
type HeaderOperations struct {
	Add map[string]string `yaml:"header-add,omitempty"` // Add values to existing header
	Set map[string]string `yaml:"header-set,omitempty"` // Set header to this value, replacing any existing
	Del []string          `yaml:"header-del,omitempty"` // Delete these headers
}

func isWebScheme(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// parseRouteKey parses a route key into (host, path) components.
// Format: "hostname/path" or just "/path" for wildcard host.
// Examples:
//   - "example.com/api/" -> ("example.com", "/api/")
//   - "/api/" -> ("", "/api/")
//   - "example.com/" -> ("example.com", "/")
func parseRouteKey(key string) (host, path string) {
	if strings.HasPrefix(key, "/") {
		// No hostname, just a path
		return "", key
	}
	// Find the first slash to separate host from path
	idx := strings.Index(key, "/")
	if idx == -1 {
		// No path, treat as host with root path
		return key, "/"
	}
	return key[:idx], key[idx:]
}

// makeRouteKey creates a route key from host and path components.
func makeRouteKey(host, path string) string {
	if host == "" {
		return path
	}
	return host + path
}

// ConfigReloader is an interface for loading and watching configuration
type ConfigReloader interface {
	Load() ([]byte, error)
	Watch(callback func([]byte, error)) error
	Close() error
}

// LocalFileLoader implements ConfigReloader for local files
type LocalReloader struct {
	path    string
	watcher *fsnotify.Watcher
}

func NewLocalReloader(path string) (*LocalReloader, error) {
	return &LocalReloader{path: path}, nil
}

func (l *LocalReloader) Load() ([]byte, error) {
	return os.ReadFile(l.path)
}

func (l *LocalReloader) Watch(callback func([]byte, error)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	l.watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					// Add a small delay to ensure the file write is complete
					time.Sleep(50 * time.Millisecond)
					data, err := l.Load()
					callback(data, err)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				callback(nil, err)
			}
		}
	}()

	return watcher.Add(l.path)
}

func (l *LocalReloader) Close() error {
	if l.watcher != nil {
		return l.watcher.Close()
	}
	return nil
}

// RemoteReloader implements ConfigReloader for HTTP URLs
type RemoteReloader struct {
	url      string
	interval time.Duration
	done     chan struct{}
}

func NewRemoteReloader(url string, interval time.Duration) (*RemoteReloader, error) {
	return &RemoteReloader{
		url:      url,
		interval: interval,
		done:     make(chan struct{}),
	}, nil
}

func (r *RemoteReloader) Load() ([]byte, error) {
	resp, err := http.Get(r.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (h *RemoteReloader) Watch(callback func([]byte, error)) error {
	ticker := time.NewTicker(h.interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				data, err := h.Load()
				callback(data, err)
			case <-h.done:
				ticker.Stop()
				return
			}
		}
	}()
	return nil
}

func (h *RemoteReloader) Close() error {
	close(h.done)
	return nil
}

// NewConfigReloader creates the appropriate ConfigReloader based on the path
func NewConfigReloader(path string, refreshInterval time.Duration) (ConfigReloader, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return NewRemoteReloader(path, refreshInterval)
	}
	return NewLocalReloader(path)
}

// LightyMux is the main application struct that coordinates all components
type LightyMux struct {
	options  *Options
	config   *LightyConfig // Current config (updated on reload)
	logger   *log.Logger
	server   *http.Server
	routes   sync.Map // map[string]http.Handler
	reloader ConfigReloader
}

// NewLightyMux creates a new LightyMux instance with the given options
func NewLightyMux(opts *Options) (*LightyMux, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	l := &LightyMux{
		options: opts,
		logger:  log.New(os.Stdout, "", log.LstdFlags),
	}

	// Set up HTTP server with timeouts
	l.server = &http.Server{
		Handler:      l,
		ReadTimeout:  opts.ReadTimeout,  // 0 means no timeout
		WriteTimeout: opts.WriteTimeout, // 0 means no timeout
		IdleTimeout:  opts.IdleTimeout,  // 0 means no timeout
	}

	return l, nil
}

func (lm *LightyMux) newReverseProxy(nextHop *url.URL) *httputil.ReverseProxy {
	transport := &http.Transport{
		ResponseHeaderTimeout: lm.options.ProxyTimeout,
		MaxIdleConnsPerHost:   100,
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			req.URL.Scheme = nextHop.Scheme
			req.URL.Host = nextHop.Host
			req.URL.Path = singleJoiningSlash(nextHop.Path, req.URL.Path)
			if lm.config != nil && lm.config.Log.Verbose {
				lm.logger.Printf("Proxying request to: %s", req.URL.String())
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if lm.config != nil && lm.config.Log.Responses {
				lm.logger.Printf("Response from %s: status=%d, headers=%v",
					resp.Request.URL.String(), resp.StatusCode, resp.Header)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if lm.config != nil && lm.config.Log.Errors {
				lm.logger.Printf("Proxy error: %v", err)
			}
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Proxy Error: %v", err)
		},
	}

	return rp
}

// handleHealthCheck handles the health check endpoint
func (lm *LightyMux) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

func (lm *LightyMux) initReloader(configPath string) error {
	if lm.reloader == nil {
		reloader, err := NewConfigReloader(configPath, lm.options.ConfigRefreshInterval)
		if err != nil {
			return fmt.Errorf("failed to create config reloader: %v", err)
		}
		data, err := reloader.Load()
		if err != nil {
			return fmt.Errorf("failed to load initial config: %v", err)
		}
		err = lm.processConfig(data)
		if err != nil {
			return fmt.Errorf("failed to process initial config: %v", err)
		}
		lm.reloader = reloader
	}
	return nil
}

func (lm *LightyMux) processConfig(data []byte) error {
	var config LightyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	if err := lm.applyConfig(&config); err != nil {
		return fmt.Errorf("failed to apply config: %v", err)
	}

	// Store config for server binding updates
	lm.config = &config

	return nil
}

func (lm *LightyMux) watchConfig(configPath string) error {
	if err := lm.initReloader(configPath); err != nil {
		return err
	}

	return lm.reloader.Watch(func(data []byte, err error) {
		if err != nil {
			lm.logger.Printf("Error loading config: %v", err)
			return
		}

		if err := lm.processConfig(data); err != nil {
			lm.logger.Printf("Error applying config: %v", err)
		}
	})
}

func (lm *LightyMux) applyConfig(config *LightyConfig) error {
	// Track which keys we're keeping
	newKeys := make(map[string]bool)

	// Add health check endpoint from config
	if config.HealthRoute != "" {
		lm.routes.Store(config.HealthRoute, http.HandlerFunc(lm.handleHealthCheck))
		newKeys[config.HealthRoute] = true
	}

	// Log the config reload
	lm.logger.Printf("Config file modified. Reloading...")

	for path, route := range config.Routes {
		target := route.Target
		if target == "" {
			return fmt.Errorf("route %s: no target specified", path)
		}

		newKeys[path] = true

		if isWebScheme(target) {
			nextHop, err := url.Parse(target)
			if err != nil {
				return fmt.Errorf("route %s: invalid URL %s: %v", path, target, err)
			}
			proxy := lm.newReverseProxy(nextHop)

			if len(route.Rules) > 0 {
				originalDirector := proxy.Director
				proxy.Director = func(req *http.Request) {
					originalDirector(req)
					for _, rule := range route.Rules {
						if rule.Request.Headers.Add != nil {
							for k, v := range rule.Request.Headers.Add {
								req.Header.Add(k, v)
							}
						}
						if rule.Request.Headers.Set != nil {
							for k, v := range rule.Request.Headers.Set {
								req.Header.Set(k, v)
							}
						}
						if rule.Request.Headers.Del != nil {
							for _, k := range rule.Request.Headers.Del {
								req.Header.Del(k)
							}
						}
					}
				}

				originalModifyResponse := proxy.ModifyResponse
				proxy.ModifyResponse = func(resp *http.Response) error {
					if originalModifyResponse != nil {
						if err := originalModifyResponse(resp); err != nil {
							return err
						}
					}

					for _, rule := range route.Rules {
						if rule.Response.Headers.Add != nil {
							for k, v := range rule.Response.Headers.Add {
								resp.Header.Add(k, v)
							}
						}
						if rule.Response.Headers.Set != nil {
							for k, v := range rule.Response.Headers.Set {
								resp.Header.Set(k, v)
							}
						}
						if rule.Response.Headers.Del != nil {
							for _, k := range rule.Response.Headers.Del {
								resp.Header.Del(k)
							}
						}
					}
					return nil
				}
			}

			lm.routes.Store(path, proxy)
			lm.logger.Printf("Added proxy route: %s -> %s", path, target)
		} else {
			// Check if target is a directory or a file
			fileInfo, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("route %s: error accessing path %s: %v", path, target, err)
			}

			if fileInfo.IsDir() {
				// For directories, serve the entire directory
				fs := http.FileServer(http.Dir(target))
				lm.routes.Store(path, http.StripPrefix(path, fs))
				lm.logger.Printf("Added directory route: %s -> %s", path, target)
			} else {
				// For single files, serve the file directly
				lm.routes.Store(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, target)
				}))
				lm.logger.Printf("Added file route: %s -> %s", path, target)
			}
		}
	}

	// Delete routes that no longer exist
	lm.routes.Range(func(key, value any) bool {
		if !newKeys[key.(string)] {
			lm.routes.Delete(key)
		}
		return true
	})

	return nil
}

// GetServerAddr returns the current server address
func (lm *LightyMux) GetServerAddr() string {
	return lm.server.Addr
}

// ServeHTTP implements the http.Handler interface
func (lm *LightyMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if lm.config != nil && lm.config.Log.Requests {
		dump, _ := httputil.DumpRequest(r, true)
		lm.logger.Printf("Request: %s", string(dump))
	}

	// Find the best matching route
	// Priority: host-specific exact > host-specific prefix > wildcard exact > wildcard prefix
	reqPath := r.URL.Path
	reqHost := r.Host
	// Strip port from host if present
	if idx := strings.LastIndex(reqHost, ":"); idx != -1 {
		reqHost = reqHost[:idx]
	}

	var handler http.Handler
	var matchedLen int

	// Try host-specific exact match first
	hostKey := makeRouteKey(reqHost, reqPath)
	if h, ok := lm.routes.Load(hostKey); ok {
		handler = h.(http.Handler)
		matchedLen = len(hostKey)
	}

	// Try wildcard exact match
	if handler == nil {
		if h, ok := lm.routes.Load(reqPath); ok {
			handler = h.(http.Handler)
			matchedLen = len(reqPath)
		}
	}

	// Try prefix matching (longest match wins)
	if handler == nil {
		lm.routes.Range(func(key, value any) bool {
			routeKey := key.(string)
			routeHost, routePath := parseRouteKey(routeKey)

			// Check if route matches
			var matches bool
			if routeHost != "" {
				// Host-specific route
				if routeHost == reqHost && strings.HasSuffix(routePath, "/") {
					matches = strings.HasPrefix(reqPath, routePath) || reqPath+"/" == routePath
				}
			} else {
				// Wildcard route
				if strings.HasSuffix(routePath, "/") {
					matches = strings.HasPrefix(reqPath, routePath) || reqPath+"/" == routePath
				}
			}

			if matches && len(routeKey) > matchedLen {
				matchedLen = len(routeKey)
				handler = value.(http.Handler)
			}
			return true
		})
	}

	if handler != nil {
		handler.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (lm *LightyMux) Run(ctx context.Context, configFile string) error {
	// Watch for config changes
	if err := lm.watchConfig(configFile); err != nil {
		return fmt.Errorf("failed to watch config: %w", err)
	}

	// Build address to listen on
	addr := lm.buildListenAddr()
	if addr == "" {
		return fmt.Errorf("no listen address configured")
	}

	// Create listener
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener on %s: %v", addr, err)
	}

	// Update server address with actual address
	lm.server.Addr = ln.Addr().String()
	lm.logger.Printf("Server started on %s", lm.GetServerAddr())

	// Start server in a goroutine
	go func() {
		if err := lm.server.Serve(ln); err != http.ErrServerClosed {
			lm.logger.Printf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	lm.logger.Println("Shutting down server...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Attempt graceful shutdown
	if err := lm.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	defer func() {
		if lm.reloader != nil {
			lm.reloader.Close()
		}
	}()

	lm.logger.Println("Server gracefully stopped")
	return nil
}

// buildListenAddr builds the address to listen on from config and options
func (lm *LightyMux) buildListenAddr() string {
	// Use config values if available
	if lm.config != nil {
		listen := lm.config.Listen
		if listen == "" {
			listen = "0.0.0.0"
		}

		// Port from config (0 means random port)
		return fmt.Sprintf("%s:%d", listen, lm.config.Port)
	}

	// Fall back to options.HTTPAddr
	return lm.options.HTTPAddr
}

// parseConfig parses command line flags and environment variables into Options
func parseArgs(args []string) (*Options, string, error) {
	opts := new(Options)

	if err := env.Parse(opts); err != nil {
		return nil, "", fmt.Errorf("error parsing env vars: %w", err)
	}

	// Create a new FlagSet for testing purposes
	fs := flag.NewFlagSet("lightymux", flag.ContinueOnError)
	fs.StringVar(&opts.HTTPAddr, "http", opts.HTTPAddr, "HTTP listen address (e.g., :8080)")

	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}

	if fs.NArg() != 1 {
		return nil, "", fmt.Errorf("exactly one config file argument is required")
	}

	return opts, fs.Arg(0), nil
}

func main() {
	opts, configFile, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Printf("Error parsing configuration: %v\n", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		fmt.Printf("Error initializing LightyMux: %v\n", err)
		os.Exit(1)
	}

	if err := lm.Run(context.Background(), configFile); err != nil {
		fmt.Printf("Error running LightyMux: %v\n", err)
		os.Exit(1)
	}
}
