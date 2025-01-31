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

// Options holds the application configuration
type Options struct {
	HTTPAddr              string        `env:"HTTP_ADDR" envDefault:""`
	ReadTimeout           time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout          time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	IdleTimeout           time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`
	ProxyTimeout          time.Duration `env:"PROXY_TIMEOUT" envDefault:"60s"`
	ConfigRefreshInterval time.Duration `env:"CONFIG_REFRESH_INTERVAL" envDefault:"1m"`
	Verbose               bool          `env:"VERBOSE" envDefault:"false"`
	LogRequests           bool          `env:"LOG_REQUESTS" envDefault:"false"`
	LogResponses          bool          `env:"LOG_RESPONSES" envDefault:"false"`
	LogErrors             bool          `env:"LOG_ERRORS" envDefault:"true"`
	LogFile               string        `env:"LOG_FILE" envDefault:""`
	HealthRoute           string        `env:"HEALTH_ROUTE" envDefault:""`
}

// MuxConfig represents the full YAML configuration
type LightyConfig struct {
	Routes map[string]RouteConfig `yaml:"routes"`
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
	logger   *log.Logger
	server   *http.Server
	mux      *http.ServeMux
	muxLock  sync.RWMutex
	reloader ConfigReloader
}

// NewLightyMux creates a new LightyMux instance with the given options
func NewLightyMux(opts *Options) (*LightyMux, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Configure logging
	var logWriter io.Writer = os.Stdout
	if opts.LogFile != "" {
		file, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logWriter = file
	}

	l := &LightyMux{
		options: opts,
		logger:  log.New(logWriter, "", log.LstdFlags),
		muxLock: sync.RWMutex{},
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
			if lm.options.Verbose {
				lm.logger.Printf("Proxying request to: %s", req.URL.String())
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if lm.options.LogResponses {
				lm.logger.Printf("Response from %s: status=%d, headers=%v",
					resp.Request.URL.String(), resp.StatusCode, resp.Header)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if lm.options.LogErrors {
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
	newMux := http.NewServeMux()

	// Add health check endpoint only if HealthRoute is non-blank
	if lm.options.HealthRoute != "" {
		newMux.HandleFunc(lm.options.HealthRoute, lm.handleHealthCheck)
	}

	// Log the config reload
	lm.logger.Printf("Config file modified. Reloading...")

	for path, route := range config.Routes {
		target := route.Target
		if target == "" {
			return fmt.Errorf("route %s: no target specified", path)
		}

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

			newMux.Handle(path, proxy)
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
				newMux.Handle(path, http.StripPrefix(path, fs))
				lm.logger.Printf("Added directory route: %s -> %s", path, target)
			} else {
				// For single files, serve the file directly
				newMux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, target)
				}))
				lm.logger.Printf("Added file route: %s -> %s", path, target)
			}
		}
	}

	// Replace the old mux with the new one atomically
	lm.muxLock.Lock()
	lm.mux = newMux
	lm.muxLock.Unlock()

	return nil
}

// GetServerAddr returns the current server address in a thread-safe manner
func (lm *LightyMux) GetServerAddr() string {
	lm.muxLock.RLock()
	defer lm.muxLock.RUnlock()
	return lm.server.Addr
}

// ServeHTTP implements the http.Handler interface
func (lm *LightyMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if lm.options.LogRequests {
		dump, _ := httputil.DumpRequest(r, true)
		lm.logger.Printf("Request: %s", string(dump))
	}
	lm.muxLock.RLock()
	mux := lm.mux
	lm.muxLock.RUnlock()
	mux.ServeHTTP(w, r)
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

	lm.logger.Printf("Starting server on %s", lm.options.HTTPAddr)

	// Create listener first to get the actual port
	ln, err := net.Listen("tcp", lm.options.HTTPAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	// Update server address with actual address
	lm.muxLock.Lock()
	lm.server.Addr = ln.Addr().String()
	lm.muxLock.Unlock()

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

// parseConfig parses command line flags and environment variables into Options
func parseArgs(args []string) (*Options, string, error) {
	opts := new(Options)

	if err := env.Parse(opts); err != nil {
		return nil, "", fmt.Errorf("error parsing env vars: %w", err)
	}

	// Create a new FlagSet for testing purposes
	fs := flag.NewFlagSet("lightymux", flag.ContinueOnError)
	fs.StringVar(&opts.HTTPAddr, "http", opts.HTTPAddr, "HTTP listen address (e.g., :8080)")
	fs.BoolVar(&opts.Verbose, "verbose", opts.Verbose, "Enable verbose logging")
	fs.BoolVar(&opts.LogRequests, "log-requests", opts.LogRequests, "Log incoming requests")
	fs.BoolVar(&opts.LogResponses, "log-responses", opts.LogResponses, "Log outgoing responses")
	fs.BoolVar(&opts.LogErrors, "log-errors", opts.LogErrors, "Log proxy errors")
	fs.StringVar(&opts.LogFile, "log-file", opts.LogFile, "Log to file instead of stderr")

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
