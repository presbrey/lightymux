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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Options holds the application configuration
type Options struct {
	HTTPAddr      string        `env:"HTTP_ADDR" envDefault:""`
	ReadTimeout   time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout  time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	IdleTimeout   time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`
	ProxyTimeout  time.Duration `env:"PROXY_TIMEOUT" envDefault:"60s"`
	Verbose       bool          `env:"VERBOSE" envDefault:"false"`
	LogRequests   bool          `env:"LOG_REQUESTS" envDefault:"false"`
	LogResponses  bool          `env:"LOG_RESPONSES" envDefault:"false"`
	LogErrors     bool          `env:"LOG_ERRORS" envDefault:"true"`
	LogFile       string        `env:"LOG_FILE" envDefault:""`
	HealthCheck   string        `env:"HEALTH_CHECK" envDefault:"/health"`
	RetryAttempts int           `env:"RETRY_ATTEMPTS" envDefault:"3"`
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

// HeaderOperations represents the different types of header modifications
type HeaderOperations struct {
	Add map[string][]string `yaml:"header-add,omitempty"` // Add values to existing header
	Set map[string]string   `yaml:"header-set,omitempty"` // Set header to this value, replacing any existing
	Del []string            `yaml:"header-del,omitempty"` // Delete these headers
}

// RequestConfig represents request modification rules
type RequestConfig struct {
	Headers HeaderOperations `yaml:"headers,omitempty"`
}

// ResponseConfig represents response modification rules
type ResponseConfig struct {
	Headers HeaderOperations `yaml:"headers,omitempty"`
}

// MuxConfig represents the full YAML configuration
type MuxConfig struct {
	Routes map[string]RouteConfig `yaml:",inline"`
}

func isWebScheme(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// LightyMux is the main application struct that coordinates all components
type LightyMux struct {
	options *Options
	logger  *log.Logger
	server  *http.Server
	mux     *http.ServeMux
	muxLock sync.RWMutex
}

// NewLightyMux creates a new LightyMux instance with the given options
func NewLightyMux(opts *Options) (*LightyMux, error) {
	if opts == nil {
		opts = &Options{}
	}

	// Set default values if not provided
	if opts.HealthCheck == "" {
		opts.HealthCheck = "/health"
	}
	if opts.RetryAttempts == 0 {
		opts.RetryAttempts = 3
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
		mux:     http.NewServeMux(),
		muxLock: sync.RWMutex{},
	}

	// Add health check endpoint
	l.mux.HandleFunc(opts.HealthCheck, l.handleHealthCheck)

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
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if lm.options.LogErrors {
				lm.logger.Printf("Proxy error: %v", err)
			}
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Proxy Error: %v", err)
		},
	}

	if lm.options.LogResponses {
		rp.ModifyResponse = lm.modifyResponse
	}

	return rp
}

// handleHealthCheck handles the health check endpoint
func (lm *LightyMux) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

func (lm *LightyMux) loadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config MuxConfig
	if err := yaml.Unmarshal(data, &config.Routes); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	newMux := http.NewServeMux()

	for path, route := range config.Routes {
		target := route.Target
		if target == "" {
			lm.logger.Printf("Skipping route %s: no target specified", path)
			continue
		}

		if isWebScheme(target) {
			// Handle remote URL
			nextHop, err := url.Parse(target)
			if err != nil {
				lm.logger.Printf("Error parsing URL %s: %v", target, err)
				continue
			}
			proxy := lm.newReverseProxy(nextHop)

			// Apply request/response rules if any
			if len(route.Rules) > 0 {
				originalDirector := proxy.Director
				proxy.Director = func(req *http.Request) {
					originalDirector(req)
					for _, rule := range route.Rules {
						for key, values := range rule.Request.Headers.Add {
							for _, value := range values {
								req.Header.Add(key, value)
							}
						}
						for key, value := range rule.Request.Headers.Set {
							req.Header.Set(key, value)
						}
						for _, key := range rule.Request.Headers.Del {
							req.Header.Del(key)
						}
					}
				}

				originalModifyResponse := proxy.ModifyResponse
				proxy.ModifyResponse = func(res *http.Response) error {
					if originalModifyResponse != nil {
						if err := originalModifyResponse(res); err != nil {
							return err
						}
					}
					for _, rule := range route.Rules {
						for key, values := range rule.Response.Headers.Add {
							for _, value := range values {
								res.Header.Add(key, value)
							}
						}
						for key, value := range rule.Response.Headers.Set {
							res.Header.Set(key, value)
						}
						for _, key := range rule.Response.Headers.Del {
							res.Header.Del(key)
						}
					}
					return nil
				}
			}

			newMux.Handle(path, proxy)
			lm.logger.Printf("Added remote route: %s -> %s", path, nextHop)
		} else {
			// Handle local filesystem path
			fileInfo, err := os.Stat(target)
			if err != nil {
				lm.logger.Printf("Error accessing path %s: %v", target, err)
				continue
			}

			if fileInfo.IsDir() {
				fs := http.FileServer(http.Dir(target))
				newMux.Handle(path, http.StripPrefix(path, fs))
				lm.logger.Printf("Added directory route: %s -> %s", path, target)
			} else {
				fs := http.FileServer(http.Dir(filepath.Dir(target)))
				newMux.Handle(path, http.StripPrefix(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Path = filepath.Base(target)
					fs.ServeHTTP(w, r)
				})))
				lm.logger.Printf("Added file route: %s -> %s", path, target)
			}
		}
	}

	lm.muxLock.Lock()
	lm.mux = newMux
	lm.muxLock.Unlock()

	return nil
}

func (lm *LightyMux) modifyResponse(res *http.Response) error {
	if lm.options.LogResponses {
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			return err
		}
		lm.logger.Printf("Response: %s", string(dump))
	}
	return nil
}

func (lm *LightyMux) watchConfig(filename string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					lm.logger.Printf("Config file modified. Reloading...")
					if err := lm.loadConfig(filename); err != nil {
						lm.logger.Printf("Error reloading config: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				lm.logger.Printf("Error watching config file: %v", err)
			}
		}
	}()

	return watcher.Add(filename)
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
	if err := lm.loadConfig(configFile); err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	if err := lm.watchConfig(configFile); err != nil {
		return fmt.Errorf("failed to watch config: %v", err)
	}

	// Create listener first to get the actual port
	ln, err := net.Listen("tcp", lm.options.HTTPAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	// Update server address with actual address
	lm.server.Addr = ln.Addr().String()
	lm.logger.Printf("Server started on %s", lm.server.Addr)

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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := lm.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	lm.logger.Println("Server gracefully stopped")
	return nil
}

func main() {
	var opts = new(Options)

	if err := env.Parse(&opts); err != nil {
		fmt.Printf("Error parsing env vars: %v\n", err)
		os.Exit(1)
	}

	// Allow command line flags to override env vars
	flag.StringVar(&opts.HTTPAddr, "http", opts.HTTPAddr, "HTTP listen address (e.g., :8080)")
	flag.BoolVar(&opts.Verbose, "verbose", opts.Verbose, "Enable verbose logging")
	flag.BoolVar(&opts.LogRequests, "log-requests", opts.LogRequests, "Log incoming requests")
	flag.BoolVar(&opts.LogResponses, "log-responses", opts.LogResponses, "Log outgoing responses")
	flag.BoolVar(&opts.LogErrors, "log-errors", opts.LogErrors, "Log proxy errors")
	flag.StringVar(&opts.LogFile, "log-file", opts.LogFile, "Log to file instead of stderr")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: ./lightymux [flags] <config_file>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		fmt.Printf("Error initializing LightyMux: %v\n", err)
		os.Exit(1)
	}

	if err := lm.Run(context.Background(), flag.Arg(0)); err != nil {
		fmt.Printf("Error running LightyMux: %v\n", err)
		os.Exit(1)
	}
}
