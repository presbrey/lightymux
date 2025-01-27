package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"os/signal"

	"github.com/caarlos0/env/v11"
	"github.com/fsnotify/fsnotify"
)

// ProxyHandler encapsulates the proxy's functionality
type ProxyHandler struct {
	mux        *http.ServeMux
	configLock sync.RWMutex
}

// Options holds the application configuration
type Options struct {
	HTTPAddr     string `env:"HTTP_ADDR" envDefault:""`
	Verbose      bool   `env:"VERBOSE" envDefault:"false"`
	LogRequests  bool   `env:"LOG_REQUESTS" envDefault:"false"`
	LogResponses bool   `env:"LOG_RESPONSES" envDefault:"false"`
	LogErrors    bool   `env:"LOG_ERRORS" envDefault:"true"`
	LogFile      string `env:"LOG_FILE" envDefault:""`
}

// Logging configuration
var (
	logger *log.Logger
)

func isWebScheme(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func (ph *ProxyHandler) loadConfig(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	newMux := http.NewServeMux()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			continue
		}
		path := parts[0]
		target := parts[1]

		if isWebScheme(target) {
			// Handle remote URL
			nextHop, err := url.Parse(target)
			if err != nil {
				logger.Printf("Error parsing URL %s: %v", target, err)
				continue
			}
			proxy := &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = nextHop.Scheme
					req.URL.Host = nextHop.Host
					req.URL.Path = singleJoiningSlash(nextHop.Path, req.URL.Path)
				},
				ModifyResponse: modifyResponse,
				// ErrorHandler:   errorHandler,
			}
			newMux.Handle(path, proxy)
			logger.Printf("Added remote route: %s -> %s", path, nextHop)
		} else {
			// Handle local filesystem path
			fileInfo, err := os.Stat(target)
			if err != nil {
				logger.Printf("Error accessing path %s: %v", target, err)
				continue
			}

			if fileInfo.IsDir() {
				// Serve directory
				fs := http.FileServer(http.Dir(target))
				newMux.Handle(path, http.StripPrefix(path, fs))
				logger.Printf("Added directory route: %s -> %s", path, target)
			} else {
				// Serve single file
				newMux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, target)
				})
				logger.Printf("Added file route: %s -> %s", path, target)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	ph.configLock.Lock()
	ph.mux = newMux
	ph.configLock.Unlock()

	return nil
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

func modifyResponse(res *http.Response) error {
	if opts.LogResponses {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		logger.Printf("Response: %s", string(body))
		res.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	return nil
}

func (ph *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ph.configLock.RLock()
	defer ph.configLock.RUnlock()

	if opts.LogRequests {
		logger.Printf("Request: %s %s", r.Method, r.RequestURI)
	}
	start := time.Now()
	ph.mux.ServeHTTP(w, r)
	if opts.Verbose {
		logger.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
	}
}

func (ph *ProxyHandler) watchConfig(filename string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Watch the directory containing the config file
	configDir := filepath.Dir(filename)
	err = watcher.Add(configDir)
	if err != nil {
		return err
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Name == filename && (event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create) {
				logger.Println("Config file changed. Reloading...")
				if err := ph.loadConfig(filename); err != nil {
					logger.Printf("Error reloading config: %v", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			logger.Printf("Error watching config file: %v", err)
		}
	}
}

var opts Options

// LightyMux is the main application struct that coordinates all components
type LightyMux struct {
	Options *Options
	handler *ProxyHandler
	server  *http.Server
	logger  *log.Logger
}

// NewLightyMux creates a new LightyMux instance with the given options
func NewLightyMux(opts *Options) (*LightyMux, error) {
	// Setup logging
	var l *log.Logger
	if opts.LogFile != "" {
		logFile, err := os.OpenFile(opts.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("error opening log file: %v", err)
		}
		l = log.New(logFile, "", log.LstdFlags)
	} else {
		l = log.New(os.Stderr, "", log.LstdFlags)
	}

	// Check for PORT environment variable if HTTPAddr is not set
	if opts.HTTPAddr == "" {
		if port := os.Getenv("PORT"); port != "" {
			opts.HTTPAddr = ":" + port
		} else {
			opts.HTTPAddr = ":8080" // Default if neither flag nor env var is set
		}
	}

	return &LightyMux{
		Options: opts,
		handler: &ProxyHandler{},
		logger:  l,
	}, nil
}

// Run starts the LightyMux server with the given configuration file
func (lm *LightyMux) Run(configFile string) error {
	// Set the global logger (temporary until we refactor to remove global state)
	logger = lm.logger

	// Initialize proxy handler with config
	if err := lm.handler.loadConfig(configFile); err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	// Start config file watcher
	go func() {
		if err := lm.handler.watchConfig(configFile); err != nil {
			lm.logger.Printf("Error watching config: %v", err)
		}
	}()

	// Initialize HTTP server
	lm.server = &http.Server{
		Addr:    lm.Options.HTTPAddr,
		Handler: lm.handler,
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		lm.logger.Println("Shutting down server...")
		if err := lm.server.Shutdown(ctx); err != nil {
			lm.logger.Printf("Error during server shutdown: %v", err)
		}
		cancel()
	}()

	lm.logger.Printf("Starting reverse proxy on %s", lm.Options.HTTPAddr)
	if err := lm.server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("error starting server: %v", err)
	}

	return nil
}

func main() {
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

	lm, err := NewLightyMux(&opts)
	if err != nil {
		fmt.Printf("Error initializing LightyMux: %v\n", err)
		os.Exit(1)
	}

	if err := lm.Run(flag.Arg(0)); err != nil {
		fmt.Printf("Error running LightyMux: %v\n", err)
		os.Exit(1)
	}
}
