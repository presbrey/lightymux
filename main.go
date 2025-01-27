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

	"os/signal"

	"github.com/caarlos0/env/v11"
	"github.com/fsnotify/fsnotify"
)

// Options holds the application configuration
type Options struct {
	HTTPAddr     string `env:"HTTP_ADDR" envDefault:""`
	Verbose      bool   `env:"VERBOSE" envDefault:"false"`
	LogRequests  bool   `env:"LOG_REQUESTS" envDefault:"false"`
	LogResponses bool   `env:"LOG_RESPONSES" envDefault:"false"`
	LogErrors    bool   `env:"LOG_ERRORS" envDefault:"true"`
	LogFile      string `env:"LOG_FILE" envDefault:""`
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

	// Set up HTTP server
	l.server = &http.Server{
		Addr:    opts.HTTPAddr,
		Handler: l,
	}

	return l, nil
}

func (lm *LightyMux) newReverseProxy(nextHop *url.URL) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = nextHop.Scheme
			req.URL.Host = nextHop.Host
			req.URL.Path = singleJoiningSlash(nextHop.Path, req.URL.Path)
		},
	}
	if lm.options.LogResponses {
		rp.ModifyResponse = lm.modifyResponse
	}
	return rp
}

func (lm *LightyMux) loadConfig(filename string) error {
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
				lm.logger.Printf("Error parsing URL %s: %v", target, err)
				continue
			}
			proxy := lm.newReverseProxy(nextHop)
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
				// Serve directory
				fs := http.FileServer(http.Dir(target))
				newMux.Handle(path, http.StripPrefix(path, fs))
				lm.logger.Printf("Added directory route: %s -> %s", path, target)
			} else {
				// Serve single file
				fs := http.FileServer(http.Dir(filepath.Dir(target)))
				newMux.Handle(path, http.StripPrefix(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Path = filepath.Base(target)
					fs.ServeHTTP(w, r)
				})))
				lm.logger.Printf("Added file route: %s -> %s", path, target)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
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

func (lm *LightyMux) Run(configFile string) error {
	// Initialize proxy handler with config
	if err := lm.loadConfig(configFile); err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	// Start config file watcher
	if err := lm.watchConfig(configFile); err != nil {
		return err
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

	lm.logger.Printf("Starting reverse proxy on %s", lm.options.HTTPAddr)
	if err := lm.server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("error starting server: %v", err)
	}

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

	if err := lm.Run(flag.Arg(0)); err != nil {
		fmt.Printf("Error running LightyMux: %v\n", err)
		os.Exit(1)
	}
}
