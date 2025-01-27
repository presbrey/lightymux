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
	Options    *Options
	server     *http.Server
	logger     *log.Logger
	mux        *http.ServeMux
	configLock sync.RWMutex
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
		Options:    opts,
		logger:     log.New(logWriter, "", log.LstdFlags),
		mux:        http.NewServeMux(),
		configLock: sync.RWMutex{},
	}

	// Set up HTTP server
	l.server = &http.Server{
		Addr:    opts.HTTPAddr,
		Handler: l,
	}

	return l, nil
}

func (l *LightyMux) loadConfig(filename string) error {
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
				l.logger.Printf("Error parsing URL %s: %v", target, err)
				continue
			}
			proxy := &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = nextHop.Scheme
					req.URL.Host = nextHop.Host
					req.URL.Path = singleJoiningSlash(nextHop.Path, req.URL.Path)
				},
				ModifyResponse: l.modifyResponse,
			}
			newMux.Handle(path, proxy)
			l.logger.Printf("Added remote route: %s -> %s", path, nextHop)
		} else {
			// Handle local filesystem path
			fileInfo, err := os.Stat(target)
			if err != nil {
				l.logger.Printf("Error accessing path %s: %v", target, err)
				continue
			}

			if fileInfo.IsDir() {
				// Serve directory
				fs := http.FileServer(http.Dir(target))
				newMux.Handle(path, http.StripPrefix(path, fs))
				l.logger.Printf("Added directory route: %s -> %s", path, target)
			} else {
				// Serve single file
				fs := http.FileServer(http.Dir(filepath.Dir(target)))
				newMux.Handle(path, http.StripPrefix(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.URL.Path = filepath.Base(target)
					fs.ServeHTTP(w, r)
				})))
				l.logger.Printf("Added file route: %s -> %s", path, target)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	l.configLock.Lock()
	l.mux = newMux
	l.configLock.Unlock()

	return nil
}

func (l *LightyMux) modifyResponse(res *http.Response) error {
	if l.Options.LogResponses {
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			return err
		}
		l.logger.Printf("Response: %s", string(dump))
	}
	return nil
}

func (l *LightyMux) watchConfig(filename string) error {
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
					l.logger.Printf("Config file modified. Reloading...")
					if err := l.loadConfig(filename); err != nil {
						l.logger.Printf("Error reloading config: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				l.logger.Printf("Error watching config file: %v", err)
			}
		}
	}()

	return watcher.Add(filename)
}

// ServeHTTP implements the http.Handler interface
func (l *LightyMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if l.Options.LogRequests {
		dump, _ := httputil.DumpRequest(r, true)
		l.logger.Printf("Request: %s", string(dump))
	}
	l.configLock.RLock()
	mux := l.mux
	l.configLock.RUnlock()
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

func (l *LightyMux) Run(configFile string) error {
	// Initialize proxy handler with config
	if err := l.loadConfig(configFile); err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	// Start config file watcher
	if err := l.watchConfig(configFile); err != nil {
		return err
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		l.logger.Println("Shutting down server...")
		if err := l.server.Shutdown(ctx); err != nil {
			l.logger.Printf("Error during server shutdown: %v", err)
		}
		cancel()
	}()

	l.logger.Printf("Starting reverse proxy on %s", l.Options.HTTPAddr)
	if err := l.server.ListenAndServe(); err != http.ErrServerClosed {
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
