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

	"github.com/fsnotify/fsnotify"
)

// ProxyHandler encapsulates the proxy's functionality
type ProxyHandler struct {
	mux        *http.ServeMux
	configLock sync.RWMutex
}

// Logging configuration
var (
	verbose       bool
	logRequests   bool
	logResponses  bool
	logErrors     bool
	logConfigFile string
	logger        *log.Logger
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
	if logResponses {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		logger.Printf("Response: %s", string(body))
		res.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	return nil
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if logErrors {
		logger.Printf("Proxy error: %v", err)
	}
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte("Proxy Error"))
}

func (ph *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ph.configLock.RLock()
	defer ph.configLock.RUnlock()

	if logRequests {
		logger.Printf("Request: %s %s", r.Method, r.RequestURI)
	}
	start := time.Now()
	ph.mux.ServeHTTP(w, r)
	if verbose {
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

func main() {
	var httpAddr string
	flag.StringVar(&httpAddr, "http", "", "HTTP listen address (e.g., :8080)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&logRequests, "log-requests", false, "Log incoming requests")
	flag.BoolVar(&logResponses, "log-responses", false, "Log outgoing responses")
	flag.BoolVar(&logErrors, "log-errors", true, "Log proxy errors")
	flag.StringVar(&logConfigFile, "log-file", "", "Log to file instead of stderr")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: ./reverse_proxy [flags] <config_file>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Setup logging
	if logConfigFile != "" {
		logFile, err := os.OpenFile(logConfigFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer logFile.Close()
		logger = log.New(logFile, "", log.LstdFlags)
	} else {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	configFile := flag.Arg(0)

	// Check for PORT environment variable if -http flag is not set
	if httpAddr == "" {
		if port := os.Getenv("PORT"); port != "" {
			httpAddr = ":" + port
		} else {
			httpAddr = ":8080" // Default if neither flag nor env var is set
		}
	}

	proxyHandler := &ProxyHandler{}
	if err := proxyHandler.loadConfig(configFile); err != nil {
		logger.Fatalf("Error loading config: %v", err)
	}

	go func() {
		if err := proxyHandler.watchConfig(configFile); err != nil {
			logger.Fatalf("Error setting up config watcher: %v", err)
		}
	}()

	server := &http.Server{
		Addr:    httpAddr,
		Handler: proxyHandler,
	}

	go func() {
		sigchan := make(chan os.Signal, 1)
		<-sigchan
		logger.Println("Shutting down the server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Printf("Error during server shutdown: %v", err)
		}
	}()

	logger.Printf("Starting reverse proxy on %s", httpAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatalf("Error starting server: %v", err)
	}
}
