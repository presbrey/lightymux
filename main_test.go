package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestIsWebScheme(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"ftp://example.com", false},
		{"file:///path", false},
		{"/local/path", false},
	}

	for _, test := range tests {
		result := isWebScheme(test.input)
		if result != test.expected {
			t.Errorf("isWebScheme(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"/", "/", "/"},
		{"/a/", "/b", "/a/b"},
		{"/a", "/b", "/a/b"},
		{"/a", "b", "/a/b"},
		{"a", "b", "a/b"},
	}

	for _, test := range tests {
		got := singleJoiningSlash(test.a, test.b)
		if got != test.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q; want %q", test.a, test.b, got, test.want)
		}
	}
}

type testFile struct {
	path    string
	content string
}

func setupTestFiles(t *testing.T) (string, []testFile, func()) {
	tmpdir, err := ioutil.TempDir("", "static")
	if err != nil {
		t.Fatal(err)
	}

	staticDir := filepath.Join(tmpdir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}

	files := []testFile{
		{filepath.Join(staticDir, "index.html"), "<html>test</html>"},
		{filepath.Join(staticDir, "test.txt"), "static test content"},
		{filepath.Join(tmpdir, "test.txt"), "single file test content"},
	}

	for _, f := range files {
		if err := ioutil.WriteFile(f.path, []byte(f.content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cleanup := func() {
		os.RemoveAll(tmpdir)
	}

	return staticDir, files, cleanup
}

func createConfigFile(t *testing.T, staticDir, testFile string) (string, func()) {
	config := LightyConfig{
		Routes: map[string]RouteConfig{
			"/api/":    {Target: "http://api.example.com"},
			"/static/": {Target: staticDir},
			"/file":    {Target: testFile},
		},
	}

	configBytes, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	tmpfile, err := ioutil.TempFile("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tmpfile.Write(configBytes); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		os.Remove(tmpfile.Name())
	}

	return tmpfile.Name(), cleanup
}

func runProxyTest(t *testing.T, server *httptest.Server, tt struct {
	name       string
	path       string
	wantStatus int
	wantBody   string
	skip       bool
}) {
	t.Run(tt.name, func(t *testing.T) {
		if tt.skip {
			t.Skip()
		}

		req, err := http.NewRequest("GET", server.URL+tt.path, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != tt.wantStatus {
			t.Errorf("Status = %d; want %d", resp.StatusCode, tt.wantStatus)
		}

		if tt.wantBody != "" {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			if !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("Body = %q; want to contain %q", string(body), tt.wantBody)
			}
		}
	})
}

func TestLoadConfig(t *testing.T) {
	// Create temporary directory and files
	staticDir, testFiles, cleanup := setupTestFiles(t)
	defer cleanup()

	// Create a test server that acts as our remote API
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "API response")
	}))
	defer apiServer.Close()

	// Create config file with actual API server URL
	config := LightyConfig{
		Routes: map[string]RouteConfig{
			"/api/":    {Target: apiServer.URL},
			"/static/": {Target: staticDir},
			"/file":    {Target: testFiles[2].path},
		},
	}

	configBytes, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	configFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(configFile.Name())

	if err := os.WriteFile(configFile.Name(), configBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Create LightyMux instance
	lm, err := NewLightyMux(&Options{})
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to signal when the server is ready
	serverReady := make(chan struct{})
	go func() {
		if err := lm.Run(ctx, configFile.Name()); err != nil && err != context.Canceled {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Wait for the server to be ready
	for i := 0; i < 50; i++ { // Try for up to 5 seconds
		if addr := lm.GetServerAddr(); addr != "" {
			close(serverReady)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case <-serverReady:
		// Server is ready, continue with the test
	case <-time.After(5 * time.Second):
		t.Fatal("Server failed to start within timeout")
	}

	// Create test server using our mux
	server := httptest.NewServer(lm)
	defer server.Close()

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
		skip       bool
	}{
		{
			name:       "API proxy",
			path:       "/api",
			wantStatus: http.StatusOK,
			wantBody:   "API response",
		},
		{
			name:       "Static directory",
			path:       "/static/index.html",
			wantStatus: http.StatusOK,
			wantBody:   "<html>test</html>",
		},
		{
			name:       "Single file",
			path:       "/file",
			wantStatus: http.StatusOK,
			wantBody:   "single file test content",
		},
		{
			name:       "Not found",
			path:       "/notfound",
			wantStatus: http.StatusNotFound,
			wantBody:   "404 page not found",
		},
	}

	for _, tt := range tests {
		runProxyTest(t, server, tt)
	}
}

func TestNewLightyMux(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name: "Default options",
			opts: &Options{},
		},
		{
			name: "Custom address",
			opts: &Options{
				HTTPAddr: ":8080",
			},
		},
		{
			name: "With logging options",
			opts: &Options{
				LogFile:      "test.log",
				LogRequests:  true,
				LogResponses: true,
			},
		},
		{
			name: "Zero timeouts disable timeouts",
			opts: &Options{
				ReadTimeout:  0,
				WriteTimeout: 0,
				IdleTimeout:  0,
			},
		},
		{
			name:    "Nil options returns error",
			opts:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lm, err := NewLightyMux(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLightyMux() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if tt.name == "Zero timeouts disable timeouts" {
				if lm.server.ReadTimeout != 0 {
					t.Errorf("ReadTimeout = %v, want 0", lm.server.ReadTimeout)
				}
				if lm.server.WriteTimeout != 0 {
					t.Errorf("WriteTimeout = %v, want 0", lm.server.WriteTimeout)
				}
				if lm.server.IdleTimeout != 0 {
					t.Errorf("IdleTimeout = %v, want 0", lm.server.IdleTimeout)
				}
			}
		})
	}
}

func TestLightyMuxRun(t *testing.T) {
	// Create a temporary config file
	configFile, err := ioutil.TempFile("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())

	// Write test configuration in YAML format
	content := `
/test:
  target: http://localhost:12345
`
	if err := ioutil.WriteFile(configFile.Name(), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create LightyMux with test options
	opts := &Options{
		HTTPAddr:    ":0", // Use random port
		LogRequests: true,
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Create a context with cancel for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- lm.Run(ctx, configFile.Name())
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Trigger graceful shutdown via context
	cancel()

	// Check if server shut down gracefully
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Server did not shut down within timeout")
	}
}

func TestHeaderModification(t *testing.T) {
	// Create a test server that will be our backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the incoming request for debugging
		log.Printf("Request: %s %s %s\n", r.Method, r.URL.Path, r.Proto)
		for name, values := range r.Header {
			for _, value := range values {
				log.Printf("%s: %s\n", name, value)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	// Create a temporary config file
	configFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write test configuration
	config := fmt.Sprintf(`
routes:
  /test:
    target: %s
    rules:
      - request:
          headers:
            header-del:
              - "X-Old-Header"
            header-add:
              X-New-Header: "new-value"
            header-set:
              X-Set-Header: "set-value"
`, backendServer.URL)

	if err := os.WriteFile(configFile.Name(), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	opts := &Options{
		HTTPAddr:    "127.0.0.1:0", // Let the system choose a port
		LogRequests: true,
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to signal when the server is ready
	serverReady := make(chan struct{})
	go func() {
		if err := lm.Run(ctx, configFile.Name()); err != nil && err != context.Canceled {
			t.Errorf("Server error: %v", err)
		}
	}()
	// Wait for the server to be ready by polling the address
	for i := 0; i < 50; i++ { // Try for up to 5 seconds
		if addr := lm.GetServerAddr(); addr != "" {
			close(serverReady)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case <-serverReady:
		// Server is ready, continue with the test
	case <-time.After(5 * time.Second):
		t.Fatal("Server failed to start within timeout")
	}

	// Get the server address using the thread-safe method
	serverAddr := lm.GetServerAddr()
	if serverAddr == "" {
		t.Fatal("Server address is empty")
	}

	// Make request to test server
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", serverAddr), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add header that should be removed
	req.Header.Set("X-Old-Header", "should-be-removed")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}

	// Clean shutdown
	cancel()
}

func TestResponseHeaderModification(t *testing.T) {
	// Create a test server that will be our backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add some initial headers that we'll modify
		w.Header().Set("X-Original-Header", "original-value")
		w.Header().Set("X-Header-To-Delete", "delete-me")
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	// Create a temporary config file
	configFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write test configuration with response header modifications
	config := fmt.Sprintf(`
routes:
  /test:
    target: %s
    rules:
      - response:
          headers:
            header-add:
              X-Added-Header: "added-value"
            header-set:
              X-Set-Header: "set-value"
              X-Original-Header: "modified-value"
            header-del:
              - "X-Header-To-Delete"
`, backendServer.URL)

	if err := os.WriteFile(configFile.Name(), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	opts := &Options{
		HTTPAddr:    "127.0.0.1:0", // Let the system choose a port
		LogRequests: true,
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to signal when the server is ready
	serverReady := make(chan struct{})
	go func() {
		if err := lm.Run(ctx, configFile.Name()); err != nil && err != context.Canceled {
			t.Errorf("Server error: %v", err)
		}
	}()
	// Wait for the server to be ready
	for i := 0; i < 50; i++ { // Try for up to 5 seconds
		if addr := lm.GetServerAddr(); addr != "" {
			close(serverReady)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case <-serverReady:
		// Server is ready, continue with the test
	case <-time.After(5 * time.Second):
		t.Fatal("Server failed to start within timeout")
	}

	// Get the server address
	serverAddr := lm.GetServerAddr()
	if serverAddr == "" {
		t.Fatal("Server address is empty")
	}

	// Make request to test server
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", serverAddr), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response status
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}

	// Test header modifications
	tests := []struct {
		name     string
		header   string
		want     []string
		wantNone bool
	}{
		{"Added header with multiple values", "X-Added-Header", []string{"added-value"}, false},
		{"Set header", "X-Set-Header", []string{"set-value"}, false},
		{"Modified original header", "X-Original-Header", []string{"modified-value"}, false},
		{"Deleted header", "X-Header-To-Delete", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resp.Header.Values(tt.header)
			if tt.wantNone {
				if len(got) > 0 {
					t.Errorf("Header %q should not exist, got %v", tt.header, got)
				}
			} else {
				if !equalStringSlices(got, tt.want) {
					t.Errorf("Header %q = %v, want %v", tt.header, got, tt.want)
				}
			}
		})
	}

	// Clean shutdown
	cancel()
}

func TestConfigFileWatcher(t *testing.T) {
	// Set up test files
	staticDir, files, cleanup := setupTestFiles(t)
	defer cleanup()

	// Create initial config file
	configPath, cleanupConfig := createConfigFile(t, staticDir, files[2].path)
	defer cleanupConfig()

	// Create a test logger that captures output
	var logOutput safeLogger
	testLogger := log.New(&wrappedWriter{sl: &logOutput}, "", 0)

	// Create LightyMux instance with test logger
	lm := &LightyMux{
		logger:  testLogger,
		options: &Options{LogRequests: true, LogResponses: true},
	}

	// Start config watcher
	errChan := make(chan error, 1)
	go func() {
		errChan <- lm.watchConfig(configPath)
	}()
	time.Sleep(100 * time.Millisecond) // Give watcher time to start

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Failed to watch config: %v", err)
		}
	default:
	}

	// Modify config file with new content
	newConfig := LightyConfig{
		Routes: map[string]RouteConfig{
			"/api/":    {Target: "http://newapi.example.com"},
			"/static/": {Target: staticDir},
			"/file":    {Target: files[2].path},
		},
	}

	newConfigBytes, err := yaml.Marshal(newConfig)
	if err != nil {
		t.Fatalf("Failed to marshal new config: %v", err)
	}

	t.Logf("Writing new config:\n%s", string(newConfigBytes))

	if err := ioutil.WriteFile(configPath, newConfigBytes, 0644); err != nil {
		t.Fatalf("Failed to modify config file: %v", err)
	}

	// Give some time for the watcher to detect and process the change
	time.Sleep(200 * time.Millisecond)

	// Log the captured output
	t.Logf("Logger output:\n%s", logOutput.String())

	// Verify that config was reloaded
	if !strings.Contains(logOutput.String(), "Config file modified. Reloading...") {
		t.Error("Expected log message about config reload not found")
	}

	// Make a test request to verify the new route
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	lm.ServeHTTP(rr, req)

	t.Logf("Response status: %d", rr.Code)
	t.Logf("Response body: %s", rr.Body.String())

	// The request should be handled by the proxy (even if it fails to connect)
	// We're mainly checking that the route was updated
	if rr.Code == http.StatusNotFound {
		t.Error("Route /api was not updated - got 404 Not Found")
	}
}

type safeLogger struct {
	mu      sync.Mutex
	builder strings.Builder
}

type wrappedWriter struct {
	sl *safeLogger
}

func (w *wrappedWriter) Write(p []byte) (n int, err error) {
	w.sl.mu.Lock()
	defer w.sl.mu.Unlock()
	return w.sl.builder.Write(p)
}

func (sl *safeLogger) String() string {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.builder.String()
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHandleHealthCheck(t *testing.T) {
	opts := &Options{
		HTTPAddr: "127.0.0.1:0",
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Call the handler
	lm.handleHealthCheck(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Check Content-Type header
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type %q, got %q", "application/json", contentType)
	}

	// Parse and validate response body
	var response struct {
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
	}

	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	// Check status field
	if response.Status != "healthy" {
		t.Errorf("Expected status %q, got %q", "healthy", response.Status)
	}

	// Validate timestamp format
	_, err = time.Parse(time.RFC3339, response.Timestamp)
	if err != nil {
		t.Errorf("Invalid timestamp format: %v", err)
	}
}

func TestRemoteReloader(t *testing.T) {
	// Create test server
	testData := []byte("initial config")
	var serverHits int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		serverHits++
		mu.Unlock()
		w.Write(testData)
	}))
	defer server.Close()

	// Test NewRemoteReloader
	interval := 100 * time.Millisecond
	reloader2, err := NewConfigReloader(server.URL, interval)
	reloader, ok := reloader2.(*RemoteReloader)
	assert.True(t, ok)
	if err != nil {
		t.Fatalf("NewRemoteReloader failed: %v", err)
	}

	if reloader.url != server.URL {
		t.Errorf("url = %q; want %q", reloader.url, server.URL)
	}
	if reloader.interval != interval {
		t.Errorf("interval = %v; want %v", reloader.interval, interval)
	}

	// Test Load
	data, err := reloader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if string(data) != string(testData) {
		t.Errorf("Load() = %q; want %q", string(data), string(testData))
	}

	// Test Watch
	var (
		receivedData []byte
		receivedErr  error
		dataReceived bool
		mu2          sync.Mutex
	)

	callback := func(data []byte, err error) {
		mu2.Lock()
		defer mu2.Unlock()
		if !dataReceived {
			receivedData = data
			receivedErr = err
			dataReceived = true
		}
	}

	if err := reloader.Watch(callback); err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// Wait for the first callback
	startTime := time.Now()
	for {
		mu2.Lock()
		if dataReceived || time.Since(startTime) > time.Second {
			mu2.Unlock()
			break
		}
		mu2.Unlock()
		time.Sleep(10 * time.Millisecond)
	}

	if !dataReceived {
		t.Fatal("Watch callback was not called within timeout")
	}
	if receivedErr != nil {
		t.Errorf("Watch callback received error: %v", receivedErr)
	}
	if string(receivedData) != string(testData) {
		t.Errorf("Watch callback received data = %q; want %q", string(receivedData), string(testData))
	}

	// Verify multiple hits to server
	time.Sleep(interval * 2)
	mu.Lock()
	if serverHits < 2 {
		t.Errorf("server hits = %d; want >= 2", serverHits)
	}
	mu.Unlock()

	// Test Close
	if err := reloader.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify no more hits after close
	currentHits := serverHits
	time.Sleep(interval * 2)
	mu.Lock()
	if serverHits != currentHits {
		t.Errorf("server received hits after Close(): got %d; want %d", serverHits, currentHits)
	}
	mu.Unlock()
}

func TestLocalReloaderCloseNilWatcher(t *testing.T) {
	// Test Close with nil watcher (no Watch called)
	reloader, err := NewLocalReloader("/tmp/test.yaml")
	assert.NoError(t, err)

	// Close without calling Watch should not panic
	err = reloader.Close()
	assert.NoError(t, err)
}

func TestVerboseProxyLogging(t *testing.T) {
	// Create a test server that will be our backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backendServer.Close()

	// Create a temporary config file
	configFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write test configuration
	config := fmt.Sprintf(`
routes:
  /test:
    target: %s
`, backendServer.URL)

	if err := os.WriteFile(configFile.Name(), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	opts := &Options{
		HTTPAddr: "127.0.0.1:0",
		Verbose:  true, // Enable verbose logging
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := lm.Run(ctx, configFile.Name()); err != nil && err != context.Canceled {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	for i := 0; i < 50; i++ {
		if addr := lm.GetServerAddr(); addr != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	serverAddr := lm.GetServerAddr()
	if serverAddr == "" {
		t.Fatal("Server address is empty")
	}

	// Make request to trigger verbose logging
	resp, err := http.Get(fmt.Sprintf("http://%s/test", serverAddr))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	cancel()
}

func TestHealthRouteRegistration(t *testing.T) {
	// Create a temporary config file
	configFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write minimal config
	config := `routes: {}`
	if err := os.WriteFile(configFile.Name(), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	opts := &Options{
		HTTPAddr:    "127.0.0.1:0",
		HealthRoute: "/health",
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := lm.Run(ctx, configFile.Name()); err != nil && err != context.Canceled {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	for i := 0; i < 50; i++ {
		if addr := lm.GetServerAddr(); addr != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	serverAddr := lm.GetServerAddr()
	if serverAddr == "" {
		t.Fatal("Server address is empty")
	}

	// Make request to health endpoint
	resp, err := http.Get(fmt.Sprintf("http://%s/health", serverAddr))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	cancel()
}

func TestProxyErrorHandler(t *testing.T) {
	// Create a temporary config file that points to a non-existent backend
	configFile, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Point to a port that's not listening
	config := `
routes:
  /test:
    target: http://127.0.0.1:19999
`
	if err := os.WriteFile(configFile.Name(), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	opts := &Options{
		HTTPAddr:  "127.0.0.1:0",
		LogErrors: true,
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := lm.Run(ctx, configFile.Name()); err != nil && err != context.Canceled {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	for i := 0; i < 50; i++ {
		if addr := lm.GetServerAddr(); addr != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	serverAddr := lm.GetServerAddr()
	if serverAddr == "" {
		t.Fatal("Server address is empty")
	}

	// Make request - should trigger error handler
	resp, err := http.Get(fmt.Sprintf("http://%s/test", serverAddr))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	// Should get bad gateway due to backend connection failure
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	cancel()
}

func TestRemoteReloaderErrors(t *testing.T) {
	// Test with invalid URL
	_, err := NewRemoteReloader("invalid-url", time.Second)
	if err != nil {
		t.Errorf("NewRemoteReloader with invalid URL returned error: %v", err)
	}

	// Test with non-existent server
	reloader, _ := NewRemoteReloader("http://localhost:12345", time.Second)
	_, err = reloader.Load()
	if err == nil {
		t.Error("Load() with non-existent server should return error")
	}
}

func TestInitReloaderErrors(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		wantErr    string
	}{
		{
			name:       "nonexistent config file",
			configPath: "/nonexistent/config.yaml",
			wantErr:    "failed to load initial config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lm := &LightyMux{
				options: &Options{
					ConfigRefreshInterval: time.Second,
				},
				logger: log.New(os.Stderr, "", log.LstdFlags),
			}
			err := lm.initReloader(tt.configPath)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestProcessConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
		setupLM func(*LightyMux)
	}{
		{
			name:    "invalid yaml",
			data:    []byte(`invalid: yaml: [`),
			wantErr: "failed to parse YAML",
		},
		{
			name: "invalid URL target",
			data: []byte(`
routes:
  "/api/":
    target: "http://[invalid-url"  # Invalid URL syntax
`),
			wantErr: "failed to apply config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &strings.Builder{}
			lm := &LightyMux{
				options: &Options{},
				logger:  log.New(buf, "", log.LstdFlags),
			}
			if tt.setupLM != nil {
				tt.setupLM(lm)
			}
			err := lm.processConfig(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	// Save original environment
	origEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, e := range origEnv {
			parts := strings.SplitN(e, "=", 2)
			os.Setenv(parts[0], parts[1])
		}
	}()

	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		wantOpts    *Options
		wantConfig  string
		wantErrText string
	}{
		{
			name: "valid args and config",
			args: []string{"-http=:8080", "-verbose", "config.yaml"},
			env:  map[string]string{},
			wantOpts: &Options{
				HTTPAddr:    ":8080",
				Verbose:     true,
				LogRequests: false,
			},
			wantConfig: "config.yaml",
		},
		{
			name: "environment variables",
			args: []string{"config.yaml"},
			env: map[string]string{
				"HTTP_ADDR":     ":9090",
				"LOG_REQUESTS":  "true",
				"LOG_RESPONSES": "true",
			},
			wantOpts: &Options{
				HTTPAddr:     ":9090",
				LogRequests:  true,
				LogResponses: true,
			},
			wantConfig: "config.yaml",
		},
		{
			name:        "missing config file",
			args:        []string{"-http=:8080"},
			env:         map[string]string{},
			wantErrText: "exactly one config file argument is required",
		},
		{
			name:        "too many arguments",
			args:        []string{"config1.yaml", "config2.yaml"},
			env:         map[string]string{},
			wantErrText: "exactly one config file argument is required",
		},
		{
			name:        "invalid flag",
			args:        []string{"-invalid-flag", "config.yaml"},
			env:         map[string]string{},
			wantErrText: "flag provided but not defined: -invalid-flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment and set test values
			os.Clearenv()
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			opts, config, err := parseArgs(tt.args)

			if tt.wantErrText != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrText)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantConfig, config)
			assert.Equal(t, tt.wantOpts.HTTPAddr, opts.HTTPAddr)
			assert.Equal(t, tt.wantOpts.Verbose, opts.Verbose)
			assert.Equal(t, tt.wantOpts.LogRequests, opts.LogRequests)
			assert.Equal(t, tt.wantOpts.LogResponses, opts.LogResponses)
		})
	}
}
