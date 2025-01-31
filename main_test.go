package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	content := fmt.Sprintf(`/api http://api.example.com
/static/ %s
/file %s
`, staticDir, testFile)

	tmpfile, err := ioutil.TempFile("", "config*.txt")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tmpfile.Write([]byte(content)); err != nil {
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
	staticDir, files, cleanup := setupTestFiles(t)
	defer cleanup()

	configFile, cleanupConfig := createConfigFile(t, staticDir, files[2].path)
	defer cleanupConfig()

	// Create a test server that acts as our remote API
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "API response")
	}))
	defer apiServer.Close()

	// Update config file with actual API server URL
	content := fmt.Sprintf(`
/api:
  target: %s
/static/:
  target: %s
/file:
  target: %s
`, apiServer.URL, staticDir, files[2].path)
	if err := ioutil.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create LightyMux instance
	lm, err := NewLightyMux(&Options{})
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Load the config
	if err := lm.loadConfig(configFile); err != nil {
		t.Fatalf("Failed to load config: %v", err)
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
	for i := 0; i < 50; i++ {
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

// equalStringSlices compares two string slices for equality
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
