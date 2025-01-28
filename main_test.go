package main

import (
	"context"
	"fmt"
	"io/ioutil"
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
	// Create a test server that echoes headers
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo request headers in response
		w.Header().Set("X-Request-Accept", strings.Join(r.Header.Values("Accept"), ", "))
		w.Header().Set("X-Request-Custom", strings.Join(r.Header.Values("X-Custom"), ", "))
		w.Header().Set("X-Request-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Request-Old", r.Header.Get("X-Old-Header"))

		// Add some headers that will be modified
		w.Header().Set("X-Internal-Header", "secret")
		w.Header().Add("Access-Control-Allow-Methods", "GET")
	}))
	defer ts.Close()

	// Create config file with header modifications
	configFile, err := ioutil.TempFile("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())

	content := fmt.Sprintf(`
/test:
  target: %s
  rules:
    - request:
        headers:
          header-add:
            Accept: ["application/json", "text/plain"]
            X-Custom: ["value1", "value2"]
          header-set:
            Authorization: "Bearer token123"
          header-del:
            - "X-Old-Header"
    - response:
        headers:
          header-add:
            Access-Control-Allow-Methods: ["POST", "OPTIONS"]
          header-set:
            Access-Control-Allow-Origin: "*"
          header-del:
            - "X-Internal-Header"
`, ts.URL)

	if err := ioutil.WriteFile(configFile.Name(), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create LightyMux instance
	opts := &Options{
		HTTPAddr:    "127.0.0.1:0", // Use random port on localhost
		LogRequests: true,
	}

	lm, err := NewLightyMux(opts)
	if err != nil {
		t.Fatalf("Failed to create LightyMux: %v", err)
	}

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- lm.Run(ctx, configFile.Name())
	}()

	// Wait for server to start and get its address
	time.Sleep(100 * time.Millisecond)

	// Get the actual server address
	serverAddr := lm.server.Addr
	if serverAddr == "" {
		t.Fatal("Server address is empty")
	}

	// Make request to test server
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", serverAddr), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Old-Header", "should-be-removed")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify request header modifications
	acceptHeaders := strings.Split(resp.Header.Get("X-Request-Accept"), ", ")
	if !containsAll(acceptHeaders, []string{"application/json", "text/plain"}) {
		t.Errorf("Accept header = %q, want both application/json and text/plain", acceptHeaders)
	}

	customHeaders := strings.Split(resp.Header.Get("X-Request-Custom"), ", ")
	if !containsAll(customHeaders, []string{"value1", "value2"}) {
		t.Errorf("X-Custom header = %q, want both value1 and value2", customHeaders)
	}

	if got := resp.Header.Get("X-Request-Auth"); got != "Bearer token123" {
		t.Errorf("Authorization header = %q, want Bearer token123", got)
	}
	if got := resp.Header.Get("X-Request-Old"); got != "" {
		t.Errorf("X-Old-Header = %q, want empty (header should be deleted)", got)
	}

	// Verify response header modifications
	methods := resp.Header.Values("Access-Control-Allow-Methods")
	if !containsAll(methods, []string{"GET", "POST", "OPTIONS"}) {
		t.Errorf("Access-Control-Allow-Methods = %v, want [GET POST OPTIONS]", methods)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := resp.Header.Get("X-Internal-Header"); got != "" {
		t.Errorf("X-Internal-Header = %q, want empty (header should be deleted)", got)
	}

	// Shutdown server
	cancel()
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Server did not shut down within timeout")
	}
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func containsAll(slice []string, items []string) bool {
	for _, item := range items {
		if !contains(slice, item) {
			return false
		}
	}
	return true
}
