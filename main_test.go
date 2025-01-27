package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if tt.skip {
		return
	}

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	reqURL := baseURL.ResolveReference(&url.URL{Path: tt.path})
	resp, err := client.Get(reqURL.String())
	if err != nil {
		t.Fatalf("client.Get(%q) failed: %v", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != tt.wantStatus {
		t.Errorf("path %q: got status = %d, want %d", tt.path, resp.StatusCode, tt.wantStatus)
		t.Logf("Response: %+v", resp)
	}

	if tt.wantBody != "" {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		gotBody := strings.TrimSpace(string(body))
		if gotBody != tt.wantBody {
			t.Errorf("path %q: got body = %q, want %q", tt.path, gotBody, tt.wantBody)
		}
	}
}

func TestProxyHandlerLoadConfig(t *testing.T) {
	staticDir, files, cleanupFiles := setupTestFiles(t)
	defer cleanupFiles()

	configFile, cleanupConfig := createConfigFile(t, staticDir, files[2].path)
	defer cleanupConfig()

	ph := &ProxyHandler{
		mux: http.NewServeMux(),
	}
	logger = log.New(ioutil.Discard, "", 0)

	if err := ph.loadConfig(configFile); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
		skip       bool
	}{
		{"api endpoint", "/api", http.StatusBadGateway, "", true},
		{"static file", "/static/index.html", http.StatusOK, "<html>test</html>", false},
		{"static txt file", "/static/test.txt", http.StatusOK, "static test content", false},
		{"static directory", "/static/", http.StatusOK, "", false},
		{"single file", "/file", http.StatusOK, "single file test content", false},
	}

	server := httptest.NewServer(ph)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runProxyTest(t, server, tt)
		})
	}
}

func TestModifyResponse(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
		Body:   ioutil.NopCloser(bytes.NewBufferString("test body")),
	}

	if err := modifyResponse(resp); err != nil {
		t.Errorf("modifyResponse() error = %v", err)
	}

	// Read the modified body to verify it wasn't corrupted
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Failed to read response body: %v", err)
	}
	if string(body) != "test body" {
		t.Errorf("modifyResponse() corrupted body = %q; want %q", string(body), "test body")
	}
}

func TestNewLightyMux(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name: "default options",
			opts: &Options{},
		},
		{
			name: "custom http address",
			opts: &Options{
				HTTPAddr: ":9090",
			},
		},
		{
			name: "with log file",
			opts: &Options{
				LogFile: "test.log",
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
			if lm == nil {
				t.Error("NewLightyMux() returned nil LightyMux")
				return
			}

			// Check if logger is initialized
			if lm.logger == nil {
				t.Error("NewLightyMux() logger is nil")
			}

			// Check if handler is initialized
			if lm.handler == nil {
				t.Error("NewLightyMux() handler is nil")
			}

			// Clean up log file if created
			if tt.opts.LogFile != "" {
				os.Remove(tt.opts.LogFile)
			}
		})
	}
}

func TestLightyMuxRun(t *testing.T) {
	// Create a temporary config file
	configContent := `{
		"routes": [
			{
				"path": "/test",
				"upstream": "http://localhost:8081"
			}
		]
	}`
	tmpfile, err := ioutil.TempFile("", "config*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create LightyMux instance
	lm, err := NewLightyMux(&Options{
		HTTPAddr: ":0", // Use random port
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- lm.Run(tmpfile.Name())
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Send interrupt signal to trigger shutdown
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	p.Signal(os.Interrupt)

	// Check if server shuts down cleanly
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() didn't shut down within timeout")
	}
}
