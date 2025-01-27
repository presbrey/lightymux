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

func TestProxyHandlerLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpdir, err := ioutil.TempDir("", "static")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create static directory with test files
	staticDir := filepath.Join(tmpdir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create test files in the static directory
	staticFiles := map[string]string{
		"index.html": "<html>test</html>",
		"test.txt":   "static test content",
	}
	for name, content := range staticFiles {
		if err := ioutil.WriteFile(filepath.Join(staticDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create a separate test file
	testFile := filepath.Join(tmpdir, "test.txt")
	if err := ioutil.WriteFile(testFile, []byte("single file test content"), 0644); err != nil {
		t.Fatal(err)
	}

	content := fmt.Sprintf(`/api http://api.example.com
/static/ %s
/file %s
`, staticDir, testFile)

	tmpfile, err := ioutil.TempFile("", "config*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Initialize proxy handler
	ph := &ProxyHandler{
		mux: http.NewServeMux(),
	}
	logger = log.New(ioutil.Discard, "", 0) // Suppress logging during tests

	// Test loading config
	if err := ph.loadConfig(tmpfile.Name()); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Test proxy routes
	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
		skip       bool
	}{
		{"api endpoint", "/api", http.StatusBadGateway, "", true}, // Skip as api.example.com doesn't exist
		{"static file", "/static/index.html", http.StatusOK, "<html>test</html>", false},
		{"static txt file", "/static/test.txt", http.StatusOK, "static test content", false},
		{"static directory", "/static/", http.StatusOK, "", false}, // Directory listing
		{"single file", "/file", http.StatusOK, "single file test content", false},
	}

	server := httptest.NewServer(ph)
	defer server.Close()

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	for _, tt := range tests {
		if tt.skip {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
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
