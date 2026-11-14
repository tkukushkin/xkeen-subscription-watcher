package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

type rciResponse struct {
	status int
	body   string
}

var defaultRCIResponses = map[string]rciResponse{
	"/show/identification": {200, `{"serial": "S123456789012", "mac": "50:ff:20:00:00:01", "cid": "x"}`},
	"/show/version":        {200, `{"vendor": "Keenetic", "title": "5.0.8", "description": "Keenetic Giga (KN-1011)", "arch": "mips"}`},
}

type fakeRCIServer struct {
	mu        sync.Mutex
	responses map[string]rciResponse
	requests  int
}

var fakeRCI = &fakeRCIServer{}

func (f *fakeRCIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	resp, ok := f.responses[r.URL.Path]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(resp.status)
	w.Write([]byte(resp.body))
}

func (f *fakeRCIServer) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses = make(map[string]rciResponse)
	for k, v := range defaultRCIResponses {
		f.responses[k] = v
	}
	f.requests = 0
}

func (f *fakeRCIServer) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// setRCIResponse меняет ответ фейкового RCI до конца теста.
func setRCIResponse(t *testing.T, path string, status int, body string) {
	t.Helper()
	fakeRCI.mu.Lock()
	fakeRCI.responses[path] = rciResponse{status, body}
	fakeRCI.mu.Unlock()
	t.Cleanup(fakeRCI.reset)
}

func TestMain(m *testing.M) {
	fakeRCI.reset()
	srv := httptest.NewServer(fakeRCI)
	rciBaseURL = srv.URL
	code := m.Run()
	srv.Close()
	os.Exit(code)
}

type headerRecorder struct {
	*httptest.Server
	mu      sync.Mutex
	headers []http.Header
}

func newHeaderRecorder(t *testing.T, body string) *headerRecorder {
	t.Helper()
	r := &headerRecorder{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		w.Write([]byte(body))
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *headerRecorder) last(t *testing.T) http.Header {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.headers) == 0 {
		t.Fatal("subscription server received no requests")
	}
	return r.headers[len(r.headers)-1]
}

func (r *headerRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.headers)
}

func TestHWIDFromSerial(t *testing.T) {
	got := hwidFromSerial("S123456789012")
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(got) {
		t.Errorf("not a version 8 UUID: %q", got)
	}
	if got != "c4287a0a-2f38-875b-9388-190bace0f06c" {
		t.Errorf("unexpected HWID %q", got)
	}
	if hwidFromSerial("S123456789013") == got {
		t.Error("different serials must give different HWIDs")
	}
}

func TestSendsHWIDHeaders(t *testing.T) {
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))

	if err := run([]string{"--output-dir", t.TempDir(), "--no-restart", fmt.Sprintf("s=%s/s", sub.URL)}); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	h := sub.last(t)
	want := map[string]string{
		"X-Hwid":         hwidFromSerial("S123456789012"),
		"X-Device-Os":    "Keenetic",
		"X-Ver-Os":       "5.0.8",
		"X-Device-Model": "Keenetic Giga (KN-1011)",
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestSendsOnlyHWIDWithoutVersionInfo(t *testing.T) {
	setRCIResponse(t, "/show/version", 500, `{"error": "temporarily unavailable"}`)
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))

	if err := run([]string{"--output-dir", t.TempDir(), "--no-restart", fmt.Sprintf("s=%s/s", sub.URL)}); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	h := sub.last(t)
	if h.Get("X-Hwid") != hwidFromSerial("S123456789012") {
		t.Errorf("X-Hwid = %q", h.Get("X-Hwid"))
	}
	for _, name := range []string{"X-Device-Os", "X-Ver-Os", "X-Device-Model"} {
		if _, ok := h[name]; ok {
			t.Errorf("%s should not be sent, got %q", name, h.Get(name))
		}
	}
}

func TestFailsWhenHWIDUnavailable(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"http error", 500, `{"serial": "S123456789012"}`},
		{"empty serial", 200, `{"serial": "", "mac": "50:ff:20:00:00:01"}`},
		{"invalid json", 200, `oops`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setRCIResponse(t, "/show/identification", tc.status, tc.body)
			sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))

			err := run([]string{"--output-dir", t.TempDir(), "--no-restart", fmt.Sprintf("s=%s/s", sub.URL)})
			if err == nil || !strings.Contains(err.Error(), "--no-hwid") {
				t.Errorf("expected error mentioning --no-hwid, got %v", err)
			}
			if sub.count() != 0 {
				t.Error("subscriptions must not be fetched without HWID")
			}
		})
	}
}

func TestFailsWhenRCIUnreachable(t *testing.T) {
	prev := rciBaseURL
	rciBaseURL = "http://127.0.0.1:1/rci"
	t.Cleanup(func() { rciBaseURL = prev })
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))

	err := run([]string{"--output-dir", t.TempDir(), "--no-restart", fmt.Sprintf("s=%s/s", sub.URL)})
	if err == nil || !strings.Contains(err.Error(), "--no-hwid") {
		t.Errorf("expected error mentioning --no-hwid, got %v", err)
	}
	if sub.count() != 0 {
		t.Error("subscriptions must not be fetched without HWID")
	}
}

func TestNoHWIDFlag(t *testing.T) {
	fakeRCI.reset()
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))

	if err := run([]string{"--output-dir", t.TempDir(), "--no-restart", "--no-hwid", fmt.Sprintf("s=%s/s", sub.URL)}); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	h := sub.last(t)
	for _, name := range []string{"X-Hwid", "X-Device-Os", "X-Ver-Os", "X-Device-Model"} {
		if _, ok := h[name]; ok {
			t.Errorf("%s should not be sent", name)
		}
	}
	if n := fakeRCI.requestCount(); n != 0 {
		t.Errorf("RCI should not be queried, got %d requests", n)
	}
}
