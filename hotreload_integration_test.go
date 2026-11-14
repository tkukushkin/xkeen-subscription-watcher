package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type subscriptionServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies map[string]string
}

func newSubscriptionServer(t *testing.T) *subscriptionServer {
	t.Helper()
	s := &subscriptionServer{bodies: make(map[string]string)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.bodies[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *subscriptionServer) set(name string, lines ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies["/"+name] = strings.Join(lines, "\n")
}

func (s *subscriptionServer) arg(tag, name string) string {
	return fmt.Sprintf("%s=%s/%s", tag, s.URL, name)
}

func runWatcher(dir string, args ...string) error {
	return run(append([]string{"--output-dir", dir}, args...))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}

// expectedFile генерирует файл подписки с --no-restart в отдельном каталоге.
func expectedFile(t *testing.T, tag string, args ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := runWatcher(dir, append([]string{"--no-restart"}, args...)...); err != nil {
		t.Fatalf("--no-restart run failed: %v", err)
	}
	return readFile(t, filepath.Join(dir, fmt.Sprintf("04_outbounds.%s.json", tag)))
}

func assertFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	if got := readFile(t, path); string(got) != string(want) {
		t.Errorf("file %s mismatch:\ngot:\n%s\nwant:\n%s", path, got, want)
	}
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Errorf("expected %s to not exist", path)
	}
}

func ssNode(host, name string) string {
	return makeSSURL("aes-256-gcm", "secret", host, 8388, name)
}

func vlessNode(name string, extra map[string]string) string {
	params := map[string]string{"type": "tcp", "security": "tls"}
	for k, v := range extra {
		params[k] = v
	}
	return makeVlessURL("11111111-2222-3333-4444-555555555555", "h2.example.com", 443, name, params)
}

// markOutbound заменяет outbound в Xray на freedom с тем же тегом, чтобы его состояние
// отличалось от файла подписки: если watcher тронет тег, отметка пропадёт.
func markOutbound(t *testing.T, addr, tag string) {
	t.Helper()
	api := xrayAPI{addr: addr}
	if err := api.removeOutbound(tag); err != nil {
		t.Fatalf("remove %s: %v", tag, err)
	}
	if err := api.addOutbound(map[string]any{"tag": tag, "protocol": "freedom"}); err != nil {
		t.Fatalf("add %s: %v", tag, err)
	}
}

func startHotReloadEnv(t *testing.T) (string, string) {
	t.Helper()
	requireXray(t)
	dir := t.TempDir()
	addr := writeAPIConfig(t, dir)
	startXray(t, dir, addr)
	return dir, addr
}

func TestHotReloadAddsOutbounds(t *testing.T) {
	dir, addr := startHotReloadEnv(t)
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"), ssNode("h2.example.com", "Узел 1"))

	if err := runWatcher(dir, srv.arg("s", "s")); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	outbounds := listOutbounds(t, addr)
	for _, tag := range []string{"s--n1", "s--Узел 1"} {
		if _, ok := outbounds[tag]; !ok {
			t.Errorf("expected outbound %q, got %v", tag, outbounds)
		}
	}
	assertFileEquals(t, filepath.Join(dir, "04_outbounds.s.json"), expectedFile(t, "s", srv.arg("s", "s")))
}

func TestHotReloadChangesAndRemovesOutbounds(t *testing.T) {
	dir, addr := startHotReloadEnv(t)
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"), ssNode("h1.example.com", "n2"), ssNode("h1.example.com", "n3"))
	if err := runWatcher(dir, srv.arg("s", "s")); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	markOutbound(t, addr, "s--n1")
	before := listOutbounds(t, addr)

	srv.set("s", ssNode("h1.example.com", "n1"), ssNode("h2.example.com", "n2"), ssNode("h1.example.com", "n4"))
	if err := runWatcher(dir, srv.arg("s", "s")); err != nil {
		t.Fatalf("second run failed: %v", err)
	}

	after := listOutbounds(t, addr)
	if after["s--n1"] != before["s--n1"] {
		t.Errorf("s--n1 should be untouched:\nbefore: %s\nafter: %s", before["s--n1"], after["s--n1"])
	}
	if after["s--n2"] == before["s--n2"] {
		t.Errorf("s--n2 should be changed: %s", after["s--n2"])
	}
	if _, ok := after["s--n3"]; ok {
		t.Error("s--n3 should be removed")
	}
	if _, ok := after["s--n4"]; !ok {
		t.Error("s--n4 should be added")
	}
	assertFileEquals(t, filepath.Join(dir, "04_outbounds.s.json"), expectedFile(t, "s", srv.arg("s", "s")))
}

func TestHotReloadDoesNotTouchOtherSubscription(t *testing.T) {
	dir, addr := startHotReloadEnv(t)
	srv := newSubscriptionServer(t)
	srv.set("a", ssNode("h1.example.com", "x"))
	srv.set("ab", ssNode("other.example.com", ""))
	args := []string{srv.arg("a", "a"), srv.arg("a--b", "ab")}
	if err := runWatcher(dir, args...); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	if _, ok := listOutbounds(t, addr)["a--b"]; !ok {
		t.Fatal("expected outbound a--b")
	}
	markOutbound(t, addr, "a--b")
	before := listOutbounds(t, addr)

	srv.set("a", ssNode("h2.example.com", "x"))
	if err := runWatcher(dir, args...); err != nil {
		t.Fatalf("second run failed: %v", err)
	}

	after := listOutbounds(t, addr)
	if after["a--b"] != before["a--b"] {
		t.Errorf("a--b should be untouched:\nbefore: %s\nafter: %s", before["a--b"], after["a--b"])
	}
	if after["a--x"] == before["a--x"] {
		t.Error("a--x should be changed")
	}
}

func TestHotReloadRetriesAfterPartialFailure(t *testing.T) {
	dir, addr := startHotReloadEnv(t)
	srv := newSubscriptionServer(t)
	path := filepath.Join(dir, "04_outbounds.s.json")

	srv.set("s", ssNode("h1.example.com", "n1"), vlessNode("n2", nil))
	if err := runWatcher(dir, srv.arg("s", "s")); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	firstN1 := listOutbounds(t, addr)["s--n1"]

	srv.set("s", ssNode("h2.example.com", "n1"), vlessNode("n2", map[string]string{"flow": "bogus"}), ssNode("h1.example.com", "n3"))
	err := runWatcher(dir, srv.arg("s", "s"))
	if err == nil {
		t.Fatal("expected second run to fail")
	}
	if !strings.Contains(err.Error(), "flow") {
		t.Errorf("error should mention flow: %v", err)
	}
	srv.set("applied", ssNode("h2.example.com", "n1"), ssNode("h1.example.com", "n3"))
	assertFileEquals(t, path, expectedFile(t, "s", srv.arg("s", "applied")))
	partial := listOutbounds(t, addr)
	if partial["s--n1"] == firstN1 {
		t.Error("s--n1 should already be updated")
	}
	if _, ok := partial["s--n3"]; !ok {
		t.Error("s--n3 should already be added")
	}
	if _, ok := partial["s--n2"]; ok {
		t.Error("s--n2 should be absent after failed ado")
	}

	srv.set("s", ssNode("h2.example.com", "n1"), vlessNode("n2", nil), ssNode("h1.example.com", "n3"))
	if err := runWatcher(dir, srv.arg("s", "s")); err != nil {
		t.Fatalf("third run failed: %v", err)
	}
	final := listOutbounds(t, addr)
	for _, tag := range []string{"s--n1", "s--n2", "s--n3"} {
		if _, ok := final[tag]; !ok {
			t.Errorf("expected outbound %q", tag)
		}
	}
	assertFileEquals(t, path, expectedFile(t, "s", srv.arg("s", "s")))
}

func TestHotReloadWritesAppliedStateWithRejectedNode(t *testing.T) {
	dir, addr := startHotReloadEnv(t)
	srv := newSubscriptionServer(t)
	path := filepath.Join(dir, "04_outbounds.s.json")
	srv.set("s", ssNode("h1.example.com", "ok1"), vlessNode("bad", map[string]string{"flow": "bogus"}))

	if err := runWatcher(dir, srv.arg("s", "s")); err == nil {
		t.Fatal("expected first run to fail")
	}
	srv.set("applied", ssNode("h1.example.com", "ok1"))
	assertFileEquals(t, path, expectedFile(t, "s", srv.arg("s", "applied")))
	if _, ok := listOutbounds(t, addr)["s--ok1"]; !ok {
		t.Error("expected outbound s--ok1")
	}
	if _, err := runXray(xrayDumpTimeout, nil, "run", "-test", "-confdir", dir); err != nil {
		t.Errorf("confdir should be loadable by xray: %v", err)
	}

	markOutbound(t, addr, "s--ok1")
	marked := listOutbounds(t, addr)["s--ok1"]
	if err := runWatcher(dir, srv.arg("s", "s")); err == nil {
		t.Fatal("expected second run to fail")
	}
	if got := listOutbounds(t, addr)["s--ok1"]; got != marked {
		t.Errorf("s--ok1 should not be re-applied:\nbefore: %s\nafter: %s", marked, got)
	}
}

func TestHotReloadWithoutAPI(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeTestFile(t, dir, "00_base.json", `{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}`)
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"))

	err := runWatcher(dir, srv.arg("s", "s"))
	if !errors.Is(err, errAPINotConfigured) {
		t.Errorf("expected errAPINotConfigured, got %v", err)
	}
	assertNoFile(t, filepath.Join(dir, "04_outbounds.s.json"))
}

func TestHotReloadXrayNotRunning(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeAPIConfig(t, dir)
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"))

	start := time.Now()
	err := runWatcher(dir, srv.arg("s", "s"))
	if err == nil {
		t.Fatal("expected error")
	}
	if elapsed := time.Since(start); elapsed >= 30*time.Second {
		t.Errorf("run took %v", elapsed)
	}
	assertNoFile(t, filepath.Join(dir, "04_outbounds.s.json"))
}

func TestHotReloadCorruptFileReportsName(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeAPIConfig(t, dir)
	writeTestFile(t, dir, "04_outbounds.s.json", `{"outbounds": [`)
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"))

	err := runWatcher(dir, srv.arg("s", "s"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "04_outbounds.s.json") {
		t.Errorf("error should mention the corrupt file: %v", err)
	}
}

func TestWriteReplacesFileAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "04_outbounds.s.json")
	writeTestFile(t, dir, "04_outbounds.s.json", "old\n")
	link := filepath.Join(t.TempDir(), "old-link")
	if err := os.Link(path, link); err != nil {
		t.Fatalf("link: %v", err)
	}

	update := &pendingUpdate{sub: subscription{tag: "s"}, path: path, newContent: []byte("new\n")}
	if err := update.write(update.newContent); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	assertFileEquals(t, path, []byte("new\n"))
	assertFileEquals(t, link, []byte("old\n"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only the target file, got %v", entries)
	}
}

func TestHotReloadNoChangesDoesNotCallXray(t *testing.T) {
	dir := t.TempDir()
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"))
	if err := runWatcher(dir, "--no-restart", srv.arg("s", "s")); err != nil {
		t.Fatalf("--no-restart run failed: %v", err)
	}
	setXrayBinary(t, filepath.Join(t.TempDir(), "missing-xray"))

	if err := runWatcher(dir, srv.arg("s", "s")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoRestartDoesNotCallXray(t *testing.T) {
	dir := t.TempDir()
	srv := newSubscriptionServer(t)
	srv.set("s", ssNode("h1.example.com", "n1"))
	setXrayBinary(t, filepath.Join(t.TempDir(), "missing-xray"))

	if err := runWatcher(dir, "--no-restart", srv.arg("s", "s")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "04_outbounds.s.json")); err != nil {
		t.Errorf("expected file to be written: %v", err)
	}
}
