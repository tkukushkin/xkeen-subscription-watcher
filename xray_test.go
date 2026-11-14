package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func requireXray(t *testing.T) {
	t.Helper()
	bin := os.Getenv("XRAY_BINARY")
	if bin == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("XRAY_BINARY is not set")
		}
		t.Skip("XRAY_BINARY is not set")
	}
	setXrayBinary(t, bin)
}

func setXrayBinary(t *testing.T, bin string) {
	t.Helper()
	prev := xrayBinary
	xrayBinary = bin
	t.Cleanup(func() { xrayBinary = prev })
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeAPIConfig(t *testing.T, dir string) string {
	t.Helper()
	addr := freeAddr(t)
	writeTestFile(t, dir, "00_base.json", fmt.Sprintf(`{
  "api": {"tag": "api", "listen": %q, "services": ["HandlerService"]},
  "outbounds": [{"tag": "direct", "protocol": "freedom"}]
}`, addr))
	return addr
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startXray(t *testing.T, dir, addr string) {
	t.Helper()
	var output syncBuffer
	cmd := exec.Command(xrayBinary, "run", "-confdir", dir)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start xray: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("xray exited before API became ready: %v\n%s", err, output.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("xray API at %s did not become ready\n%s", addr, output.String())
}

func listOutbounds(t *testing.T, addr string) map[string]string {
	t.Helper()
	out, err := exec.Command(xrayBinary, "api", "lso", "-s", addr, "-t", "5").Output()
	if err != nil {
		t.Fatalf("xray api lso failed: %v", err)
	}
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to parse lso output: %v\n%s", err, out)
	}
	result := make(map[string]string)
	for _, raw := range parsed.Outbounds {
		var o struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatalf("failed to parse outbound: %v\n%s", err, raw)
		}
		result[o.Tag] = string(raw)
	}
	return result
}

func TestFindAPIAddress(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	addr := writeAPIConfig(t, dir)

	got, err := findAPIAddress(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != addr {
		t.Errorf("got %q, want %q", got, addr)
	}
}

func TestFindAPIAddressCaseInsensitive(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeTestFile(t, dir, "00_base.json", `{
  "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["handlerservice", "StatsService"]}
}`)

	got, err := findAPIAddress(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "127.0.0.1:10085" {
		t.Errorf("got %q", got)
	}
}

func TestFindAPIAddressWithoutAPI(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeTestFile(t, dir, "00_base.json", `{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}`)

	_, err := findAPIAddress(dir)
	if !errors.Is(err, errAPINotConfigured) {
		t.Errorf("expected errAPINotConfigured, got %v", err)
	}
}

func TestFindAPIAddressWithoutHandlerService(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeTestFile(t, dir, "00_base.json", `{
  "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]}
}`)

	_, err := findAPIAddress(dir)
	if !errors.Is(err, errAPINotConfigured) {
		t.Errorf("expected errAPINotConfigured, got %v", err)
	}
}

func TestXrayAPIAddReplaceRemove(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	addr := writeAPIConfig(t, dir)
	startXray(t, dir, addr)
	api := xrayAPI{addr: addr}
	outbound := map[string]any{"tag": "x", "protocol": "freedom"}

	if err := api.addOutbound(outbound); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	if _, ok := listOutbounds(t, addr)["x"]; !ok {
		t.Fatal("expected outbound x after add")
	}
	if err := api.addOutbound(outbound); err == nil {
		t.Error("expected error when adding existing tag")
	}

	if err := api.removeOutbound("x"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if _, ok := listOutbounds(t, addr)["x"]; ok {
		t.Error("expected outbound x to be removed")
	}
	if err := api.removeOutbound("x"); err != nil {
		t.Errorf("removing missing tag should succeed: %v", err)
	}
}
