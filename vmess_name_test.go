package main

import (
	"fmt"
	"strings"
	"testing"
)

func vmessNode(ps, fragment string) string {
	fields := map[string]any{
		"add":  "vm.example.com",
		"port": 443,
		"id":   "11111111-2222-3333-4444-555555555555",
		"net":  "tcp",
		"tls":  "tls",
	}
	if ps != "" {
		fields["ps"] = ps
	}
	return makeVmessURL(fields, fragment)
}

func runVmessSubscription(t *testing.T, body string, args ...string) map[string]any {
	t.Helper()
	srv := newTestServer(map[string]testResponse{"/sub": {body: body}})
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	all := append([]string{"--output-dir", dir, "--no-restart", "--no-hwid"}, args...)
	all = append(all, fmt.Sprintf("s=%s/sub", srv.URL))
	if err := run(all); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return loadConfig(t, dir, "s")
}

func TestVmessNameFromPS(t *testing.T) {
	cfg := runVmessSubscription(t, vmessNode("🇩🇪 Germany 1", ""))
	assertDeepEqual(t, configTags(cfg), []string{"s--Germany 1"})
}

func TestVmessFragmentTakesPriorityOverPS(t *testing.T) {
	cfg := runVmessSubscription(t, vmessNode("From PS", "From Fragment"))
	assertDeepEqual(t, configTags(cfg), []string{"s--From Fragment"})
}

func TestVmessFilterByPS(t *testing.T) {
	body := strings.Join([]string{vmessNode("🇷🇺 Russia 1", ""), vmessNode("🇩🇪 Germany 1", "")}, "\n")
	cfg := runVmessSubscription(t, body, "--exclude", "*🇷🇺*")
	assertDeepEqual(t, configTags(cfg), []string{"s--Germany 1"})
}
