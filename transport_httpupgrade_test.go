package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func httpUpgradeSubscription() string {
	params := map[string]string{
		"type":     "httpupgrade",
		"security": "tls",
		"sni":      "front.example.com",
		"host":     "front.example.com",
		"path":     "/secret?ed=2048",
	}
	return makeVlessURL("11111111-2222-3333-4444-555555555555", "vl.example.com", 443, "vl", params) + "\n" +
		makeTrojanURL("trojan-pass", "tj.example.com", 443, "tj", params) + "\n" +
		makeVmessURL(map[string]any{
			"add":  "vm.example.com",
			"port": 443,
			"id":   "11111111-2222-3333-4444-555555555555",
			"net":  "httpupgrade",
			"tls":  "tls",
			"sni":  "front.example.com",
			"host": "front.example.com",
			"path": "/secret?ed=2048",
		}, "vm") + "\n"
}

func generateHTTPUpgradeConfig(t *testing.T) string {
	t.Helper()
	srv := newTestServer(map[string]testResponse{"/sub": {body: httpUpgradeSubscription()}})
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	if err := runMain(t, "--output-dir", dir, "--no-restart", "--no-hwid", fmt.Sprintf("hu=%s/sub", srv.URL)); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return dir
}

func TestHTTPUpgradeTransport(t *testing.T) {
	dir := generateHTTPUpgradeConfig(t)

	outbounds := loadConfig(t, dir, "hu")["outbounds"].([]any)
	if len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds, got %d", len(outbounds))
	}
	for _, o := range outbounds {
		out := o.(map[string]any)
		ss := out["streamSettings"].(map[string]any)
		if ss["network"] != "httpupgrade" {
			t.Errorf("%s: network = %v", out["tag"], ss["network"])
		}
		assertDeepEqual(t, ss["httpupgradeSettings"], map[string]any{
			"host": "front.example.com",
			"path": "/secret?ed=2048",
		})
	}
}

func TestHTTPUpgradeConfigLoadsInXray(t *testing.T) {
	requireXray(t)
	dir := generateHTTPUpgradeConfig(t)
	if err := os.WriteFile(filepath.Join(dir, "00_base.json"),
		[]byte(`{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := runXray(xrayDumpTimeout, nil, "run", "-test", "-confdir", dir); err != nil {
		t.Errorf("xray rejected generated config: %v", err)
	}
}
