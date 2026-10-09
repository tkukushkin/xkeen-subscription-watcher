package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testResponse struct {
	body       string
	statusCode int
}

func newTestServer(responses map[string]testResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
			return
		}
		sc := resp.statusCode
		if sc == 0 {
			sc = 200
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(sc)
		w.Write([]byte(resp.body))
	}))
}

func loadConfig(t *testing.T, dir, tag string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("04_outbounds.%s.json", tag)))
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	return result
}

func encodeSubscription(lines ...string) string {
	payload := strings.Join(lines, "\n")
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func makeVlessURL(userID, host string, port int, fragment string, params map[string]string) string {
	netloc := fmt.Sprintf("%s@%s", userID, host)
	if port > 0 {
		netloc += fmt.Sprintf(":%d", port)
	}
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	u := fmt.Sprintf("vless://%s?%s", netloc, q.Encode())
	if fragment != "" {
		u += "#" + fragment
	}
	return u
}

func makeSSURL(method, password, host string, port int, fragment string) string {
	auth := base64.StdEncoding.EncodeToString([]byte(method + ":" + password))
	netloc := fmt.Sprintf("%s@%s", auth, host)
	if port > 0 {
		netloc += fmt.Sprintf(":%d", port)
	}
	u := fmt.Sprintf("ss://%s", netloc)
	if fragment != "" {
		u += "#" + fragment
	}
	return u
}

func makeVmessURL(fields map[string]any, fragment string) string {
	data, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	u := "vmess://" + base64.StdEncoding.EncodeToString(data)
	if fragment != "" {
		u += "#" + fragment
	}
	return u
}

func makeTrojanURL(password, host string, port int, fragment string, params map[string]string) string {
	netloc := fmt.Sprintf("%s@%s", password, host)
	if port > 0 {
		netloc += fmt.Sprintf(":%d", port)
	}
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	u := fmt.Sprintf("trojan://%s?%s", netloc, q.Encode())
	if fragment != "" {
		u += "#" + fragment
	}
	return u
}

func runMain(t *testing.T, args ...string) error {
	t.Helper()
	return run(args)
}

func assertDeepEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("mismatch:\ngot:\n%s\n\nwant:\n%s", gotJSON, wantJSON)
	}
}

func TestGeneratesConfigFromPlaintextSubscription(t *testing.T) {
	srv := newTestServer(map[string]testResponse{
		"/sub": {
			body: "vless://user@example.com:443" +
				"?type=tcp&security=reality&sni=edge.example.com&pbk=pubkey&flow=xtls-rprx-vision" +
				"# First Node\n",
		},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("demo=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "demo")
	want := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "demo--First Node",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": "example.com",
							"port":    float64(443),
							"users": []any{
								map[string]any{
									"id":         "user",
									"encryption": "none",
									"flow":       "xtls-rprx-vision",
								},
							},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  "edge.example.com",
						"fingerprint": "chrome",
						"publicKey":   "pubkey",
					},
				},
			},
		},
	}

	assertDeepEqual(t, got, want)
}

func TestGeneratesSortedConfigFromBase64Subscription(t *testing.T) {
	vlessURL := makeVlessURL("uuid-1", "alpha.example.com", 0, "Fancy/Node!", map[string]string{
		"type":     "grpc",
		"security": "reality",
		"sni":      "alpha.example.com",
		"pbk":      "pub-alpha",
		"flow":     "xtls-rprx-vision",
		"sid":      "short-id",
		"spx":      "/grpc",
	})
	ssURL := makeSSURL("aes-256-gcm", "passw0rd", "beta.example.com", 0, "")

	srv := newTestServer(map[string]testResponse{
		"/sub": {
			body: encodeSubscription(
				"unknown://ignored",
				vlessURL,
				ssURL,
				"",
			),
		},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("mix=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "mix")
	want := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "mix",
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"servers": []any{
						map[string]any{
							"address":  "beta.example.com",
							"port":     float64(443),
							"method":   "aes-256-gcm",
							"password": "passw0rd",
						},
					},
				},
			},
			map[string]any{
				"tag":      "mix--FancyNode",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": "alpha.example.com",
							"port":    float64(443),
							"users": []any{
								map[string]any{
									"id":         "uuid-1",
									"encryption": "none",
									"flow":       "xtls-rprx-vision",
								},
							},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "grpc",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  "alpha.example.com",
						"fingerprint": "chrome",
						"publicKey":   "pub-alpha",
						"spiderX":     "/grpc",
						"shortId":     "short-id",
					},
				},
			},
		},
	}

	assertDeepEqual(t, got, want)
}

func TestAddsDialerProxyVariants(t *testing.T) {
	vlessURL := makeVlessURL("uuid-2", "dial.example.com", 443, "Dial Node", map[string]string{
		"type":     "ws",
		"security": "reality",
		"sni":      "dial.example.com",
		"pbk":      "pub-dial",
		"flow":     "xtls-rprx-vision",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: vlessURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"--dialer-proxies=warp,tor",
		fmt.Sprintf("dial=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "dial")

	baseStreamSettings := map[string]any{
		"network":  "ws",
		"security": "reality",
		"realitySettings": map[string]any{
			"serverName":  "dial.example.com",
			"fingerprint": "chrome",
			"publicKey":   "pub-dial",
		},
	}

	baseVnext := []any{
		map[string]any{
			"address": "dial.example.com",
			"port":    float64(443),
			"users": []any{
				map[string]any{
					"id":         "uuid-2",
					"encryption": "none",
					"flow":       "xtls-rprx-vision",
				},
			},
		},
	}

	want := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "dial--Dial Node",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": baseVnext,
				},
				"streamSettings": baseStreamSettings,
			},
			map[string]any{
				"tag":      "dial--Dial Node--warp",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": baseVnext,
				},
				"streamSettings": map[string]any{
					"network":  "ws",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  "dial.example.com",
						"fingerprint": "chrome",
						"publicKey":   "pub-dial",
					},
					"sockopt": map[string]any{"dialerProxy": "warp"},
				},
			},
			map[string]any{
				"tag":      "dial--Dial Node--tor",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": baseVnext,
				},
				"streamSettings": map[string]any{
					"network":  "ws",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  "dial.example.com",
						"fingerprint": "chrome",
						"publicKey":   "pub-dial",
					},
					"sockopt": map[string]any{"dialerProxy": "tor"},
				},
			},
		},
	}

	assertDeepEqual(t, got, want)
}

func TestDoesNotRewriteUnchangedConfig(t *testing.T) {
	ssURL := makeSSURL("aes-128-gcm", "same", "stable.example.com", 8388, "")

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: ssURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	args := []string{
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("stable=%s/sub", srv.URL),
	}

	if err := run(args); err != nil {
		t.Fatalf("first run failed: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "04_outbounds.stable.json")
	firstContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	firstInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat config: %v", err)
	}
	firstMtime := firstInfo.ModTime()

	time.Sleep(20 * time.Millisecond)

	if err := run(args); err != nil {
		t.Fatalf("second run failed: %v", err)
	}

	secondContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read config after second run: %v", err)
	}
	secondInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat config after second run: %v", err)
	}

	if string(secondContent) != string(firstContent) {
		t.Error("config content changed on second run")
	}
	if !secondInfo.ModTime().Equal(firstMtime) {
		t.Error("config mtime changed on second run")
	}
}

func TestContinuesWhenOneSubscriptionFails(t *testing.T) {
	ssURL := makeSSURL("chacha20-ietf-poly1305", "secret", "ok.example.com", 8388, "ok")

	srv := newTestServer(map[string]testResponse{
		"/ok":  {body: ssURL},
		"/bad": {body: "server error", statusCode: 500},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("good=%s/ok", srv.URL),
		fmt.Sprintf("bad=%s/bad", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "04_outbounds.good.json")); err != nil {
		t.Error("expected good config to exist")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "04_outbounds.bad.json")); err == nil {
		t.Error("expected bad config to not exist")
	}
}

func TestErrorForSubscriptionWithoutSeparator(t *testing.T) {
	tmpDir := t.TempDir()
	err := run([]string{"--output-dir", tmpDir, "--no-restart", "--no-hot-reload", "broken"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "неверный формат подписки") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestErrorForDuplicateTags(t *testing.T) {
	tmpDir := t.TempDir()
	err := run([]string{
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"dup=http://example.com/one",
		"dup=http://example.com/two",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "указан несколько раз") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestErrorForInvalidURLScheme(t *testing.T) {
	tmpDir := t.TempDir()
	err := run([]string{
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"demo=ftp://example.com/sub",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "URL должен начинаться") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVersionCommand(t *testing.T) {
	cmd := newRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	if got != getVersion() {
		t.Errorf("got %q, want %q", got, getVersion())
	}
}

func TestHysteria2Subscription(t *testing.T) {
	srv := newTestServer(map[string]testResponse{
		"/sub": {
			body: "hysteria2://myauth@hy2.example.com:8443?sni=hy2.example.com&insecure=1#HY2 Node\n",
		},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("hy=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "hy")
	want := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "hy--HY2 Node",
				"protocol": "hysteria",
				"settings": map[string]any{
					"version": float64(2),
					"address": "hy2.example.com",
					"port":    float64(8443),
				},
				"streamSettings": map[string]any{
					"network":  "hysteria",
					"security": "tls",
					"tlsSettings": map[string]any{
						"serverName":    "hy2.example.com",
						"allowInsecure": true,
					},
					"hysteriaSettings": map[string]any{
						"version":         float64(2),
						"auth":            "myauth",
						"keepAlivePeriod": float64(5),
					},
				},
			},
		},
	}

	assertDeepEqual(t, got, want)
}

func TestHysteria2FallbackSNI(t *testing.T) {
	srv := newTestServer(map[string]testResponse{
		"/sub": {
			body: "hysteria2://auth@fallback.example.com:443#node\n",
		},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("fb=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "fb")
	outbounds := got["outbounds"].([]any)
	out := outbounds[0].(map[string]any)
	ss := out["streamSettings"].(map[string]any)
	tls := ss["tlsSettings"].(map[string]any)

	if tls["serverName"] != "fallback.example.com" {
		t.Errorf("expected SNI fallback to address, got %q", tls["serverName"])
	}
	if tls["allowInsecure"] != false {
		t.Error("expected allowInsecure=false when insecure not set")
	}
}

func TestVlessXhttpSettings(t *testing.T) {
	vlessURL := makeVlessURL("user", "xhttp.example.com", 443, "XNode", map[string]string{
		"type":     "xhttp",
		"security": "reality",
		"sni":      "xhttp.example.com",
		"pbk":      "pub-xhttp",
		"host":     "cdn.example.com",
		"path":     "%2Fmy-path",
		"mode":     "auto",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: vlessURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("xh=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "xh")
	outbounds := got["outbounds"].([]any)
	out := outbounds[0].(map[string]any)
	ss := out["streamSettings"].(map[string]any)
	xhttp := ss["xhttpSettings"].(map[string]any)

	if xhttp["host"] != "cdn.example.com" {
		t.Errorf("expected host cdn.example.com, got %q", xhttp["host"])
	}
	if xhttp["path"] != "/my-path" {
		t.Errorf("expected path /my-path, got %q", xhttp["path"])
	}
	if xhttp["mode"] != "auto" {
		t.Errorf("expected mode auto, got %q", xhttp["mode"])
	}
}

func TestRealityFingerprintOverride(t *testing.T) {
	vlessURL := makeVlessURL("user", "fp.example.com", 443, "FP", map[string]string{
		"type":     "tcp",
		"security": "reality",
		"sni":      "fp.example.com",
		"pbk":      "pub-fp",
		"fp":       "firefox",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: vlessURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"--reality-fingerprint=safari",
		fmt.Sprintf("fp=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "fp")
	outbounds := got["outbounds"].([]any)
	out := outbounds[0].(map[string]any)
	ss := out["streamSettings"].(map[string]any)
	rs := ss["realitySettings"].(map[string]any)

	if rs["fingerprint"] != "safari" {
		t.Errorf("expected fingerprint override to safari, got %q", rs["fingerprint"])
	}
}

func TestVlessFingerprintFromProxy(t *testing.T) {
	vlessURL := makeVlessURL("user", "fp2.example.com", 443, "FP2", map[string]string{
		"type":     "tcp",
		"security": "reality",
		"sni":      "fp2.example.com",
		"pbk":      "pub-fp2",
		"fp":       "firefox",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: vlessURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("fp2=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "fp2")
	outbounds := got["outbounds"].([]any)
	out := outbounds[0].(map[string]any)
	ss := out["streamSettings"].(map[string]any)
	rs := ss["realitySettings"].(map[string]any)

	if rs["fingerprint"] != "firefox" {
		t.Errorf("expected fingerprint from proxy firefox, got %q", rs["fingerprint"])
	}
}

func TestSingleProxyMode(t *testing.T) {
	srv := newTestServer(map[string]testResponse{
		"/sub": {
			body: makeSSURL("aes-256-gcm", "p1", "first.example.com", 8388, "First") + "\n" +
				makeSSURL("aes-256-gcm", "p2", "second.example.com", 8388, "Second") + "\n",
		},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"--single-proxy",
		fmt.Sprintf("sp=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "sp")
	outbounds := got["outbounds"].([]any)

	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound in single-proxy mode, got %d", len(outbounds))
	}
	out := outbounds[0].(map[string]any)
	if out["tag"] != "sp" {
		t.Errorf("expected tag 'sp' without proxy name, got %q", out["tag"])
	}
}

func TestDialerProxyOnShadowsocks(t *testing.T) {
	ssURL := makeSSURL("aes-256-gcm", "pass", "ss.example.com", 8388, "SS")

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: ssURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"--dialer-proxies=warp",
		fmt.Sprintf("ssd=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "ssd")
	outbounds := got["outbounds"].([]any)

	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}

	dialerOut := outbounds[1].(map[string]any)
	if dialerOut["tag"] != "ssd--SS--warp" {
		t.Errorf("expected tag ssd--SS--warp, got %q", dialerOut["tag"])
	}
	ss := dialerOut["streamSettings"].(map[string]any)
	sockopt := ss["sockopt"].(map[string]any)
	if sockopt["dialerProxy"] != "warp" {
		t.Errorf("expected dialerProxy warp, got %q", sockopt["dialerProxy"])
	}
}

func TestVmessSubscription(t *testing.T) {
	vmessURL := makeVmessURL(map[string]any{
		"v":    "2",
		"add":  "vm.example.com",
		"port": 443,
		"id":   "vm-uuid",
		"aid":  0,
		"scy":  "auto",
		"net":  "ws",
		"type": "none",
		"tls":  "tls",
		"sni":  "vm.example.com",
		"host": "cdn.example.com",
		"path": "/ws",
	}, "VM Node")

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: vmessURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("vm=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "vm")
	want := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "vm--VM Node",
				"protocol": "vmess",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": "vm.example.com",
							"port":    float64(443),
							"users": []any{
								map[string]any{
									"id":       "vm-uuid",
									"alterId":  float64(0),
									"security": "auto",
								},
							},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "ws",
					"security": "tls",
					"tlsSettings": map[string]any{
						"serverName":    "vm.example.com",
						"allowInsecure": false,
						"fingerprint":   "chrome",
					},
					"wsSettings": map[string]any{
						"path": "/ws",
						"host": "cdn.example.com",
					},
				},
			},
		},
	}

	assertDeepEqual(t, got, want)
}

func TestVmessFlexIntStringValues(t *testing.T) {
	vmessURL := makeVmessURL(map[string]any{
		"add":  "flex.example.com",
		"port": "8443", // string instead of number
		"id":   "flex-uuid",
		"aid":  "1", // string instead of number
		"net":  "tcp",
		"tls":  "",
	}, "")

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: vmessURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("flex=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "flex")
	outbounds := got["outbounds"].([]any)
	out := outbounds[0].(map[string]any)
	vnext := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)

	if vnext["port"] != float64(8443) {
		t.Errorf("expected port 8443 from string, got %v", vnext["port"])
	}
	users := vnext["users"].([]any)[0].(map[string]any)
	if users["alterId"] != float64(1) {
		t.Errorf("expected alterId 1 from string, got %v", users["alterId"])
	}
	ss := out["streamSettings"].(map[string]any)
	if ss["security"] != "none" {
		t.Errorf("expected security none without tls, got %v", ss["security"])
	}
	if _, ok := ss["tlsSettings"]; ok {
		t.Error("did not expect tlsSettings without tls")
	}
}

func TestTrojanSubscription(t *testing.T) {
	trojanURL := makeTrojanURL("trojan-pass", "tj.example.com", 443, "TJ Node", map[string]string{
		"security":    "tls",
		"type":        "grpc",
		"sni":         "tj.example.com",
		"serviceName": "grpc-svc",
		"fp":          "firefox",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: trojanURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("tj=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "tj")
	want := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "tj--TJ Node",
				"protocol": "trojan",
				"settings": map[string]any{
					"servers": []any{
						map[string]any{
							"address":  "tj.example.com",
							"port":     float64(443),
							"password": "trojan-pass",
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "grpc",
					"security": "tls",
					"tlsSettings": map[string]any{
						"serverName":    "tj.example.com",
						"allowInsecure": false,
						"fingerprint":   "firefox",
					},
					"grpcSettings": map[string]any{
						"serviceName": "grpc-svc",
					},
				},
			},
		},
	}

	assertDeepEqual(t, got, want)
}

func TestTrojanTcpNoTransportBlock(t *testing.T) {
	trojanURL := makeTrojanURL("pw", "t2.example.com", 443, "T2", map[string]string{
		"security": "tls",
		"type":     "tcp",
		"sni":      "t2.example.com",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: trojanURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("t2=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "t2")
	ss := got["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	for _, key := range []string{"wsSettings", "grpcSettings", "xhttpSettings"} {
		if _, ok := ss[key]; ok {
			t.Errorf("did not expect %s for tcp transport", key)
		}
	}
	if _, ok := ss["tlsSettings"]; !ok {
		t.Error("expected tlsSettings for tls security")
	}
}

func TestSkipsUnsupportedTransport(t *testing.T) {
	badVmess := makeVmessURL(map[string]any{
		"add":  "bad.example.com",
		"port": 443,
		"id":   "bad-uuid",
		"net":  "h2", // removed in modern Xray -> must be skipped
		"tls":  "tls",
	}, "Bad")
	goodTrojan := makeTrojanURL("pw", "good.example.com", 443, "Good", map[string]string{
		"security": "tls",
		"type":     "tcp",
		"sni":      "good.example.com",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: badVmess + "\n" + goodTrojan + "\n"},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		fmt.Sprintf("mix=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "mix")
	outbounds := got["outbounds"].([]any)
	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound (bad transport skipped), got %d", len(outbounds))
	}
	out := outbounds[0].(map[string]any)
	if out["protocol"] != "trojan" {
		t.Errorf("expected the surviving outbound to be trojan, got %v", out["protocol"])
	}
}

func TestDialerProxyOnTrojan(t *testing.T) {
	trojanURL := makeTrojanURL("pw", "td.example.com", 443, "TD", map[string]string{
		"security": "tls",
		"type":     "tcp",
		"sni":      "td.example.com",
	})

	srv := newTestServer(map[string]testResponse{
		"/sub": {body: trojanURL},
	})
	defer srv.Close()

	tmpDir := t.TempDir()
	err := runMain(t,
		"--output-dir", tmpDir,
		"--no-restart",
		"--no-hot-reload",
		"--dialer-proxies=warp",
		fmt.Sprintf("td=%s/sub", srv.URL),
	)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := loadConfig(t, tmpDir, "td")
	outbounds := got["outbounds"].([]any)
	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}
	dialerOut := outbounds[1].(map[string]any)
	if dialerOut["tag"] != "td--TD--warp" {
		t.Errorf("expected tag td--TD--warp, got %q", dialerOut["tag"])
	}
	ss := dialerOut["streamSettings"].(map[string]any)
	sockopt := ss["sockopt"].(map[string]any)
	if sockopt["dialerProxy"] != "warp" {
		t.Errorf("expected dialerProxy warp, got %q", sockopt["dialerProxy"])
	}
}

func TestParseProxyURLErrors(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"unsupported scheme", "wireguard://user@host:443", "неподдерживаемая схема"},
		{"empty hostname", "vless://user@:443?type=tcp&security=reality&sni=s&pbk=p", "адрес сервера"},
		{"missing ss credentials", "ss://@host:443", "имя пользователя"},
		{"bad ss base64", "ss://not-base64@host:443", "декодирования SS"},
		{"ss credentials no colon", "ss://" + base64.StdEncoding.EncodeToString([]byte("nocolon")) + "@host:443", "формат SS credentials"},
		{"vless missing user", "vless://@host:443?type=tcp&security=reality&sni=s&pbk=p", "идентификатор пользователя"},
		{"trojan missing password", "trojan://@host:443?security=tls", "пароль"},
		{"trojan unsupported transport", "trojan://pw@host:443?type=quic", "неподдерживаемый транспорт"},
		{"vmess bad base64", "vmess://!!!not-base64!!!", "декодирования vmess"},
		{"vmess bad json", "vmess://" + base64.StdEncoding.EncodeToString([]byte("not json")), "парсинга vmess"},
		{"vmess missing add", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"id":"x"}`)), "адрес сервера"},
		{"vmess missing id", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"h"}`)), "идентификатор пользователя"},
		{"vmess unsupported transport", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"h","id":"x","net":"h2"}`)), "неподдерживаемый транспорт"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseProxyURL(tt.url)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestNoSubscriptionsError(t *testing.T) {
	tmpDir := t.TempDir()
	err := run([]string{"--output-dir", tmpDir, "--no-restart", "--no-hot-reload"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "не указаны подписки") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestErrorWhenOutputDirIsNotDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "not-a-dir")
	if err := os.WriteFile(outputPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := run([]string{
		"--output-dir", outputPath,
		"--no-restart",
		"--no-hot-reload",
		"demo=http://example.com/sub",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "не является директорией") {
		t.Errorf("unexpected error: %v", err)
	}
}
