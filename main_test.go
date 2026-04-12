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
	err := run([]string{"--output-dir", tmpDir, "--no-restart", "broken"})
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

func TestErrorWhenOutputDirIsNotDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "not-a-dir")
	if err := os.WriteFile(outputPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := run([]string{
		"--output-dir", outputPath,
		"--no-restart",
		"demo=http://example.com/sub",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "не является директорией") {
		t.Errorf("unexpected error: %v", err)
	}
}
