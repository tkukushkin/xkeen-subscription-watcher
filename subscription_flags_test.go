package main

import (
	"log"
	"strings"
	"testing"
)

func TestTagAndURLFlags(t *testing.T) {
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))
	dir := t.TempDir()

	if err := run([]string{"--output-dir", dir, "--no-restart", "--no-hwid", "--tag", "s", "--url", sub.URL + "/s?token=a=b"}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	assertDeepEqual(t, configTags(loadConfig(t, dir, "s")), []string{"s--n1"})
}

func TestTagAndURLFlagsErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"url without tag", []string{"--url", "https://example.com/s"}, "нужно указывать вместе"},
		{"tag without url", []string{"--tag", "s"}, "нужно указывать вместе"},
		{"flags with positional", []string{"--tag", "s", "--url", "https://example.com/s", "other=https://example.com/o"}, "нельзя совмещать"},
		{"tag with equals sign", []string{"--tag", "a=b", "--url", "https://example.com/s"}, "не может содержать"},
		{"invalid url", []string{"--tag", "s", "--url", "ftp://example.com/s"}, "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(append([]string{"--output-dir", t.TempDir(), "--no-restart", "--no-hwid"}, tc.args...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestPositionalSubscriptionsDeprecationWarning(t *testing.T) {
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))
	logs := captureLog(t)

	if err := run([]string{"--output-dir", t.TempDir(), "--no-restart", "--no-hwid", "s=" + sub.URL + "/s"}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !strings.Contains(logs.String(), "устарел") || !strings.Contains(logs.String(), "--tag") {
		t.Errorf("expected deprecation warning mentioning --tag, got logs:\n%s", logs.String())
	}
}

func TestTagAndURLFlagsNoDeprecationWarning(t *testing.T) {
	sub := newHeaderRecorder(t, ssNode("h1.example.com", "n1"))
	logs := captureLog(t)

	if err := run([]string{"--output-dir", t.TempDir(), "--no-restart", "--no-hwid", "--tag", "s", "--url", sub.URL + "/s"}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if strings.Contains(logs.String(), "устарел") {
		t.Errorf("unexpected deprecation warning:\n%s", logs.String())
	}
}
