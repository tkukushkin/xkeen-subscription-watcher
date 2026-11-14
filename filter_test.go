package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestGlobMatching(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*Russia*", "🇷🇺 Russia 1", true},
		{"*russia*", "🇷🇺 RUSSIA 1", true},
		{"*Russia*", "🇩🇪 Germany 1", false},
		{"Russia", "🇷🇺 Russia 1", false},
		{"*🇷🇺*", "🇷🇺 Moscow", true},
		{"*Россия*", "Россия, Москва", true},
		{"DE-?", "DE-1", true},
		{"DE-?", "DE-12", false},
		{"[DF]*", "DE-1", true},
		{"[DF]*", "NL-1", false},
		{"[^R]*", "Russia", false},
		{"[^R]*", "Germany", true},
		{"*", "a/b", true},
		{"*Frankfurt*", "DE / Frankfurt", true},
		{"DE?Frankfurt", "DE/Frankfurt", true},
		{"a.b", "axb", false},
		{"a+b", "a+b", true},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"|"+tc.name, func(t *testing.T) {
			f, err := newNameFilter([]string{tc.pattern}, nil)
			if err != nil {
				t.Fatalf("newNameFilter(%q): %v", tc.pattern, err)
			}
			if got := f.allows(tc.name); got != tc.want {
				t.Errorf("match(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
			}
		})
	}
}

func filterSubscription() string {
	return strings.Join([]string{
		ssNode("ru.example.com", "%F0%9F%87%B7%F0%9F%87%BA%20Russia%201"),
		ssNode("de.example.com", "%F0%9F%87%A9%F0%9F%87%AA%20Germany%201"),
		ssNode("fi.example.com", "%F0%9F%87%AB%F0%9F%87%AE%20Finland%201"),
		ssNode("noname.example.com", ""),
	}, "\n")
}

func runFilter(t *testing.T, args ...string) (map[string]any, *headerRecorder) {
	t.Helper()
	sub := newHeaderRecorder(t, filterSubscription())
	dir := t.TempDir()
	all := append([]string{"--output-dir", dir, "--no-restart", "--no-hwid"}, args...)
	all = append(all, fmt.Sprintf("s=%s/s", sub.URL))
	if err := run(all); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return loadConfig(t, dir, "s"), sub
}

func configTags(cfg map[string]any) []string {
	tags := []string{}
	outbounds, _ := cfg["outbounds"].([]any)
	for _, o := range outbounds {
		tags = append(tags, o.(map[string]any)["tag"].(string))
	}
	return tags
}

func TestExcludeFilter(t *testing.T) {
	cfg, _ := runFilter(t, "--exclude", "*Russia*")
	assertDeepEqual(t, configTags(cfg), []string{"s--Germany 1", "s--Finland 1", "s"})
}

func TestExcludeFilterByEmoji(t *testing.T) {
	cfg, _ := runFilter(t, "--exclude", "*🇷🇺*")
	assertDeepEqual(t, configTags(cfg), []string{"s--Germany 1", "s--Finland 1", "s"})
}

func TestIncludeFilterRepeated(t *testing.T) {
	cfg, _ := runFilter(t, "--include", "*germany*", "--include", "*Finland*")
	assertDeepEqual(t, configTags(cfg), []string{"s--Germany 1", "s--Finland 1"})
}

func TestIncludeThenExclude(t *testing.T) {
	cfg, _ := runFilter(t, "--include", "* 1", "--exclude", "*Russia*", "--exclude", "*Finland*")
	assertDeepEqual(t, configTags(cfg), []string{"s--Germany 1"})
}

func TestFilterLeavesNothing(t *testing.T) {
	cfg, _ := runFilter(t, "--include", "*Narnia*")
	assertDeepEqual(t, configTags(cfg), []string{})
}

func TestFilterAppliesBeforeSingleProxy(t *testing.T) {
	cfg, _ := runFilter(t, "--single-proxy", "--exclude", "*Russia*")
	assertDeepEqual(t, configTags(cfg), []string{"s"})
	outbound := cfg["outbounds"].([]any)[0].(map[string]any)
	address := outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["address"]
	if address != "de.example.com" {
		t.Errorf("expected first remaining node de.example.com, got %v", address)
	}
}

func TestInvalidGlobFailsBeforeFetching(t *testing.T) {
	sub := newHeaderRecorder(t, filterSubscription())
	err := run([]string{"--output-dir", t.TempDir(), "--no-restart", "--no-hwid", "--exclude", "[abc", fmt.Sprintf("s=%s/s", sub.URL)})
	if err == nil || !strings.Contains(err.Error(), "[abc") {
		t.Errorf("expected error mentioning the pattern, got %v", err)
	}
	if sub.count() != 0 {
		t.Error("subscription must not be fetched with an invalid pattern")
	}
}
