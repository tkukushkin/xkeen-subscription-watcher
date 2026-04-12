package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

func fetchProxyURLs(sub subscription) ([]string, error) {
	body, err := doHTTPRequest(sub.url, false)
	if err != nil {
		log.Printf("Не удалось получить подписку %q без прокси, пробуем с прокси: %v", sub.tag, err)
		body, err = doHTTPRequest(sub.url, true)
		if err != nil {
			return nil, err
		}
	}

	return parseSubscriptionResponse(body), nil
}

func doHTTPRequest(requestURL string, withProxy bool) (string, error) {
	var transport *http.Transport
	if withProxy {
		proxyURL, _ := url.Parse("http://127.0.0.1:8080")
		transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	} else {
		transport = &http.Transport{}
	}

	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(requestURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return string(bodyBytes), nil
}

func parseSubscriptionResponse(body string) []string {
	body = strings.TrimSpace(body)

	decoded, err := base64.StdEncoding.DecodeString(body)
	if err == nil {
		body = strings.TrimSpace(string(decoded))
	}

	var result []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "vless://") ||
			strings.HasPrefix(line, "ss://") ||
			strings.HasPrefix(line, "hysteria2://") {
			result = append(result, line)
		}
	}

	return result
}

func getProxyName(rawURL string) string {
	idx := strings.LastIndex(rawURL, "#")
	if idx < 0 {
		return ""
	}
	name, err := url.QueryUnescape(strings.TrimSpace(rawURL[idx+1:]))
	if err != nil {
		name = strings.TrimSpace(rawURL[idx+1:])
	}
	var b strings.Builder
	for _, c := range name {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == ' ' || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}
