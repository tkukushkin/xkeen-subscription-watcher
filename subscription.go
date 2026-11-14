package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// fetchProxyURLs запрашивает подписку; device == nil означает, что заголовки HWID не отправляются.
func fetchProxyURLs(sub subscription, device *deviceInfo) ([]string, error) {
	body, err := doHTTPRequest(sub.url, false, device)
	if err != nil {
		log.Printf("Не удалось получить подписку %q без прокси, пробуем с прокси: %v", sub.tag, err)
		body, err = doHTTPRequest(sub.url, true, device)
		if err != nil {
			return nil, err
		}
	}

	return parseSubscriptionResponse(body), nil
}

func doHTTPRequest(requestURL string, withProxy bool, device *deviceInfo) (string, error) {
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

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", err
	}
	if device != nil {
		device.setHeaders(req.Header)
	}
	resp, err := client.Do(req)
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
			strings.HasPrefix(line, "vmess://") ||
			strings.HasPrefix(line, "trojan://") ||
			strings.HasPrefix(line, "ss://") ||
			strings.HasPrefix(line, "hysteria2://") {
			result = append(result, line)
		}
	}

	return result
}

// rawProxyName возвращает декодированное имя узла без очистки: из фрагмента URL, а у vmess без
// фрагмента — из поля ps.
func rawProxyName(rawURL string) string {
	idx := strings.LastIndex(rawURL, "#")
	if idx < 0 {
		if strings.HasPrefix(rawURL, "vmess://") {
			return vmessName(rawURL)
		}
		return ""
	}
	fragment := strings.TrimSpace(rawURL[idx+1:])
	if name, err := url.QueryUnescape(fragment); err == nil {
		return strings.TrimSpace(name)
	}
	return fragment
}

func vmessName(rawURL string) string {
	decoded, err := decodeVmessPayload(rawURL)
	if err != nil {
		return ""
	}
	var payload struct {
		PS string `json:"ps"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.PS)
}

// getProxyName возвращает имя узла для тега: только буквы, цифры, пробел, `-` и `_`.
func getProxyName(rawURL string) string {
	var b strings.Builder
	for _, c := range rawProxyName(rawURL) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == ' ' || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}
