package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type proxy interface {
	isProxy()
}

// streamParams holds the security/transport settings shared by the TLS/transport
// family of protocols (vless, vmess, trojan). It is consumed by buildStreamSettings.
type streamParams struct {
	network       string // tcp | raw | ws | grpc | xhttp (xhttp: vless only)
	security      string // reality | tls | none
	serverName    string // sni
	fingerprint   string // fp (utls)
	alpn          []string
	allowInsecure bool
	// reality (vless)
	publicKey string
	shortID   string
	spiderX   string
	// transports
	host        string
	path        string
	mode        string
	serviceName string // grpc
}

type vlessProxy struct {
	streamParams
	address    string
	port       int
	userID     string
	encryption string
	flow       string
}

func (vlessProxy) isProxy() {}

type vmessProxy struct {
	streamParams
	address  string
	port     int
	userID   string
	alterID  int
	security string // scy (cipher): auto | aes-128-gcm | ...
}

func (vmessProxy) isProxy() {}

type trojanProxy struct {
	streamParams
	address  string
	port     int
	password string
	flow     string
}

func (trojanProxy) isProxy() {}

type shadowSocksProxy struct {
	address  string
	port     int
	method   string
	password string
}

func (shadowSocksProxy) isProxy() {}

type hysteria2Proxy struct {
	address  string
	port     int
	auth     string
	insecure bool
	sni      string
}

func (hysteria2Proxy) isProxy() {}

// flexInt unmarshals a JSON value that may be either a number or a quoted string
// (vmess subscriptions are inconsistent about port/aid types).
type flexInt int

func (f *flexInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("неверное числовое значение %q: %w", s, err)
	}
	*f = flexInt(n)
	return nil
}

func parseProxyURL(rawURL string) (proxy, error) {
	if strings.HasPrefix(rawURL, "vmess://") {
		return parseVmess(rawURL)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга URL: %w", err)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL должен содержать адрес сервера")
	}

	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("неверный порт: %w", err)
		}
	}

	query := u.Query()

	switch u.Scheme {
	case "vless":
		if u.User == nil || u.User.Username() == "" {
			return nil, fmt.Errorf("URL должен содержать идентификатор пользователя")
		}
		return vlessProxy{
			streamParams: streamParams{
				network:     query.Get("type"),
				security:    query.Get("security"),
				serverName:  query.Get("sni"),
				fingerprint: query.Get("fp"),
				publicKey:   query.Get("pbk"),
				shortID:     query.Get("sid"),
				spiderX:     query.Get("spx"),
				host:        query.Get("host"),
				path:        query.Get("path"),
				mode:        query.Get("mode"),
			},
			address:    u.Hostname(),
			port:       port,
			userID:     u.User.Username(),
			encryption: queryDefault(query, "encryption", "none"),
			flow:       query.Get("flow"),
		}, nil

	case "trojan":
		if u.User == nil || u.User.Username() == "" {
			return nil, fmt.Errorf("URL должен содержать пароль")
		}
		network := queryDefault(query, "type", "tcp")
		if err := validateStreamTransport("trojan", network); err != nil {
			return nil, err
		}
		return trojanProxy{
			streamParams: streamParams{
				network:       network,
				security:      queryDefault(query, "security", "tls"),
				serverName:    query.Get("sni"),
				fingerprint:   query.Get("fp"),
				alpn:          splitCSV(query.Get("alpn")),
				allowInsecure: query.Get("allowInsecure") == "1" || query.Get("insecure") == "1",
				host:          query.Get("host"),
				path:          query.Get("path"),
				mode:          query.Get("mode"),
				serviceName:   query.Get("serviceName"),
			},
			address:  u.Hostname(),
			port:     port,
			password: u.User.Username(),
			flow:     query.Get("flow"),
		}, nil

	case "ss":
		if u.User == nil || u.User.Username() == "" {
			return nil, fmt.Errorf("URL должен содержать имя пользователя")
		}
		decoded, err := base64.StdEncoding.DecodeString(u.User.Username())
		if err != nil {
			return nil, fmt.Errorf("ошибка декодирования SS credentials: %w", err)
		}
		method, password, found := strings.Cut(string(decoded), ":")
		if !found {
			return nil, fmt.Errorf("неверный формат SS credentials")
		}
		return shadowSocksProxy{
			address:  u.Hostname(),
			port:     port,
			method:   method,
			password: password,
		}, nil

	case "hysteria2":
		auth := ""
		if u.User != nil {
			auth = u.User.Username()
		}
		return hysteria2Proxy{
			address:  u.Hostname(),
			port:     port,
			auth:     auth,
			insecure: query.Get("insecure") == "1",
			sni:      query.Get("sni"),
		}, nil

	default:
		return nil, fmt.Errorf("неподдерживаемая схема: %s", u.Scheme)
	}
}

// vmessJSON mirrors the standard vmess share-link payload. Note: `net` is the
// transport (tcp/ws/grpc); `type` (omitted here) is the header-obfuscation type.
type vmessJSON struct {
	Add  string  `json:"add"`
	Port flexInt `json:"port"`
	ID   string  `json:"id"`
	Aid  flexInt `json:"aid"`
	Scy  string  `json:"scy"`
	Net  string  `json:"net"`
	TLS  string  `json:"tls"`
	SNI  string  `json:"sni"`
	Host string  `json:"host"`
	Path string  `json:"path"`
	Alpn string  `json:"alpn"`
	FP   string  `json:"fp"`
}

func parseVmess(rawURL string) (proxy, error) {
	decoded, err := decodeVmessPayload(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования vmess: %w", err)
	}

	var vj vmessJSON
	if err := json.Unmarshal(decoded, &vj); err != nil {
		return nil, fmt.Errorf("ошибка парсинга vmess JSON: %w", err)
	}

	if vj.Add == "" {
		return nil, fmt.Errorf("URL должен содержать адрес сервера")
	}
	if vj.ID == "" {
		return nil, fmt.Errorf("URL должен содержать идентификатор пользователя")
	}

	port := int(vj.Port)
	if port == 0 {
		port = 443
	}
	network := vj.Net
	if network == "" {
		network = "tcp"
	}
	if err := validateStreamTransport("vmess", network); err != nil {
		return nil, err
	}
	security := "none"
	if vj.TLS == "tls" {
		security = "tls"
	}
	scy := vj.Scy
	if scy == "" {
		scy = "auto"
	}

	return vmessProxy{
		streamParams: streamParams{
			network:     network,
			security:    security,
			serverName:  vj.SNI,
			fingerprint: vj.FP,
			alpn:        splitCSV(vj.Alpn),
			host:        vj.Host,
			path:        vj.Path,
			serviceName: vj.Path, // grpc serviceName lives in `path` for vmess
		},
		address:  vj.Add,
		port:     port,
		userID:   vj.ID,
		alterID:  int(vj.Aid),
		security: scy,
	}, nil
}

// decodeVmessPayload extracts and base64-decodes the JSON payload of a vmess:// URL,
// tolerating std/raw and url-safe alphabets with or without padding.
func decodeVmessPayload(rawURL string) ([]byte, error) {
	payload := strings.TrimPrefix(rawURL, "vmess://")
	if i := strings.IndexByte(payload, '#'); i >= 0 {
		payload = payload[:i]
	}
	payload = strings.TrimSpace(payload)

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(payload); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("не удалось декодировать base64")
}

// validateStreamTransport rejects transports that modern Xray (bundled by XKeen)
// cannot build for vmess/trojan, so the offending node is skipped instead of
// breaking the whole config.
func validateStreamTransport(protocol, network string) error {
	switch network {
	case "tcp", "raw", "ws", "grpc", "httpupgrade":
		return nil
	default:
		return fmt.Errorf("неподдерживаемый транспорт для %s: %q", protocol, network)
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func queryDefault(q url.Values, key, defaultValue string) string {
	if v := q.Get(key); v != "" {
		return v
	}
	return defaultValue
}
