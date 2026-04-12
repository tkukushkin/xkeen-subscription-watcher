package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type proxy interface {
	isProxy()
}

type vlessProxy struct {
	address     string
	port        int
	userID      string
	encryption  string
	flow        string
	network     string
	security    string
	serverName  string
	publicKey   string
	shortID     string
	spiderX     string
	fingerprint string
	host        string
	path        string
	mode        string
}

func (vlessProxy) isProxy() {}

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

func parseProxyURL(rawURL string) (proxy, error) {
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
			address:     u.Hostname(),
			port:        port,
			userID:      u.User.Username(),
			encryption:  queryDefault(query, "encryption", "none"),
			flow:        query.Get("flow"),
			network:     query.Get("type"),
			security:    query.Get("security"),
			serverName:  query.Get("sni"),
			publicKey:   query.Get("pbk"),
			shortID:     query.Get("sid"),
			spiderX:     query.Get("spx"),
			fingerprint: query.Get("fp"),
			host:        query.Get("host"),
			path:        query.Get("path"),
			mode:        query.Get("mode"),
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

func queryDefault(q url.Values, key, defaultValue string) string {
	if v := q.Get(key); v != "" {
		return v
	}
	return defaultValue
}
