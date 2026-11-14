package main

import "net/url"

// buildStreamSettings builds the streamSettings block shared by the TLS/transport
// family (vless, vmess, trojan). fingerprintOverride applies to the reality branch
// only (it is sourced from --reality-fingerprint).
func buildStreamSettings(sp streamParams, address, fingerprintOverride string) map[string]any {
	ss := map[string]any{
		"network":  sp.network,
		"security": sp.security,
	}

	switch sp.security {
	case "reality":
		fingerprint := fingerprintOverride
		if fingerprint == "" {
			fingerprint = sp.fingerprint
		}
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		realitySettings := map[string]any{
			"serverName":  sp.serverName,
			"fingerprint": fingerprint,
			"publicKey":   sp.publicKey,
		}
		if sp.spiderX != "" {
			realitySettings["spiderX"] = sp.spiderX
		}
		if sp.shortID != "" {
			realitySettings["shortId"] = sp.shortID
		}
		ss["realitySettings"] = realitySettings

	case "tls":
		serverName := sp.serverName
		if serverName == "" {
			serverName = address
		}
		fingerprint := sp.fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		tlsSettings := map[string]any{
			"serverName":    serverName,
			"allowInsecure": sp.allowInsecure,
			"fingerprint":   fingerprint,
		}
		if len(sp.alpn) > 0 {
			tlsSettings["alpn"] = sp.alpn
		}
		ss["tlsSettings"] = tlsSettings
	}

	switch sp.network {
	case "ws", "httpupgrade":
		settings := map[string]any{}
		if sp.path != "" {
			settings["path"] = sp.path
		}
		if sp.host != "" {
			settings["host"] = sp.host
		}
		if len(settings) > 0 {
			ss[sp.network+"Settings"] = settings
		}

	case "grpc":
		grpcSettings := map[string]any{}
		if sp.serviceName != "" {
			grpcSettings["serviceName"] = sp.serviceName
		}
		if sp.host != "" {
			grpcSettings["authority"] = sp.host
		}
		if sp.mode == "multi" {
			grpcSettings["multiMode"] = true
		}
		if len(grpcSettings) > 0 {
			ss["grpcSettings"] = grpcSettings
		}

	case "xhttp":
		xhttpSettings := map[string]any{}
		if sp.host != "" {
			xhttpSettings["host"] = sp.host
		}
		if sp.path != "" {
			if decoded, err := url.PathUnescape(sp.path); err == nil {
				xhttpSettings["path"] = decoded
			} else {
				xhttpSettings["path"] = sp.path
			}
		}
		if sp.mode != "" {
			xhttpSettings["mode"] = sp.mode
		}
		if len(xhttpSettings) > 0 {
			ss["xhttpSettings"] = xhttpSettings
		}
	}

	return ss
}

func generateOutbound(p proxy, tag string, realityFingerprint string, dialerProxy string) map[string]any {
	var proxyConfig map[string]any

	switch p := p.(type) {
	case vlessProxy:
		proxyConfig = map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": p.address,
						"port":    p.port,
						"users": []any{
							map[string]any{
								"id":         p.userID,
								"encryption": p.encryption,
								"flow":       p.flow,
							},
						},
					},
				},
			},
			"streamSettings": buildStreamSettings(p.streamParams, p.address, realityFingerprint),
		}

	case vmessProxy:
		proxyConfig = map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": p.address,
						"port":    p.port,
						"users": []any{
							map[string]any{
								"id":       p.userID,
								"alterId":  p.alterID,
								"security": p.security,
							},
						},
					},
				},
			},
			"streamSettings": buildStreamSettings(p.streamParams, p.address, realityFingerprint),
		}

	case trojanProxy:
		server := map[string]any{
			"address":  p.address,
			"port":     p.port,
			"password": p.password,
		}
		if p.flow != "" {
			server["flow"] = p.flow
		}
		proxyConfig = map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{
				"servers": []any{server},
			},
			"streamSettings": buildStreamSettings(p.streamParams, p.address, realityFingerprint),
		}

	case shadowSocksProxy:
		proxyConfig = map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"servers": []any{
					map[string]any{
						"address":  p.address,
						"port":     p.port,
						"method":   p.method,
						"password": p.password,
					},
				},
			},
		}

	case hysteria2Proxy:
		sni := p.sni
		if sni == "" {
			sni = p.address
		}
		proxyConfig = map[string]any{
			"protocol": "hysteria",
			"settings": map[string]any{
				"version": 2,
				"address": p.address,
				"port":    p.port,
			},
			"streamSettings": map[string]any{
				"network":  "hysteria",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    sni,
					"allowInsecure": p.insecure,
				},
				"hysteriaSettings": map[string]any{
					"version":         2,
					"auth":            p.auth,
					"keepAlivePeriod": 5,
				},
			},
		}

	default:
		panic("unreachable")
	}

	result := map[string]any{"tag": tag}
	for k, v := range proxyConfig {
		result[k] = v
	}

	if dialerProxy != "" {
		ss, ok := result["streamSettings"].(map[string]any)
		if !ok {
			ss = map[string]any{}
			result["streamSettings"] = ss
		}
		ss["sockopt"] = map[string]any{"dialerProxy": dialerProxy}
	}

	return result
}
