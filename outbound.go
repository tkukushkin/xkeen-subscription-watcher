package main

import "net/url"

func generateOutbound(p proxy, tag string, realityFingerprint string, dialerProxy string) map[string]any {
	var proxyConfig map[string]any

	switch p := p.(type) {
	case vlessProxy:
		fingerprint := realityFingerprint
		if fingerprint == "" {
			fingerprint = p.fingerprint
		}
		if fingerprint == "" {
			fingerprint = "chrome"
		}

		realitySettings := map[string]any{
			"serverName":  p.serverName,
			"fingerprint": fingerprint,
			"publicKey":   p.publicKey,
		}
		if p.spiderX != "" {
			realitySettings["spiderX"] = p.spiderX
		}
		if p.shortID != "" {
			realitySettings["shortId"] = p.shortID
		}

		streamSettings := map[string]any{
			"network":         p.network,
			"security":        p.security,
			"realitySettings": realitySettings,
		}

		if p.network == "xhttp" && (p.host != "" || p.path != "") {
			xhttpSettings := map[string]any{}
			if p.host != "" {
				xhttpSettings["host"] = p.host
			}
			if p.path != "" {
				decoded, err := url.PathUnescape(p.path)
				if err == nil {
					xhttpSettings["path"] = decoded
				} else {
					xhttpSettings["path"] = p.path
				}
			}
			if p.mode != "" {
				xhttpSettings["mode"] = p.mode
			}
			streamSettings["xhttpSettings"] = xhttpSettings
		}

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
			"streamSettings": streamSettings,
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
