import base64
import json
import sys
import threading
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from xkeen_subscription_watcher.main import main


@dataclass(frozen=True, slots=True)
class _ResponseSpec:
    body: str
    status: int = 200
    content_type: str = "text/plain; charset=utf-8"


class _SubscriptionRequestHandler(BaseHTTPRequestHandler):
    server: "_TestServer"

    def do_GET(self) -> None:  # noqa: N802
        response = self.server.responses.get(self.path)
        if response is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"not found")
            return

        payload = response.body.encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class _TestServer(ThreadingHTTPServer):
    def __init__(self, responses: dict[str, _ResponseSpec]):
        super().__init__(("127.0.0.1", 0), _SubscriptionRequestHandler)
        self.responses = responses


@contextmanager
def _http_server(responses: dict[str, _ResponseSpec]):
    server = _TestServer(responses)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@contextmanager
def _patched_argv(*args: str):
    old_argv = sys.argv[:]
    sys.argv = ["xkeen-subscription-watcher", *args]
    try:
        yield
    finally:
        sys.argv = old_argv


def _run_main(*args: str) -> None:
    with _patched_argv(*args):
        main()


def _load_config(output_dir: Path, tag: str) -> dict:
    return json.loads((output_dir / f"04_outbounds.{tag}.json").read_text(encoding="utf-8"))


def _encode_subscription(*lines: str) -> str:
    payload = "\n".join(lines).encode("utf-8")
    return base64.b64encode(payload).decode("utf-8")


def _make_vless_url(
    *,
    user_id: str = "user",
    host: str = "example.com",
    port: int | None = 443,
    fragment: str | None = None,
    **params: str,
) -> str:
    netloc = f"{user_id}@{host}"
    if port is not None:
        netloc += f":{port}"
    return urllib.parse.urlunparse(("vless", netloc, "", "", urllib.parse.urlencode(params), fragment or ""))


def _make_ss_url(
    *,
    method: str = "chacha20-ietf-poly1305",
    password: str = "secret",
    host: str = "ss.example.com",
    port: int | None = 8388,
    fragment: str | None = None,
) -> str:
    auth = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8")
    netloc = f"{auth}@{host}"
    if port is not None:
        netloc += f":{port}"
    return urllib.parse.urlunparse(("ss", netloc, "", "", "", fragment or ""))


def test_main_generates_config_from_plaintext_subscription(tmp_path: Path) -> None:
    with _http_server(
        {
            "/sub": _ResponseSpec(
                body=(
                    "vless://user@example.com:443"
                    "?type=tcp&security=reality&sni=edge.example.com&pbk=pubkey&flow=xtls-rprx-vision"
                    "# First Node\n"
                )
            )
        }
    ) as base_url:
        _run_main(f"demo={base_url}/sub", "--output-dir", str(tmp_path), "--no-restart")

    assert _load_config(tmp_path, "demo") == {
        "outbounds": [
            {
                "tag": "demo--First Node",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "example.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "user",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "edge.example.com",
                        "fingerprint": "chrome",
                        "publicKey": "pubkey",
                    },
                },
            }
        ]
    }


def test_main_generates_sorted_config_from_base64_subscription(tmp_path: Path) -> None:
    with _http_server(
        {
            "/sub": _ResponseSpec(
                body=_encode_subscription(
                    "unknown://ignored",
                    _make_vless_url(
                        user_id="uuid-1",
                        host="alpha.example.com",
                        port=None,
                        type="grpc",
                        security="reality",
                        sni="alpha.example.com",
                        pbk="pub-alpha",
                        flow="xtls-rprx-vision",
                        sid="short-id",
                        spx="/grpc",
                        fragment="Fancy/Node!",
                    ),
                    _make_ss_url(method="aes-256-gcm", password="passw0rd", host="beta.example.com", port=None),
                    "",
                )
            )
        }
    ) as base_url:
        _run_main(f"mix={base_url}/sub", "--output-dir", str(tmp_path), "--no-restart")

    assert _load_config(tmp_path, "mix") == {
        "outbounds": [
            {
                "tag": "mix",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": "beta.example.com",
                            "port": 443,
                            "method": "aes-256-gcm",
                            "password": "passw0rd",
                        }
                    ]
                },
            },
            {
                "tag": "mix--FancyNode",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "alpha.example.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "uuid-1",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "alpha.example.com",
                        "fingerprint": "chrome",
                        "publicKey": "pub-alpha",
                        "spiderX": "/grpc",
                        "shortId": "short-id",
                    },
                },
            },
        ]
    }


def test_main_adds_dialer_proxy_variants_without_losing_vless_stream_settings(tmp_path: Path) -> None:
    with _http_server(
        {
            "/sub": _ResponseSpec(
                body=_make_vless_url(
                    user_id="uuid-2",
                    host="dial.example.com",
                    type="ws",
                    security="reality",
                    sni="dial.example.com",
                    pbk="pub-dial",
                    flow="xtls-rprx-vision",
                    fragment="Dial Node",
                )
            )
        }
    ) as base_url:
        _run_main(
            f"dial={base_url}/sub",
            "--output-dir",
            str(tmp_path),
            "--no-restart",
            "--dialer-proxies",
            "warp",
            "tor",
        )

    assert _load_config(tmp_path, "dial") == {
        "outbounds": [
            {
                "tag": "dial--Dial Node",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "dial.example.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "uuid-2",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "dial.example.com",
                        "fingerprint": "chrome",
                        "publicKey": "pub-dial",
                    },
                },
            },
            {
                "tag": "dial--Dial Node--warp",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "dial.example.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "uuid-2",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "dial.example.com",
                        "fingerprint": "chrome",
                        "publicKey": "pub-dial",
                    },
                    "sockopt": {"dialerProxy": "warp"},
                },
            },
            {
                "tag": "dial--Dial Node--tor",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "dial.example.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "uuid-2",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "dial.example.com",
                        "fingerprint": "chrome",
                        "publicKey": "pub-dial",
                    },
                    "sockopt": {"dialerProxy": "tor"},
                },
            },
        ]
    }


def test_main_does_not_rewrite_unchanged_config(tmp_path: Path) -> None:
    with _http_server(
        {"/sub": _ResponseSpec(body=_make_ss_url(method="aes-128-gcm", password="same", host="stable.example.com"))}
    ) as base_url:
        args = (f"stable={base_url}/sub", "--output-dir", str(tmp_path), "--no-restart")
        _run_main(*args)
        output_path = tmp_path / "04_outbounds.stable.json"
        first_mtime = output_path.stat().st_mtime_ns
        first_contents = output_path.read_text(encoding="utf-8")

        time.sleep(0.02)

        _run_main(*args)

    assert output_path.read_text(encoding="utf-8") == first_contents
    assert output_path.stat().st_mtime_ns == first_mtime


def test_main_continues_when_one_subscription_returns_http_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with _http_server(
        {
            "/ok": _ResponseSpec(body=_make_ss_url(host="ok.example.com", fragment="ok")),
            "/bad": _ResponseSpec(body="server error", status=500),
        }
    ) as base_url:
        _run_main(
            f"good={base_url}/ok",
            f"bad={base_url}/bad",
            "--output-dir",
            str(tmp_path),
            "--no-restart",
        )

    assert (tmp_path / "04_outbounds.good.json").is_file()
    assert not (tmp_path / "04_outbounds.bad.json").exists()
    assert "bad" in caplog.text


def test_main_raises_for_subscription_without_separator(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Неверный формат подписки"):
        _run_main("broken", "--output-dir", str(tmp_path), "--no-restart")


def test_main_raises_for_duplicate_tags(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="указан несколько раз"):
        _run_main(
            "dup=http://example.com/one",
            "dup=http://example.com/two",
            "--output-dir",
            str(tmp_path),
            "--no-restart",
        )


def test_main_raises_for_invalid_url_scheme(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="URL должен начинаться"):
        _run_main("demo=ftp://example.com/sub", "--output-dir", str(tmp_path), "--no-restart")


def test_main_raises_when_output_dir_is_not_directory(tmp_path: Path) -> None:
    output_path = tmp_path / "not-a-dir"
    output_path.write_text("content", encoding="utf-8")

    with pytest.raises(ValueError, match="не является директорией"):
        _run_main("demo=http://example.com/sub", "--output-dir", str(output_path), "--no-restart")
