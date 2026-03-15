#!/opt/bin/python
import argparse
import base64
import json
import logging
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from collections import defaultdict
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias, assert_never


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    args = _parse_args()

    updated = False

    for subscription in args.subscriptions:
        try:
            updated |= _process_subscription(
                subscription=subscription, output_dir=args.output_dir, dialer_proxies=args.dialer_proxies
            )
        except Exception:
            logging.warning("Ошибка при обработке подписки %r, пропускаем.", subscription.tag, exc_info=True)

    if not updated:
        logging.info("Изменений в подписках не найдено, завершаем работу.")
        return

    if args.restart_xkeen:
        logging.info("Перезапускаем XKeen.")
        subprocess.run(["xkeen", "-restart"], check=True)


def _parse_args() -> "_Args":
    parser = argparse.ArgumentParser(description="Скрипт для обработки подписок и генерации конфигураций для Xray.")
    parser.add_argument(
        "subscriptions",
        nargs="+",
        help="Подписки. Пример: mytag=http://example.com/subscription",
        metavar="<tag>=<url>",
    )
    parser.add_argument(
        "--output-dir",
        default="/opt/etc/xray/configs",
        help="Каталог для сохранения сгенерированных конфигураций. По-умолчанию /opt/etc/xray/configs.",
    )
    parser.add_argument(
        "--no-restart",
        action="store_false",
        dest="restart_xkeen",
        help="Не перезапускать XKeen после обновления конфигураций.",
    )
    parser.add_argument("--dialer-proxies", nargs="*", default=())
    args = parser.parse_args()

    subscriptions = []
    tags = set[str]()
    for arg in args.subscriptions:
        tag, sep, url = arg.partition("=")
        if not sep:
            raise ValueError(f"Неверный формат подписки: {arg!r}. Ожидается <tag>=<url>.")

        if tag in tags:
            raise ValueError(f"Тег {tag!r} указан несколько раз, используйте уникальные имена.")
        tags.add(tag)

        if not url.startswith(("http://", "https://")):
            raise ValueError(f"Неизвестный формат URL: {url}. URL должен начинаться на http:// или https://.")

        subscriptions.append(_Subscription(tag=tag, url=url))

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        raise ValueError(f"Указанный путь для --output-dir {output_dir} не является директорией.")

    return _Args(
        subscriptions=subscriptions,
        output_dir=output_dir,
        restart_xkeen=args.restart_xkeen,
        dialer_proxies=args.dialer_proxies,
    )


@dataclass(frozen=True, slots=True)
class _Args:
    subscriptions: Sequence["_Subscription"]
    output_dir: Path
    restart_xkeen: bool
    dialer_proxies: Sequence[str]


@dataclass(frozen=True, slots=True)
class _Subscription:
    tag: str
    url: str


def _process_subscription(subscription: _Subscription, output_dir: Path, dialer_proxies: Sequence[str]) -> bool:
    output_path = output_dir / f"04_outbounds.{subscription.tag}.json"

    xray_config = {"outbounds": _get_outbounds(subscription=subscription, dialer_proxies=dialer_proxies)}

    if output_path.exists() and json.loads(output_path.read_bytes()) == xray_config:
        logging.info("Изменения в подписке %r не найдены, пропускаем.", subscription.tag)
        return False

    logging.info("Записываем новую конфигурацию для подписки %r в %s.", subscription.tag, output_path)
    output_path.write_text(json.dumps(xray_config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def _get_outbounds(subscription: _Subscription, dialer_proxies: Sequence[str]) -> list[dict[str, Any]]:
    logging.info("Запрашиваем URL подписки: %s.", subscription.url)
    proxy_urls = _get_proxy_urls(subscription)
    proxy_urls.sort()

    tag_counters = defaultdict[str, int](int)

    result = []
    for i, proxy_url in enumerate(proxy_urls, 1):
        try:
            proxy = _parse_proxy_url(proxy_url)
        except Exception:
            logging.warning(
                "Не удалось распарсить URL прокси %r из подписки %r, пропускаем.",
                proxy_url,
                subscription.tag,
                exc_info=True,
            )
            continue

        tag = f"{subscription.tag}--{_get_proxy_name(proxy_url) or i}"

        tag_counters[tag] += 1

        if tag_counters[tag] > 1:
            tag = f"{tag}--{tag_counters[tag]}"

        result.append(_generate_outbound(proxy=proxy, tag=tag))
        for dialer_proxy in dialer_proxies:
            result.append(_generate_outbound(proxy=proxy, tag=f"{tag}--{dialer_proxy}", dialer_proxy=dialer_proxy))

    return result


def _get_proxy_urls(subscription: _Subscription) -> list[str]:
    try:
        with _request(subscription.url, with_proxy=False) as response:
            response_text = response.read().decode("utf-8")
    except urllib.error.HTTPError:
        raise
    except Exception:
        logging.warning(
            "Не удалось получить подписку %s без прокси, пробуем с прокси.", subscription.tag, exc_info=True
        )
        with _request(subscription.url, with_proxy=True) as response:
            response_text = response.read().decode("utf-8")

    if response.status != 200:
        raise RuntimeError(
            f"Ошибка при получении подписки {subscription.tag}: код {response.status}, текст ответа: {response_text}"
        )

    return _parse_subscription_response_text(response_text)


def _request(subscription_url: str, *, with_proxy: bool) -> urllib.response.addinfourl:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(
            {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"} if with_proxy else {}
        )
    )
    request = urllib.request.Request(subscription_url)
    request.headers["User-Agent"] = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    )
    return opener.open(request, timeout=20)


def _parse_subscription_response_text(response_text: str) -> list[str]:
    response_text = response_text.strip()

    with suppress(ValueError):
        response_text = base64.b64decode(response_text.encode("utf-8"), validate=True).decode("utf-8").strip()

    result = []

    for line in response_text.splitlines(keepends=False):
        line = line.strip()
        if line and line.startswith(("vless://", "ss://", "hysteria2://")):
            result.append(line)

    return result


def _get_proxy_name(url: str) -> str | None:
    if "#" not in url:
        return None
    name = url.rsplit("#", 1)[-1].strip()
    return "".join(c for c in name if c.isalnum() or c in (" -_")).strip()


def _parse_proxy_url(proxy_url: str) -> "_Proxy":
    parse_result = urllib.parse.urlparse(proxy_url)
    query_params = dict(urllib.parse.parse_qsl(parse_result.query, keep_blank_values=True))
    assert parse_result.hostname, "URL должен содержать адрес сервера."
    assert parse_result.username, "URL должен содержать идентификатор пользователя."
    if parse_result.scheme == "vless":
        return _VlessProxy(
            address=parse_result.hostname,
            port=parse_result.port or 443,
            user_id=parse_result.username,
            encryption=query_params.get("encryption", "none"),
            flow=query_params.get("flow"),
            network=query_params["type"],
            security=query_params["security"],
            server_name=query_params["sni"],
            public_key=query_params["pbk"],
            short_id=query_params.get("sid"),
            spider_x=query_params.get("spx"),
        )
    if parse_result.scheme == "ss":
        assert parse_result.username, "URL должен содержать имя пользователя."
        method, password = base64.b64decode(parse_result.username.encode("utf-8")).decode("utf-8").split(":", 1)
        return _ShadowSocksProxy(
            address=parse_result.hostname,
            port=parse_result.port or 443,
            method=method,
            password=password,
        )
    if parse_result.scheme == "hysteria2":
        return _Hysteria2Proxy(
            address=parse_result.hostname,
            port=parse_result.port or 443,
            auth=parse_result.username,
            insecure=query_params.get("insecure") == "1",
            sni=query_params.get("sni"),
        )

    raise AssertionError("unreachable")


@dataclass(frozen=True, slots=True)
class _VlessProxy:
    address: str
    port: int
    user_id: str
    encryption: str
    flow: str | None
    network: str
    security: str
    server_name: str
    public_key: str
    short_id: str | None
    spider_x: str | None


@dataclass(frozen=True, slots=True)
class _ShadowSocksProxy:
    address: str
    port: int
    method: str
    password: str


@dataclass(frozen=True, slots=True)
class _Hysteria2Proxy:
    address: str
    port: int
    auth: str | None
    insecure: bool
    sni: str | None


_Proxy: TypeAlias = _VlessProxy | _ShadowSocksProxy | _Hysteria2Proxy


def _generate_outbound(proxy: _Proxy, tag: str, dialer_proxy: str | None = None) -> dict[str, Any]:
    proxy_config: dict[str, Any]

    if isinstance(proxy, _VlessProxy):
        reality_settings = {
            "serverName": proxy.server_name,
            "fingerprint": "firefox",
            "publicKey": proxy.public_key,
        }
        if proxy.spider_x:
            reality_settings["spiderX"] = proxy.spider_x
        if proxy.short_id:
            reality_settings["shortId"] = proxy.short_id

        proxy_config = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": proxy.address,
                        "port": proxy.port,
                        "users": [
                            {
                                "id": proxy.user_id,
                                "encryption": proxy.encryption,
                                "flow": proxy.flow or "",
                            }
                        ],
                    }
                ],
            },
            "streamSettings": {
                "network": proxy.network,
                "security": proxy.security,
                "realitySettings": reality_settings,
            },
        }
    elif isinstance(proxy, _ShadowSocksProxy):
        proxy_config = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": proxy.address,
                        "port": proxy.port,
                        "method": proxy.method,
                        "password": proxy.password,
                    }
                ],
            },
        }
    elif isinstance(proxy, _Hysteria2Proxy):
        proxy_config = {
            "protocol": "hysteria",
            "settings": {"version": 2, "address": proxy.address, "port": proxy.port},
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": {"serverName": proxy.sni or proxy.address, "allowInsecure": proxy.insecure},
                "hysteriaSettings": {
                    "version": 2,
                    "auth": proxy.auth,
                    "keepAlivePeriod": 5,
                },
            },
        }
    else:
        assert_never(proxy)

    result: dict[str, Any] = {"tag": tag, **proxy_config}

    if dialer_proxy:
        stream_settings = result.setdefault("streamSettings", {})
        stream_settings["sockopt"] = {"dialerProxy": dialer_proxy}

    return result


if __name__ == "__main__":
    main()
