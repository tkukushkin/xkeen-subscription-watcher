#!/opt/bin/python
import base64
import json
import logging
import subprocess
import sys
import urllib.parse
import urllib.request
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    subscriptions = _parse_args()

    xray_config = _get_xray_config(subscriptions)

    output_path = Path("/opt/etc/xray/configs/04_outbounds.generated.json")

    if output_path.exists() and json.loads(output_path.read_bytes()) == xray_config:
        logging.info("Изменения подписок не найдены, завершаем работу.")
        return

    logging.info("Записываем новую конфигурацию в %s.", output_path)
    output_path.write_text(json.dumps(xray_config, indent=2) + "\n", encoding="utf-8")

    logging.info("Перезапускаем XKeen.")
    subprocess.run(["xkeen", "-restart"], check=True)


def _parse_args() -> list["_Subscription"]:
    result = []
    tags = set[str]()
    for arg in sys.argv[1:]:
        tag, url = arg.split("=", 1)
        if tag in tags:
            raise ValueError(f"Тег {tag!r} указан несколько раз, используйте уникальные имена.")
        tags.add(tag)

        if not url.startswith("http"):
            raise ValueError(f"Неизвестный формат URL: {url}. URL должен начинаться на http:// или https://.")

        result.append(_Subscription(tag=tag, url=url))

    return result


@dataclass(frozen=True, slots=True)
class _Subscription:
    tag: str
    url: str


def _get_xray_config(subscriptions: Sequence[_Subscription]) -> dict[str, Any]:
    return {"outbounds": [_get_outbound(subscription) for subscription in subscriptions]}


def _get_outbound(subscription: _Subscription) -> dict[str, Any]:
    logging.info("Запрашиваем URL подписки: %s.", subscription.url)
    proxy_url = _get_proxy_url(subscription.url)
    credentials = _parse_proxy_url(proxy_url)
    logging.info("Используем прокси: %s.", proxy_url)
    reality_settings = {
        "serverName": credentials.server_name,
        "fingerprint": "firefox",
        "publicKey": credentials.public_key,
    }
    if credentials.spider_x:
        reality_settings["spiderX"] = credentials.spider_x
    if credentials.short_id:
        reality_settings["shortId"] = credentials.short_id
    return {
        "tag": subscription.tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": credentials.address,
                    "port": credentials.port,
                    "users": [
                        {
                            "id": credentials.user_id,
                            "encryption": credentials.encryption,
                            "flow": credentials.flow,
                        }
                    ],
                }
            ],
        },
        "streamSettings": {
            "network": credentials.network,
            "security": credentials.security,
            "realitySettings": reality_settings,
        },
    }


def _get_proxy_url(subscription_url: str) -> str:
    with urllib.request.urlopen(subscription_url, timeout=20) as response:
        response_text = response.read().decode("utf-8")
    if response.status != 200:
        raise RuntimeError(
            f"Не удалось получить подписку по URL: {subscription_url}, "
            f"код ответа: {response.status}, текст: {response_text}"
        )
    return _parse_subscription_response_text(response_text)


def _parse_subscription_response_text(response_text: str) -> str:
    response_text = response_text.strip()

    with suppress(ValueError):
        response_text = base64.b64decode(response_text.encode("utf-8"), validate=True).decode("utf-8").strip()

    for line in response_text.splitlines(keepends=False):
        line = line.strip()
        if line and line.startswith("vless://"):
            return line

    raise RuntimeError("Не удалось найти ни одного URL прокси в ответе подписки в формате vless.")


def _parse_proxy_url(proxy_url: str) -> "_ProxyCredentials":
    parse_result = urllib.parse.urlparse(proxy_url)
    query_params = dict(urllib.parse.parse_qsl(parse_result.query, keep_blank_values=True))
    assert parse_result.hostname, "URL должен содержать адрес сервера."
    assert parse_result.username, "URL должен содержать идентификатор пользователя."
    return _ProxyCredentials(
        address=parse_result.hostname,
        port=parse_result.port or 443,
        user_id=parse_result.username,
        encryption=query_params.get("encryption", "none"),
        flow=query_params["flow"],
        network=query_params["type"],
        security=query_params["security"],
        server_name=query_params["sni"],
        public_key=query_params["pbk"],
        short_id=query_params.get("sid"),
        spider_x=query_params.get("spx"),
    )


@dataclass(frozen=True, slots=True)
class _ProxyCredentials:
    address: str
    port: int
    user_id: str
    encryption: str
    flow: str
    network: str
    security: str
    server_name: str
    public_key: str
    short_id: str | None
    spider_x: str | None


if __name__ == "__main__":
    main()
