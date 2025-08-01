import base64

import pytest

from xkeen_subscription_watcher.main import _parse_subscription_response_text


def test_parse_subscription_response_text__several_urls__get_first():
    response_text = "ss://... \n   vless://1 \nvless://2\n"

    assert _parse_subscription_response_text(response_text) == "vless://1"


def test_parse_subscription_response_text__base64__ok():
    response_text = "ss://... \n   vless://1 \nvless://2\n"
    response_text = base64.b64encode(response_text.encode("utf-8")).decode("utf-8") + "\n"

    assert _parse_subscription_response_text(response_text) == "vless://1"


def test_parse_subscription_response_text__no_supported_urls__error():
    with pytest.raises(RuntimeError, match="Не удалось найти ни одного URL прокси в ответе подписки в формате vless."):
        _parse_subscription_response_text("ss://...\n")
