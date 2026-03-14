import base64

from xkeen_subscription_watcher.main import _parse_subscription_response_text


def test_parse_subscription_response_text__several_urls__return_all():
    response_text = "ss://1 \n  unknown://something \n vless://2 \nvless://3\n"

    assert _parse_subscription_response_text(response_text) == ["ss://1", "vless://2", "vless://3"]


def test_parse_subscription_response_text__base64__ok():
    response_text = "ss://1 \n  unknown://something \n vless://2 \nvless://3\n"
    response_text = base64.b64encode(response_text.encode("utf-8")).decode("utf-8") + "\n"

    assert _parse_subscription_response_text(response_text) == ["ss://1", "vless://2", "vless://3"]
