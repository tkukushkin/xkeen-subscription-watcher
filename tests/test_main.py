import base64


from xkeen_subscription_watcher.main import _parse_subscription_response_text


def test_parse_subscription_response_text__several_urls__return_all():
    response_text = "ss://... \n   vless://1 \nvless://2\n"

    assert _parse_subscription_response_text(response_text) == ["vless://1", "vless://2"]


def test_parse_subscription_response_text__base64__ok():
    response_text = "ss://... \n   vless://1 \nvless://2\n"
    response_text = base64.b64encode(response_text.encode("utf-8")).decode("utf-8") + "\n"

    assert _parse_subscription_response_text(response_text) == ["vless://1", "vless://2"]
