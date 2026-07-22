from __future__ import annotations

import base64
import json

from vless2clash.source import parse_subscription
from vless2clash.vless import parse_vless_link


def test_parse_tcp_reality() -> None:
    proxy = parse_vless_link(
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com"
        "&fp=chrome&pbk=public_key&sid=abcd&type=tcp#JP"
    )
    assert proxy["name"] == "JP"
    assert proxy["network"] == "tcp"
    assert proxy["encryption"] == "none"
    assert proxy["reality-opts"] == {"public-key": "public_key", "short-id": "abcd"}


def test_parse_xhttp_and_encryption() -> None:
    encryption = "mlkem768x25519plus.native.0rtt.long_value"
    proxy = parse_vless_link(
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        f"?encryption={encryption}&security=tls&sni=edge.example.com&fp=chrome"
        "&type=xhttp&path=%2Fapi&mode=auto#HK"
    )
    assert proxy["network"] == "xhttp"
    assert proxy["encryption"] == encryption
    assert proxy["xhttp-opts"] == {"path": "/api", "mode": "auto"}


def test_parse_xhttp_extra_json() -> None:
    extra = json.dumps(
        {
            "xhttpSettings": {
                "xPaddingBytes": "100-1000",
                "xPaddingObfsMode": True,
                "xmux": {"maxConnections": "2", "hMaxReusableSecs": "600-900"},
            }
        }
    )
    link = (
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        f"?encryption=none&type=splithttp&extra={extra}#XHTTP"
    )
    opts = parse_vless_link(link)["xhttp-opts"]
    assert opts["x-padding-bytes"] == "100-1000"
    assert opts["x-padding-obfs-mode"] is True
    assert opts["reuse-settings"]["max-connections"] == 2


def test_plain_and_base64_subscription() -> None:
    link = "vless://id@example.com:443?encryption=none&type=xhttp#node"
    assert len(parse_subscription(link)) == 1
    encoded = base64.urlsafe_b64encode(link.encode()).decode().rstrip("=")
    assert len(parse_subscription(encoded)) == 1
