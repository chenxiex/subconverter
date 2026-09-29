from __future__ import annotations

import base64
import json
from urllib.parse import quote

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


def test_explicit_tls_ignores_stray_reality_key() -> None:
    proxy = parse_vless_link(
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        "?encryption=none&security=tls&sni=www.example.com&pbk=stale_key&type=xhttp#TLS"
    )
    assert "reality-opts" not in proxy


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


def test_parse_xhttp_download_settings() -> None:
    extra = json.dumps(
        {
            "downloadSettings": {
                "address": "203.0.113.10",
                "port": 443,
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": False,
                    "serverName": "download.example.com",
                    "fingerprint": "chrome",
                    "alpn": ["h2"],
                    "echConfigList": "gitlab.io+https://dns.example/dns-query",
                    "echForceQuery": "full",
                },
                "xhttpSettings": {"path": "/download", "mode": "auto"},
            }
        }
    )
    link = (
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        "?encryption=none&security=tls&type=xhttp&path=%2Fupload"
        f"&extra={quote(extra, safe='')}#XHTTP"
    )
    download = parse_vless_link(link)["xhttp-opts"]["download-settings"]
    assert download == {
        "server": "203.0.113.10",
        "port": 443,
        "tls": True,
        "path": "/download",
        "skip-cert-verify": False,
        "servername": "download.example.com",
        "client-fingerprint": "chrome",
        "alpn": ["h2"],
        "ech-opts": {"enable": True, "query-server-name": "gitlab.io"},
    }


def test_base64_xhttp_extra_preserves_sibling_settings() -> None:
    extra = {
        "xhttpSettings": {"xPaddingBytes": "100-1000"},
        "downloadSettings": {
            "address": "download.example.com",
            "xhttpSettings": {"path": "/download"},
        },
    }
    encoded = base64.urlsafe_b64encode(json.dumps(extra).encode()).decode().rstrip("=")
    proxy = parse_vless_link(
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        f"?encryption=none&security=tls&type=xhttp&extra={encoded}#XHTTP"
    )
    opts = proxy["xhttp-opts"]
    assert opts["x-padding-bytes"] == "100-1000"
    assert opts["download-settings"] == {
        "server": "download.example.com",
        "path": "/download",
    }


def test_plain_and_base64_subscription() -> None:
    link = "vless://id@example.com:443?encryption=none&type=xhttp#node"
    assert len(parse_subscription(link)) == 1
    encoded = base64.urlsafe_b64encode(link.encode()).decode().rstrip("=")
    assert len(parse_subscription(encoded)) == 1
