from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx
import yaml

from .vless import VlessParseError, make_names_unique, parse_vless_link

USER_AGENT = "vless2clash/0.1"


def read_source(source: str, *, timeout: float = 20.0) -> str:
    source = unquote(source.strip())
    if source.startswith(("http://", "https://")):
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            response = client.get(source, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            return response.text.lstrip("\ufeff")
    path = Path(source).expanduser()
    if path.is_file():
        return path.read_text(encoding="utf-8-sig")
    if source.startswith("vless://"):
        return source
    raise FileNotFoundError(f"找不到输入源: {source}")


def _maybe_base64(content: str) -> str:
    compact = re.sub(r"\s+", "", content)
    if not compact or "vless://" in content.lower():
        return content
    try:
        decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return content
    return decoded if "vless://" in decoded.lower() else content


def parse_subscription(content: str) -> list[dict[str, object]]:
    content = _maybe_base64(content)
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        document = None
    if isinstance(document, dict) and isinstance(document.get("proxies"), list):
        proxies = [item for item in document["proxies"] if isinstance(item, dict)]
        if proxies:
            return make_names_unique(proxies)

    links = re.findall(r"(?im)^\s*(vless://\S+)\s*$", content)
    if not links and content.strip().lower().startswith("vless://"):
        links = [content.strip()]
    if not links:
        raise VlessParseError("订阅中没有找到 VLESS 节点")
    return make_names_unique(parse_vless_link(link) for link in links)
