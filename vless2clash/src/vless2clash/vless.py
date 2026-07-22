from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, unquote, urlsplit


class VlessParseError(ValueError):
    """Raised when a VLESS share link is malformed."""


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def _first(params: dict[str, str], *names: str) -> str:
    for name in names:
        value = params.get(name)
        if value is not None and value != "":
            return value
    return ""


def _boolean(value: str) -> bool | None:
    lowered = value.lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    return None


def _number(value: object) -> object:
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _decode_extra(value: str) -> dict[str, object]:
    if not value:
        return {}
    candidates = [value]
    padding = "=" * (-len(value) % 4)
    try:
        candidates.append(base64.urlsafe_b64decode(value + padding).decode())
    except (ValueError, UnicodeDecodeError):
        pass
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            nested = parsed.get("xhttpSettings") or parsed.get("splithttpSettings")
            return nested if isinstance(nested, dict) else parsed
    raise VlessParseError("xHTTP extra 参数不是有效的 JSON 或 URL-safe Base64 JSON")


XHTTP_ALIASES = {
    "path": "path",
    "host": "host",
    "mode": "mode",
    "headers": "headers",
    "noGRPCHeader": "no-grpc-header",
    "noGrpcHeader": "no-grpc-header",
    "no-grpc-header": "no-grpc-header",
    "xPaddingBytes": "x-padding-bytes",
    "x-padding-bytes": "x-padding-bytes",
    "xPaddingObfsMode": "x-padding-obfs-mode",
    "x-padding-obfs-mode": "x-padding-obfs-mode",
    "xPaddingKey": "x-padding-key",
    "x-padding-key": "x-padding-key",
    "xPaddingHeader": "x-padding-header",
    "x-padding-header": "x-padding-header",
    "xPaddingPlacement": "x-padding-placement",
    "x-padding-placement": "x-padding-placement",
    "xPaddingMethod": "x-padding-method",
    "x-padding-method": "x-padding-method",
    "uplinkHTTPMethod": "uplink-http-method",
    "uplink-http-method": "uplink-http-method",
    "sessionPlacement": "session-placement",
    "session-placement": "session-placement",
    "sessionKey": "session-key",
    "session-key": "session-key",
    "seqPlacement": "seq-placement",
    "seq-placement": "seq-placement",
    "seqKey": "seq-key",
    "seq-key": "seq-key",
    "uplinkDataPlacement": "uplink-data-placement",
    "uplink-data-placement": "uplink-data-placement",
    "uplinkDataKey": "uplink-data-key",
    "uplink-data-key": "uplink-data-key",
    "uplinkChunkSize": "uplink-chunk-size",
    "uplink-chunk-size": "uplink-chunk-size",
    "scMaxEachPostBytes": "sc-max-each-post-bytes",
    "sc-max-each-post-bytes": "sc-max-each-post-bytes",
    "scMinPostsIntervalMs": "sc-min-posts-interval-ms",
    "sc-min-posts-interval-ms": "sc-min-posts-interval-ms",
}

BOOLEAN_XHTTP_FIELDS = {"no-grpc-header", "x-padding-obfs-mode"}
INTEGER_XHTTP_FIELDS = {
    "uplink-chunk-size",
    "sc-max-each-post-bytes",
    "sc-min-posts-interval-ms",
}


def _normalize_reuse_settings(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    aliases = {
        "maxConcurrency": "max-concurrency",
        "maxConnections": "max-connections",
        "cMaxReuseTimes": "c-max-reuse-times",
        "hMaxRequestTimes": "h-max-request-times",
        "hMaxReusableSecs": "h-max-reusable-secs",
        "hKeepAlivePeriod": "h-keep-alive-period",
    }
    result: dict[str, object] = {}
    for key, item in value.items():
        output_key = aliases.get(key, key)
        result[output_key] = _number(item)
    return result


def _normalize_xhttp(params: dict[str, str]) -> dict[str, object]:
    extra = _decode_extra(params.get("extra", "")) if params.get("extra") else {}
    combined: dict[str, object] = {**extra, **params}
    result: dict[str, object] = {}
    for key, value in combined.items():
        output_key = XHTTP_ALIASES.get(key)
        if not output_key or value in (None, ""):
            continue
        if output_key in BOOLEAN_XHTTP_FIELDS and isinstance(value, str):
            parsed = _boolean(value)
            value = parsed if parsed is not None else value
        elif output_key in INTEGER_XHTTP_FIELDS:
            value = _number(value)
        elif output_key == "headers" and isinstance(value, str):
            try:
                parsed_headers = json.loads(value)
                value = parsed_headers if isinstance(parsed_headers, dict) else value
            except json.JSONDecodeError:
                pass
        result[output_key] = value

    reuse = extra.get("reuse-settings") or extra.get("reuseSettings") or extra.get("xmux")
    normalized_reuse = _normalize_reuse_settings(reuse)
    if normalized_reuse:
        result["reuse-settings"] = normalized_reuse
    return result


def parse_vless_link(link: str) -> dict[str, object]:
    link = link.strip()
    parsed = urlsplit(link)
    if parsed.scheme.lower() != "vless":
        raise VlessParseError("仅支持 vless:// 分享链接")
    if not parsed.username:
        raise VlessParseError("VLESS 链接缺少 UUID")
    if not parsed.hostname:
        raise VlessParseError("VLESS 链接缺少服务器地址")
    try:
        port = parsed.port
    except ValueError as exc:
        raise VlessParseError("VLESS 端口无效") from exc
    if port is None:
        raise VlessParseError("VLESS 链接缺少端口")

    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    name = unquote(parsed.fragment) or f"{parsed.hostname}:{port}"
    network = _first(params, "type", "network").lower() or "tcp"
    if network in {"raw", "none"}:
        network = "tcp"
    if network == "splithttp":
        network = "xhttp"

    proxy: dict[str, object] = {
        "name": name,
        "type": "vless",
        "server": parsed.hostname,
        "port": port,
        "uuid": unquote(parsed.username),
        "udp": _boolean(params.get("udp", "true")) is not False,
    }

    encryption = params.get("encryption")
    if encryption is not None:
        proxy["encryption"] = encryption
    flow = params.get("flow", "")
    if flow:
        proxy["flow"] = flow
    packet_encoding = _first(params, "packet-encoding", "packetEncoding")
    if packet_encoding:
        proxy["packet-encoding"] = packet_encoding

    security = params.get("security", "").lower()
    tls = security in {"tls", "reality"} or _boolean(params.get("tls", "")) is True
    if tls:
        proxy["tls"] = True
    servername = _first(params, "sni", "peer", "servername")
    if servername:
        proxy["servername"] = servername
    fingerprint = _first(params, "fp", "client-fingerprint", "fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    alpn = params.get("alpn", "")
    if alpn:
        proxy["alpn"] = [item for item in re.split(r"[,|]", alpn) if item]
    insecure = _first(params, "allowInsecure", "insecure", "skip-cert-verify")
    if insecure:
        parsed_insecure = _boolean(insecure)
        if parsed_insecure is not None:
            proxy["skip-cert-verify"] = parsed_insecure

    public_key = _first(params, "pbk", "public-key")
    short_id = _first(params, "sid", "short-id")
    if security == "reality" or public_key or short_id:
        reality: dict[str, str] = {}
        if public_key:
            reality["public-key"] = public_key
        if short_id:
            reality["short-id"] = short_id
        if reality:
            proxy["reality-opts"] = reality

    host = params.get("host", "")
    path = params.get("path", "")
    if network == "tcp":
        proxy["network"] = "tcp"
    elif network == "ws":
        proxy["network"] = "ws"
        opts: dict[str, object] = {}
        if path:
            opts["path"] = path
        if host:
            opts["headers"] = {"Host": host}
        early_data = _first(params, "ed", "max-early-data")
        if early_data:
            opts["max-early-data"] = _number(early_data)
        early_header = _first(params, "eh", "early-data-header-name")
        if early_header:
            opts["early-data-header-name"] = early_header
        if opts:
            proxy["ws-opts"] = opts
    elif network == "grpc":
        proxy["network"] = "grpc"
        opts = {}
        service_name = _first(params, "serviceName", "service-name") or path
        if service_name:
            opts["grpc-service-name"] = service_name
        mode = params.get("mode", "")
        if mode:
            opts["grpc-mode"] = mode
        if opts:
            proxy["grpc-opts"] = opts
    elif network in {"h2", "http"}:
        proxy["network"] = network
        opts = {}
        if path:
            opts["path"] = [path] if network == "http" else path
        if host:
            opts["headers" if network == "http" else "host"] = (
                {"Host": [host]} if network == "http" else [host]
            )
        if opts:
            proxy[f"{network}-opts"] = opts
    elif network in {"httpupgrade", "http-upgrade"}:
        proxy["network"] = "ws"
        proxy["v2ray-http-upgrade"] = True
        opts = {}
        if path:
            opts["path"] = path
        if host:
            opts["headers"] = {"Host": host}
        if opts:
            proxy["ws-opts"] = opts
    elif network == "xhttp":
        proxy["network"] = "xhttp"
        opts = _normalize_xhttp(params)
        if path:
            opts["path"] = path
        if host:
            opts["host"] = host
        mode = params.get("mode", "")
        if mode:
            opts["mode"] = mode
        proxy["xhttp-opts"] = opts
    else:
        raise VlessParseError(f"不支持的 VLESS 传输类型: {network}")
    return proxy


def make_names_unique(proxies: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    counts: dict[str, int] = {}
    for original in proxies:
        proxy = dict(original)
        name = str(proxy["name"])
        counts[name] = counts.get(name, 0) + 1
        if counts[name] > 1:
            proxy["name"] = f"{name} {counts[name]}"
        result.append(proxy)
    return result
