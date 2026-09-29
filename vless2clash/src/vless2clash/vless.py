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
            return parsed
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
    "sessionTable": "session-table",
    "session-table": "session-table",
    "sessionLength": "session-length",
    "session-length": "session-length",
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


def _normalize_headers(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    return parsed if isinstance(parsed, dict) else value


def _normalize_alpn(value: object) -> object:
    if isinstance(value, str):
        return [item for item in re.split(r"[,|]", value) if item]
    return value


def _normalize_reality_settings(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    public_key = value.get("publicKey") or value.get("public-key")
    short_id = value.get("shortId") or value.get("short-id")
    if public_key:
        result["public-key"] = public_key
    if short_id:
        result["short-id"] = short_id
    return result


def _normalize_ech_settings(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    enabled = value.get("enable")
    if isinstance(enabled, str):
        parsed_enabled = _boolean(enabled)
        enabled = parsed_enabled if parsed_enabled is not None else enabled
    if enabled is not None:
        result["enable"] = enabled
    config = value.get("config") or value.get("Config")
    query_name = value.get("queryServerName") or value.get("query-server-name")
    if config:
        result["config"] = config
    if query_name:
        result["query-server-name"] = query_name
    return result


def _xray_ech_settings(tls_settings: dict[str, object]) -> dict[str, object]:
    nested = tls_settings.get("echSettings")
    nested_settings = nested if isinstance(nested, dict) else {}
    config_list = (
        nested_settings.get("ConfigList")
        or nested_settings.get("configList")
        or tls_settings.get("echConfigList")
    )
    force_query = (
        nested_settings.get("ForceQuery")
        or nested_settings.get("forceQuery")
        or tls_settings.get("echForceQuery")
    )
    if not config_list and not force_query:
        return {}

    result: dict[str, object] = {"enable": True}
    if not isinstance(config_list, str) or not config_list:
        return result

    query_match = re.fullmatch(
        r"([^+]+)\+(?:udp|https?|h2c)(?:\+local)?://.+", config_list
    )
    if query_match:
        result["query-server-name"] = query_match.group(1)
    elif "://" not in config_list:
        result["config"] = config_list
    return result


def _normalize_download_settings(
    value: object, *, parent_security: str = ""
) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}

    result: dict[str, object] = {}
    aliases = {
        "address": "server",
        "server": "server",
        "port": "port",
        "tls": "tls",
        "alpn": "alpn",
        "path": "path",
        "host": "host",
        "headers": "headers",
        "skipCertVerify": "skip-cert-verify",
        "skip-cert-verify": "skip-cert-verify",
        "nameCertVerify": "name-cert-verify",
        "name-cert-verify": "name-cert-verify",
        "certificate": "certificate",
        "privateKey": "private-key",
        "private-key": "private-key",
        "serverName": "servername",
        "servername": "servername",
        "clientFingerprint": "client-fingerprint",
        "client-fingerprint": "client-fingerprint",
        "fingerprint": "fingerprint",
    }
    for key, item in value.items():
        output_key = aliases.get(key)
        if not output_key or item in (None, ""):
            continue
        if output_key == "port":
            item = _number(item)
        elif output_key in {"tls", "skip-cert-verify"} and isinstance(item, str):
            parsed = _boolean(item)
            item = parsed if parsed is not None else item
        elif output_key == "alpn":
            item = _normalize_alpn(item)
        elif output_key == "headers":
            item = _normalize_headers(item)
        result[output_key] = item

    security = value.get("security")
    if isinstance(security, str):
        security = security.lower()
        if security in {"tls", "reality"}:
            result["tls"] = True
        elif security in {"none", ""}:
            result["tls"] = False
        if parent_security == "reality" and security != "reality":
            # A non-nil option overrides Mihomo's inherited uplink Reality config;
            # RealityOptions.Parse treats an explicitly empty public key as disabled.
            result["reality-opts"] = {"public-key": ""}

    xhttp_settings = value.get("xhttpSettings") or value.get("splithttpSettings")
    if isinstance(xhttp_settings, dict):
        for key in ("path", "host", "headers"):
            item = xhttp_settings.get(key)
            if item not in (None, ""):
                result[key] = _normalize_headers(item) if key == "headers" else item
        reuse = (
            xhttp_settings.get("reuse-settings")
            or xhttp_settings.get("reuseSettings")
            or xhttp_settings.get("xmux")
        )
        normalized_reuse = _normalize_reuse_settings(reuse)
        if normalized_reuse:
            result["reuse-settings"] = normalized_reuse

    direct_reuse = (
        value.get("reuse-settings") or value.get("reuseSettings") or value.get("xmux")
    )
    normalized_reuse = _normalize_reuse_settings(direct_reuse)
    if normalized_reuse:
        result["reuse-settings"] = normalized_reuse

    tls_settings = value.get("tlsSettings")
    if isinstance(tls_settings, dict):
        allow_insecure = tls_settings.get("allowInsecure")
        if allow_insecure is not None:
            if isinstance(allow_insecure, str):
                parsed = _boolean(allow_insecure)
                allow_insecure = parsed if parsed is not None else allow_insecure
            result["skip-cert-verify"] = allow_insecure
        servername = tls_settings.get("serverName")
        if servername:
            result["servername"] = servername
        fingerprint = tls_settings.get("fingerprint")
        if fingerprint:
            result["client-fingerprint"] = fingerprint
        alpn = tls_settings.get("alpn")
        if alpn:
            result["alpn"] = _normalize_alpn(alpn)
        name_cert_verify = tls_settings.get("verifyPeerCertByName")
        if name_cert_verify:
            result["name-cert-verify"] = name_cert_verify
        ech = _xray_ech_settings(tls_settings)
        if ech:
            result["ech-opts"] = ech

    ech = _normalize_ech_settings(value.get("echOpts") or value.get("ech-opts"))
    if ech:
        result["ech-opts"] = ech

    reality = _normalize_reality_settings(
        value.get("realitySettings")
        or value.get("realityOpts")
        or value.get("reality-opts")
    )
    if security == "reality" and reality:
        result["reality-opts"] = reality
    return result


def _normalize_xhttp(params: dict[str, str]) -> dict[str, object]:
    extra = _decode_extra(params.get("extra", "")) if params.get("extra") else {}
    nested = extra.get("xhttpSettings") or extra.get("splithttpSettings")
    nested_settings = nested if isinstance(nested, dict) else {}
    combined: dict[str, object] = {**extra, **nested_settings, **params}
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
        elif output_key == "headers":
            value = _normalize_headers(value)
        result[output_key] = value

    reuse = (
        combined.get("reuse-settings")
        or combined.get("reuseSettings")
        or combined.get("xmux")
    )
    normalized_reuse = _normalize_reuse_settings(reuse)
    if normalized_reuse:
        result["reuse-settings"] = normalized_reuse
    download = _normalize_download_settings(
        extra.get("downloadSettings")
        or extra.get("download-settings")
        or nested_settings.get("downloadSettings")
        or nested_settings.get("download-settings"),
        parent_security=params.get("security", "").lower(),
    )
    if download:
        result["download-settings"] = download
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
    if security == "reality" or (not security and (public_key or short_id)):
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
