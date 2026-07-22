from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from dotenv import dotenv_values

from .converter import build_clash_config, dump_clash_config
from .external_config import parse_external_config
from .source import parse_subscription, read_source
from .vless import VlessParseError


def _request_defaults(request: str | None) -> dict[str, str]:
    if not request:
        return {}
    query = parse_qs(urlsplit(request).query, keep_blank_values=True)
    return {key: values[-1] for key, values in query.items() if values}


ENV_PREFIX = "VLESS2CLASH_"


def _environment_defaults(env_file: Path) -> dict[str, str]:
    """Read prefixed settings, with the process environment overriding .env."""
    values = {
        key: value
        for key, value in dotenv_values(env_file).items()
        if key.startswith(ENV_PREFIX) and value is not None
    }
    values.update(
        (key, value)
        for key, value in os.environ.items()
        if key.startswith(ENV_PREFIX)
    )
    return {
        key.removeprefix(ENV_PREFIX).lower(): value for key, value in values.items()
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vless2clash",
        description="将 VLESS 分享链接或订阅转换为 Mihomo/Clash YAML。",
    )
    parser.add_argument(
        "request",
        nargs="?",
        help="可选：完整的 /sub?target=...&url=...&config=... 请求 URL",
    )
    parser.add_argument("--target", choices=("clash", "mihomo"), help="输出目标；默认 clash")
    parser.add_argument("--url", help="订阅 URL、本地文件或 vless:// 链接；多个源用 | 分隔")
    parser.add_argument("--config", help="可选的 subconverter INI 外部配置 URL 或本地文件")
    parser.add_argument("-o", "--output", help="输出 YAML 文件")
    parser.add_argument("--timeout", type=float, help="HTTP 超时秒数（默认 20）")
    parser.add_argument(
        "--env-file",
        help="环境变量文件（默认读取当前目录的 .env）",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    env_file = Path(args.env_file) if args.env_file else Path.cwd() / ".env"
    if args.env_file and not env_file.is_file():
        parser.error(f"环境变量文件不存在: {env_file}")
    environment = _environment_defaults(env_file)
    request = args.request or environment.get("request")
    defaults = _request_defaults(request)
    target = args.target or defaults.get("target") or environment.get("target", "clash")
    source_arg = args.url or defaults.get("url") or environment.get("url")
    config_arg = args.config or defaults.get("config") or environment.get("config")
    output_arg = args.output or environment.get("output")
    timeout_value = (
        args.timeout if args.timeout is not None else environment.get("timeout", 20.0)
    )
    if target not in {"clash", "mihomo"}:
        parser.error("target 仅支持 clash 或 mihomo")
    if not source_arg:
        parser.error("必须通过 --url、请求 URL 或 VLESS2CLASH_URL 提供订阅")
    if not output_arg:
        parser.error("必须通过 --output 或 VLESS2CLASH_OUTPUT 指定输出文件")
    try:
        timeout = float(timeout_value)
    except (TypeError, ValueError):
        parser.error("VLESS2CLASH_TIMEOUT 必须是数字")

    proxies: list[dict[str, object]] = []
    for source in source_arg.split("|"):
        proxies.extend(parse_subscription(read_source(source, timeout=timeout)))
    if not proxies:
        raise VlessParseError("没有解析到节点")

    external = None
    if config_arg:
        external = parse_external_config(read_source(config_arg, timeout=timeout))
    warnings: list[str] = []
    document = build_clash_config(
        proxies,
        external,
        ruleset_loader=lambda url: read_source(url, timeout=timeout),
        warnings=warnings,
    )
    output = Path(output_arg)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(dump_clash_config(document), encoding="utf-8")
    for warning in warnings:
        print(f"警告: {warning}", file=sys.stderr)
    print(f"已写入 {output}（{len(proxies)} 个节点）", file=sys.stderr)
    return 2 if warnings else 0


def main() -> None:
    try:
        raise SystemExit(run())
    except (VlessParseError, ValueError, FileNotFoundError, httpx.HTTPError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
