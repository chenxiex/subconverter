from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from collections.abc import Callable
from urllib.parse import urlsplit

import yaml


@dataclass
class ExternalConfig:
    groups: list[str] = field(default_factory=list)
    rulesets: list[str] = field(default_factory=list)
    enable_rule_generator: bool = True
    overwrite_original_rules: bool = False


@dataclass
class RulesetBuildResult:
    providers: dict[str, dict[str, object]] = field(default_factory=dict)
    rules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_external_config(content: str) -> ExternalConfig:
    result = ExternalConfig()
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith((";", "#", "[")) or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key == "custom_proxy_group":
            result.groups.append(value)
        elif key == "ruleset":
            result.rulesets.append(value)
        elif key == "enable_rule_generator":
            result.enable_rule_generator = value.lower() in {"1", "true", "yes", "on"}
        elif key == "overwrite_original_rules":
            result.overwrite_original_rules = value.lower() in {"1", "true", "yes", "on"}
    return result


def _matched_names(pattern: str, names: list[str]) -> list[str]:
    try:
        matcher = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"代理组正则表达式无效 {pattern!r}: {exc}") from exc
    return [name for name in names if matcher.search(name)]


def build_proxy_groups(specs: list[str], proxies: list[dict[str, object]]) -> list[dict[str, object]]:
    names = [str(proxy["name"]) for proxy in proxies]
    groups: list[dict[str, object]] = []
    for spec in specs:
        fields = spec.split("`")
        if len(fields) < 3:
            raise ValueError(f"custom_proxy_group 格式无效: {spec}")
        name, group_type, *tokens = fields
        group: dict[str, object] = {"name": name, "type": group_type}
        selectors = tokens
        if group_type in {"url-test", "fallback", "load-balance"}:
            if len(tokens) < 3:
                raise ValueError(f"{group_type} 代理组缺少测试 URL 或间隔: {spec}")
            selectors = tokens[:-2]
            group["url"] = tokens[-2]
            interval_parts = tokens[-1].split(",")
            group["interval"] = int(interval_parts[0])
            if len(interval_parts) > 1 and interval_parts[1]:
                group["timeout"] = int(interval_parts[1])
            if len(interval_parts) > 2 and interval_parts[2]:
                group["tolerance"] = int(interval_parts[2])

        members: list[str] = []
        for selector in selectors:
            if selector.startswith("[]"):
                candidate = selector[2:]
                if candidate not in members:
                    members.append(candidate)
            elif selector:
                for candidate in _matched_names(selector, names):
                    if candidate not in members:
                        members.append(candidate)
        if not members:
            raise ValueError(f"代理组 {name!r} 没有匹配任何节点或组")
        group["proxies"] = members
        groups.append(group)
    return groups


def _provider_name(policy: str, url: str, used: set[str]) -> str:
    filename = urlsplit(url).path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    base = re.sub(r"[^0-9A-Za-z_-]+", "-", filename).strip("-") or re.sub(
        r"[^0-9A-Za-z_-]+", "-", policy
    ).strip("-")
    name = base or "ruleset"
    if name in used:
        name = f"{name}-{hashlib.sha1(url.encode()).hexdigest()[:8]}"
    used.add(name)
    return name


def _split_rule_fields(rule: str) -> list[str]:
    """Split a Clash rule on commas that are outside logical-rule parentheses."""
    fields: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(rule):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            fields.append(rule[start:index].strip())
            start = index + 1
    fields.append(rule[start:].strip())
    return fields


def _rule_policy(rule: str) -> tuple[str | None, int | None, list[str]]:
    fields = _split_rule_fields(rule)
    if not fields or not fields[0]:
        raise ValueError(f"空的 Clash 规则: {rule!r}")
    rule_type = fields[0].upper()
    if rule_type == "MATCH":
        return (fields[1], 1, fields) if len(fields) >= 2 else (None, None, fields)
    if fields[-1].lower() == "no-resolve":
        return (fields[-2], len(fields) - 2, fields) if len(fields) >= 4 else (None, None, fields)
    return (fields[-1], len(fields) - 1, fields) if len(fields) >= 3 else (None, None, fields)


def _full_rules(content: str, url: str) -> list[str]:
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"无法解析三字段规则 YAML {url}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ValueError(f"三字段规则 YAML 缺少 rules 列表: {url}")
    rules = document["rules"]
    if not all(isinstance(rule, str) and rule.strip() for rule in rules):
        raise ValueError(f"三字段规则 YAML 的 rules 必须全部是非空字符串: {url}")
    return [rule.strip() for rule in rules]


def _validate_full_rules(
    rules: list[str],
    url: str,
    valid_policies: set[str],
    warnings: list[str],
) -> list[str]:
    for rule in rules:
        policy, _, _ = _rule_policy(rule)
        if policy is None:
            raise ValueError(f"三字段规则缺少策略字段: {rule!r} ({url})")
        if policy not in valid_policies:
            warning = f"规则集 {url} 引用了不存在的策略/代理组 {policy!r}"
            if warning not in warnings:
                warnings.append(warning)
    return rules


def build_rulesets(
    specs: list[str],
    *,
    loader: Callable[[str], str] | None = None,
    valid_policies: set[str] | None = None,
) -> RulesetBuildResult:
    result = RulesetBuildResult()
    used: set[str] = set()
    accepted_policies = valid_policies or set()
    for spec in specs:
        if spec.startswith("clash-rules:"):
            url = spec[len("clash-rules:") :].strip()
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"clash-rules 目前仅支持 HTTP/HTTPS URL: {url}")
            if loader is None:
                raise ValueError("clash-rules 需要规则加载器")
            rules = _full_rules(loader(url), url)
            result.rules.extend(
                _validate_full_rules(
                    rules,
                    url,
                    accepted_policies,
                    result.warnings,
                )
            )
            continue

        if "," not in spec:
            raise ValueError(f"ruleset 格式无效: {spec}")
        policy, source = (part.strip() for part in spec.split(",", 1))
        if source.startswith("[]"):
            inline = source[2:]
            if inline == "FINAL":
                result.rules.append(f"MATCH,{policy}")
            else:
                result.rules.append(f"{inline},{policy}")
            continue

        interval = 86400
        interval_match = re.match(r"^(.*),(\d+)$", source)
        if interval_match:
            source = interval_match.group(1).strip()
            interval = int(interval_match.group(2))

        behavior = "classical"
        url = source
        for prefix, mapped in (
            ("clash-classic:", "classical"),
            ("clash-domain:", "domain"),
            ("clash-ipcidr:", "ipcidr"),
        ):
            if source.startswith(prefix):
                behavior = mapped
                url = source[len(prefix) :]
                break
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"目前仅支持 Clash HTTP ruleset 或 [] 内联规则: {source}")

        name = _provider_name(policy, url, used)
        result.providers[name] = {
            "type": "http",
            "behavior": behavior,
            "format": "yaml",
            "url": url,
            "path": f"./ruleset/{name}.yaml",
            "interval": interval,
        }
        result.rules.append(f"RULE-SET,{name},{policy}")
    return result
