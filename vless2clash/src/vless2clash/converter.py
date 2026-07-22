from __future__ import annotations

from collections.abc import Callable
from importlib.resources import files

import yaml

from .external_config import ExternalConfig, build_proxy_groups, build_rulesets


def load_default_clash_config() -> dict[str, object]:
    """Load the packaged copy of subconverter's default Clash base template."""
    resource = files("vless2clash").joinpath("resources/clash_base.yml")
    document = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("内置 Clash 基础模板不是有效的 YAML 对象")
    return document


def build_clash_config(
    proxies: list[dict[str, object]],
    external: ExternalConfig | None = None,
    *,
    ruleset_loader: Callable[[str], str] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, object]:
    config = load_default_clash_config()
    config["proxies"] = proxies
    if external and external.groups:
        config["proxy-groups"] = build_proxy_groups(external.groups, proxies)
    else:
        config["proxy-groups"] = [
            {"name": "PROXY", "type": "select", "proxies": [str(item["name"]) for item in proxies]}
        ]

    original_rules = config.get("rules")
    original_rule_list = original_rules if isinstance(original_rules, list) else []
    if external and external.enable_rule_generator and external.rulesets:
        groups = config["proxy-groups"]
        valid_policies = {
            *(str(group["name"]) for group in groups),
            *(str(proxy["name"]) for proxy in proxies),
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "PASS",
            "COMPATIBLE",
            "GLOBAL",
        }
        result = build_rulesets(
            external.rulesets,
            loader=ruleset_loader,
            valid_policies=valid_policies,
        )
        if result.providers:
            config["rule-providers"] = result.providers
        config["rules"] = (
            result.rules
            if external.overwrite_original_rules
            else [*original_rule_list, *result.rules]
        )
        if warnings is not None:
            warnings.extend(result.warnings)
    else:
        groups = config["proxy-groups"]
        fallback_group = str(groups[0]["name"])
        config["rules"] = original_rule_list or [f"MATCH,{fallback_group}"]
    return config


class _MihomoDumper(yaml.SafeDumper):
    pass


def _disable_aliases(self: yaml.SafeDumper, data: object) -> bool:
    return True


_MihomoDumper.ignore_aliases = _disable_aliases  # type: ignore[method-assign]


def dump_clash_config(config: dict[str, object]) -> str:
    return yaml.dump(
        config,
        Dumper=_MihomoDumper,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=4096,
    )
