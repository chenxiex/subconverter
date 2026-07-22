from __future__ import annotations

import pytest

from vless2clash.converter import build_clash_config, load_default_clash_config
from vless2clash.external_config import build_rulesets, parse_external_config


def test_given_external_config_shape() -> None:
    external = parse_external_config(
        """
[custom]
custom_proxy_group=香港延迟最低`url-test`hk`https://example.com/204`300,5
custom_proxy_group=香港`select`hk`[]香港延迟最低
enable_rule_generator=true
overwrite_original_rules=true
ruleset=REJECT,clash-classic:https://example.com/block.yaml
ruleset=DIRECT,[]GEOIP,CN
ruleset=香港,[]FINAL
"""
    )
    proxies = [{"name": "hk-1", "type": "vless"}]
    config = build_clash_config(proxies, external)
    assert config["proxy-groups"][0]["proxies"] == ["hk-1"]
    assert config["rules"] == [
        "RULE-SET,block,REJECT",
        "GEOIP,CN,DIRECT",
        "MATCH,香港",
    ]


def test_copied_default_clash_template() -> None:
    config = load_default_clash_config()
    assert config["log-level"] == "warning"
    assert config["listeners"] == [
        {"name": "socks", "type": "mixed", "listen": "127.0.0.1", "port": 10808, "udp": True},
        {"name": "socks2", "type": "mixed", "listen": "127.0.0.1", "port": 10809, "udp": True},
        {"name": "socks3", "type": "mixed", "listen": "0.0.0.0", "port": 10810, "udp": True},
    ]
    assert config["sniffer"]["override-destination"] is False
    assert config["dns"]["enhanced-mode"] == "redir-host"
    assert config["dns"]["nameserver"] == [
        "https://cloudflare-dns.com/dns-query#DNS&h3=true",
        "https://dns.google/dns-query",
    ]
    assert config["dns"]["respect-rules"] is True
    assert config["dns"]["proxy-server-nameserver"] == ["tls://223.5.5.5:853"]
    assert config["hosts"]["dns.google"][0] == "8.8.8.8"
    assert config["proxies"] is None
    assert config["proxy-groups"] is None
    assert config["rules"] is None


def test_groups_without_rules_fall_back_to_first_group() -> None:
    external = parse_external_config("custom_proxy_group=HK`select`hk\n")
    config = build_clash_config([{"name": "hk-1", "type": "vless"}], external)
    assert config["rules"] == ["MATCH,HK"]


@pytest.mark.parametrize(
    ("source", "behavior"),
    [
        ("clash-classic:https://example.com/hk.yaml", "classical"),
        ("clash-domain:https://example.com/hk.yaml", "domain"),
        ("clash-ipcidr:https://example.com/hk.yaml", "ipcidr"),
        ("https://example.com/hk.yaml", "classical"),
    ],
)
def test_two_field_rulesets_remain_providers_without_download(
    source: str, behavior: str
) -> None:
    def must_not_download(_: str) -> str:
        raise AssertionError("二字段 rule-provider 不应在转换阶段下载")

    result = build_rulesets(
        [f"HK,{source}"],
        loader=must_not_download,
        valid_policies={"HK"},
    )
    assert list(result.providers) == ["hk"]
    assert result.providers["hk"]["behavior"] == behavior
    assert result.rules == ["RULE-SET,hk,HK"]
    assert result.warnings == []


def test_explicit_full_rules_are_downloaded_and_expanded() -> None:
    result = build_rulesets(
        ["clash-rules:https://example.com/policy.yaml"],
        loader=lambda _: """
rules:
  - DOMAIN-SUFFIX,example.com,HK
  - IP-CIDR,10.0.0.0/8,DEFAULT,no-resolve
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT
""",
        valid_policies={"DEFAULT", "HK", "REJECT"},
    )
    assert result.providers == {}
    assert result.rules == [
        "DOMAIN-SUFFIX,example.com,HK",
        "IP-CIDR,10.0.0.0/8,DEFAULT,no-resolve",
        "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
    ]
    assert result.warnings == []


def test_missing_policy_is_a_warning_not_a_parse_failure() -> None:
    result = build_rulesets(
        ["clash-rules:https://example.com/policy.yaml"],
        loader=lambda _: "rules:\n  - DOMAIN,example.com,DOES-NOT-EXIST\n",
        valid_policies={"DEFAULT"},
    )
    assert result.rules == ["DOMAIN,example.com,DOES-NOT-EXIST"]
    assert result.warnings == [
        "规则集 https://example.com/policy.yaml 引用了不存在的策略/代理组 'DOES-NOT-EXIST'"
    ]


def test_explicit_full_rules_require_rules_root_and_policy() -> None:
    with pytest.raises(ValueError, match="缺少 rules 列表"):
        build_rulesets(
            ["clash-rules:https://example.com/policy.yaml"],
            loader=lambda _: "payload:\n  - DOMAIN,example.com,HK\n",
            valid_policies={"HK"},
        )

    with pytest.raises(ValueError, match="缺少策略字段"):
        build_rulesets(
            ["clash-rules:https://example.com/policy.yaml"],
            loader=lambda _: "rules:\n  - DOMAIN,example.com\n",
            valid_policies={"HK"},
        )
