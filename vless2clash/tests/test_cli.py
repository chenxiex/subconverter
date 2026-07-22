from __future__ import annotations

from urllib.parse import quote

import yaml

from vless2clash.cli import run


def test_complete_request_url(tmp_path) -> None:
    subscription = tmp_path / "subscription.txt"
    external = tmp_path / "external.ini"
    output = tmp_path / "output.yaml"
    subscription.write_text(
        "vless://id@example.com:443?encryption=none&type=xhttp&path=%2Fx#hk",
        encoding="utf-8",
    )
    external.write_text(
        "[custom]\ncustom_proxy_group=HK`select`hk\nruleset=HK,[]FINAL\n",
        encoding="utf-8",
    )
    request = (
        "http://127.0.0.1:25500/sub?target=clash"
        f"&url={quote(str(subscription), safe='')}"
        f"&config={quote(str(external), safe='')}"
    )
    assert run([request, "-o", str(output)]) == 0
    document = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert document["proxies"][0]["network"] == "xhttp"
    assert document["proxy-groups"][0]["proxies"] == ["hk"]
    assert document["rules"] == ["MATCH,HK"]


def test_missing_ruleset_policy_writes_output_and_returns_nonzero(
    tmp_path, monkeypatch, capsys
) -> None:
    output = tmp_path / "warning-output.yaml"
    sources = {
        "subscription": "vless://id@example.com:443?encryption=none&type=tcp#hk",
        "external": """
custom_proxy_group=HK`select`hk
overwrite_original_rules=true
ruleset=clash-rules:https://example.com/policy.yaml
""",
        "https://example.com/policy.yaml": "rules:\n  - DOMAIN,example.com,MISSING\n",
    }

    def fake_read_source(source: str, *, timeout: float = 20.0) -> str:
        return sources[source]

    monkeypatch.setattr("vless2clash.cli.read_source", fake_read_source)
    status = run(
        ["--url", "subscription", "--config", "external", "--output", str(output)]
    )
    assert status == 2
    assert output.is_file()
    document = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert document["rules"] == ["DOMAIN,example.com,MISSING"]
    stderr = capsys.readouterr().err
    assert "警告:" in stderr
    assert "MISSING" in stderr


def test_reads_inputs_from_default_dotenv(tmp_path, monkeypatch) -> None:
    subscription = tmp_path / "subscription.txt"
    output = tmp_path / "from-dotenv.yaml"
    subscription.write_text(
        "vless://id@example.com:443?encryption=none&type=tcp#env-node",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        f"VLESS2CLASH_URL={subscription}\n"
        f"VLESS2CLASH_OUTPUT={output}\n"
        "VLESS2CLASH_TARGET=mihomo\n"
        "VLESS2CLASH_TIMEOUT=5\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert run([]) == 0
    document = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert document["proxies"][0]["name"] == "env-node"


def test_process_environment_overrides_env_file(tmp_path, monkeypatch) -> None:
    subscription = tmp_path / "subscription.txt"
    output = tmp_path / "from-environment.yaml"
    subscription.write_text(
        "vless://id@example.com:443?encryption=none&type=tcp#system-env",
        encoding="utf-8",
    )
    env_file = tmp_path / "settings.env"
    env_file.write_text(
        "VLESS2CLASH_URL=missing-subscription.txt\n"
        "VLESS2CLASH_OUTPUT=wrong-output.yaml\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VLESS2CLASH_URL", str(subscription))
    monkeypatch.setenv("VLESS2CLASH_OUTPUT", str(output))

    assert run(["--env-file", str(env_file)]) == 0
    document = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert document["proxies"][0]["name"] == "system-env"


def test_command_line_overrides_environment(tmp_path, monkeypatch) -> None:
    subscription = tmp_path / "subscription.txt"
    output = tmp_path / "from-cli.yaml"
    subscription.write_text(
        "vless://id@example.com:443?encryption=none&type=tcp#cli",
        encoding="utf-8",
    )
    monkeypatch.setenv("VLESS2CLASH_URL", "missing-subscription.txt")
    monkeypatch.setenv("VLESS2CLASH_OUTPUT", "wrong-output.yaml")

    assert run(["--url", str(subscription), "--output", str(output)]) == 0
    document = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert document["proxies"][0]["name"] == "cli"
