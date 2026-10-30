#!/usr/bin/env python3
"""Generate client rule providers from Johnshall's Shadowrocket sr_cnip.conf."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/Johnshall/"
    "Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf"
)
PAGES_BASE = "https://remix123.github.io/mihomo-cnip-doh-rules"
RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
}


def extract_rule_lines(text: str) -> tuple[list[str], list[str], str, int, str]:
    lines = text.splitlines()
    try:
        start = lines.index("[Rule]") + 1
    except ValueError as exc:
        raise ValueError("Upstream file has no [Rule] section") from exc

    end = next(
        (index for index in range(start, len(lines)) if lines[index].startswith("[")),
        len(lines),
    )
    proxy_rules: list[str] = []
    direct_rules: list[str] = []
    final_policy = ""
    active_count = 0

    for line_number, raw_line in enumerate(lines[start:end], start + 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Shadowrocket's inline comments start after the rule's policy.
        line = line.split(" #", 1)[0].strip()
        fields = [field.strip() for field in next(csv.reader([line], skipinitialspace=True))]
        if not fields:
            continue
        active_count += 1
        rule_type = fields[0].upper()

        if rule_type in {"FINAL", "MATCH"}:
            if len(fields) < 2:
                raise ValueError(f"Line {line_number}: {rule_type} has no policy")
            final_policy = fields[1].upper()
            continue

        if rule_type not in RULE_TYPES:
            raise ValueError(f"Line {line_number}: unsupported Mihomo rule type {rule_type}")
        if len(fields) < 3:
            raise ValueError(f"Line {line_number}: rule has no policy")

        policy = fields[2].upper()
        if policy not in {"PROXY", "DIRECT"}:
            raise ValueError(f"Line {line_number}: unsupported policy {fields[2]}")

        # RULE-SET files hold matching conditions; the route action belongs to
        # the referencing RULE-SET entry. Preserve optional flags after policy.
        provider_rule = ",".join([rule_type, fields[1], *fields[3:]])
        if policy == "PROXY":
            proxy_rules.append(provider_rule)
        else:
            direct_rules.append(provider_rule)

    if not proxy_rules or not direct_rules:
        raise ValueError("Upstream profile must contain both proxy and direct rules")
    if final_policy != "PROXY":
        raise ValueError(f"Expected FINAL,PROXY; found {final_policy or 'none'}")

    build_time = next(
        (match.group(1).strip() for line in lines if (match := re.match(r"#\s*build time:\s*(.+)", line, re.I))),
        "unknown",
    )
    return proxy_rules, direct_rules, final_policy, active_count, build_time


def yaml_payload(rules: list[str]) -> str:
    entries = "\n".join(f"  - {json.dumps(rule, ensure_ascii=False)}" for rule in rules)
    return f"# Generated from Johnshall sr_cnip.conf; do not edit by hand.\npayload:\n{entries}\n"


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def generate(source: Path, output: Path) -> dict[str, object]:
    source_bytes = source.read_bytes()
    source_text = source_bytes.decode("utf-8-sig")
    proxy_rules, direct_rules, final_policy, active_count, build_time = extract_rule_lines(source_text)
    digest = hashlib.sha256(source_bytes).hexdigest()

    write_text(output / "mihomo/sr_cnip_proxy.yaml", yaml_payload(proxy_rules))
    write_text(output / "mihomo/sr_cnip_direct.yaml", yaml_payload(direct_rules))
    write_text(output / "shadowrocket/sr_cnip_proxy.list", "\n".join(proxy_rules) + "\n")
    write_text(output / "shadowrocket/sr_cnip_direct.list", "\n".join(direct_rules) + "\n")

    metadata: dict[str, object] = {
        "profile": "sr_cnip",
        "source": SOURCE_URL,
        "source_build_time_utc": build_time,
        "source_sha256": digest,
        "source_active_rule_count": active_count,
        "proxy_rule_count": len(proxy_rules),
        "direct_rule_count": len(direct_rules),
        "final_policy": final_policy,
        "license": "CC BY-SA 4.0",
    }
    write_text(output / "metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")

    providers = f"""# Merge these mappings into the existing Mihomo config.
rule-providers:
  sr-cnip-proxy:
    type: http
    behavior: classical
    format: yaml
    url: {PAGES_BASE}/mihomo/sr_cnip_proxy.yaml
    path: ./rule-providers/sr_cnip_proxy.yaml
    interval: 86400
  sr-cnip-direct:
    type: http
    behavior: classical
    format: yaml
    url: {PAGES_BASE}/mihomo/sr_cnip_direct.yaml
    path: ./rule-providers/sr_cnip_direct.yaml
    interval: 86400

# Put after app-specific rules and before broad country/GEOIP rules.
rules:
  - RULE-SET,sr-cnip-proxy,Proxy
  - RULE-SET,sr-cnip-direct,DIRECT
  - MATCH,Proxy
"""
    write_text(output / "config/mihomo-rules.yaml", providers)

    shadowrocket_rules = f"""# Merge these entries into the active Shadowrocket [Rule] section.
# Place after app-specific rules and before broad country/GEOIP rules.
RULE-SET,{PAGES_BASE}/shadowrocket/sr_cnip_proxy.list,PROXY
RULE-SET,{PAGES_BASE}/shadowrocket/sr_cnip_direct.list,DIRECT
FINAL,PROXY
"""
    write_text(output / "config/shadowrocket-rules.conf", shadowrocket_rules)

    escaped_build = html.escape(build_time)
    index = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>sr_cnip 客户端规则</title>
  <style>
    body {{ max-width: 760px; margin: 3rem auto; padding: 0 1rem; font: 16px/1.6 system-ui, sans-serif; color: #202124; }}
    h1, h2 {{ line-height: 1.25; }}
    li {{ margin: .45rem 0; }}
    code {{ background: #f2f3f5; padding: .12rem .3rem; }}
  </style>
</head>
<body>
  <h1>sr_cnip 规则</h1>
  <p>上游构建时间：<code>{escaped_build}</code>；代理规则 {len(proxy_rules)} 条，直连规则 {len(direct_rules)} 条。</p>
  <h2>Mihomo</h2>
  <ul>
    <li><a href="mihomo/sr_cnip_proxy.yaml">代理规则 provider</a></li>
    <li><a href="mihomo/sr_cnip_direct.yaml">直连规则 provider</a></li>
    <li><a href="config/mihomo-rules.yaml">provider 与路由片段</a></li>
    <li><a href="config/mihomo-dns.yaml">DNS 分流片段</a></li>
  </ul>
  <h2>Shadowrocket</h2>
  <ul>
    <li><a href="shadowrocket/sr_cnip_proxy.list">代理规则集</a></li>
    <li><a href="shadowrocket/sr_cnip_direct.list">直连规则集</a></li>
    <li><a href="config/shadowrocket-rules.conf">RULE-SET 引用片段</a></li>
  </ul>
  <p>源文件：<a href="{SOURCE_URL}">Johnshall sr_cnip.conf</a></p>
  <p><a href="metadata.json">生成元数据</a> · 上游规则遵循 CC BY-SA 4.0。</p>
</body>
</html>
"""
    write_text(output / "index.html", index)
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True, help="Downloaded Johnshall sr_cnip.conf")
    parser.add_argument("--output", type=Path, default=Path("public"))
    args = parser.parse_args()
    metadata = generate(args.source, args.output)
    print(
        "Generated: "
        f"{metadata['proxy_rule_count']} proxy rules, "
        f"{metadata['direct_rule_count']} direct rules "
        f"from upstream build {metadata['source_build_time_utc']}"
    )


if __name__ == "__main__":
    main()
