#!/usr/bin/env python3
"""Generate Mihomo providers and an adapted full Shadowrocket profile from Johnshall."""

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
VAN_DNS_REFERENCE = (
    "https://raw.githubusercontent.com/Van426326/"
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
SHADOWROCKET_DNS_KEYS = {
    "dns-server",
    "direct-dns-server",
    "fallback-dns-server",
    "proxy-dns-server",
    "dns-direct-system",
    "dns-direct-fallback-proxy",
    "ipv6",
    "prefer-ipv6",
    "hijack-dns",
}
APPLE_LS_SKIP_PROXY = "*.ls.apple.com"
APPLE_INTELLIGENCE_HOST = "gspe1-ssl.ls.apple.com"
APPLE_MAPS_HOST = "gspe19-cn-ssl.ls.apple.com"


def shadowrocket_full_profile(source_text: str) -> str:
    """Keep Johnshall's full profile, adjust DNS, and make its Tailscale routes work."""
    lines = source_text.splitlines()
    general_start = next(
        (index for index, line in enumerate(lines) if line.strip().lower() == "[general]"),
        None,
    )
    if general_start is None:
        raise ValueError("Johnshall profile has no [General] section")
    general_end = next(
        (index for index in range(general_start + 1, len(lines)) if lines[index].strip().startswith("[")),
        len(lines),
    )

    dns_block = [
        "# DNS: Cloudflare DoH through the selected proxy; AliDNS DoH direct for direct and node-bootstrap lookups.",
        "# Based on Van426326 DNS behavior and Rabbit-DoH.yaml resolver endpoints.",
        "dns-server = https://1.1.1.1/dns-query#proxy,https://1.0.0.1/dns-query#proxy",
        "direct-dns-server = https://223.5.5.5/dns-query,https://223.6.6.6/dns-query",
        "proxy-dns-server = https://223.5.5.5/dns-query,https://223.6.6.6/dns-query",
        "fallback-dns-server = https://1.1.1.1/dns-query#proxy,https://1.0.0.1/dns-query#proxy",
        "dns-direct-system = false",
        "dns-direct-fallback-proxy = false",
        "ipv6 = false",
        "prefer-ipv6 = false",
        "hijack-dns = 8.8.8.8:53,8.8.4.4:53,1.1.1.1:53,1.0.0.1:53",
    ]

    insertion_index = general_end
    for index in range(general_start + 1, general_end):
        line = lines[index].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip().lower()
        if key in SHADOWROCKET_DNS_KEYS:
            insertion_index = index
            break

    result: list[str] = []
    for index, line in enumerate(lines):
        if index == insertion_index:
            result.extend(dns_block)
        if general_start < index < general_end:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0].strip().lower()
                if key in SHADOWROCKET_DNS_KEYS:
                    continue
        result.append(line)
    if insertion_index == len(lines):
        result.extend(dns_block)

    profile = "\n".join(result) + "\n"
    profile = remove_tailscale_cgnat_bypass(profile)
    profile = add_tailscale_rules(profile)
    if PAGES_BASE in profile:
        raise ValueError("Full Shadowrocket profile must not depend on GitHub Pages rule URLs")
    if "[Rule]" not in profile or "RULE-SET," in profile:
        raise ValueError("Expected Johnshall's inline [Rule] section in the full profile")
    if "IP-CIDR,100.64.0.0/10,TAILSCALE,no-resolve" not in profile or "DOMAIN-SUFFIX,ts.net,TAILSCALE" not in profile:
        raise ValueError("Tailscale CGNAT rule missing from the full profile")
    in_general = False
    for line in profile.splitlines():
        if line.strip().startswith("["):
            in_general = line.strip().lower() == "[general]"
            continue
        stripped = line.strip()
        if in_general and stripped.lower().startswith("bypass-tun") and "=" in stripped:
            ranges = [part.strip() for part in stripped.split("=", 1)[1].split(",")]
            if "100.64.0.0/10" in ranges:
                raise ValueError("Tailscale CGNAT range remains in bypass-tun")
    return profile


def shadowrocket_apple_intelligence_profile(source_text: str) -> str:
    """Build an opt-in profile that proxies Apple's region check."""
    profile = shadowrocket_full_profile(source_text)
    profile = remove_skip_proxy_entry(profile, APPLE_LS_SKIP_PROXY)
    profile = add_apple_intelligence_rules(profile)

    in_general = False
    for line in profile.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_general = stripped.lower() == "[general]"
            continue
        if in_general and stripped.lower().startswith("skip-proxy") and "=" in stripped:
            entries = [item.strip().casefold() for item in stripped.split("=", 1)[1].split(",")]
            if APPLE_LS_SKIP_PROXY.casefold() in entries:
                raise ValueError("Apple Intelligence profile still bypasses all ls.apple.com hosts")

    required_rules = {
        f"DOMAIN,{APPLE_INTELLIGENCE_HOST},PROXY".casefold(),
        f"DOMAIN,{APPLE_MAPS_HOST},DIRECT".casefold(),
    }
    rule_start = next(
        (index for index, line in enumerate(profile.splitlines()) if line.strip().lower() == "[rule]"),
        None,
    )
    if rule_start is None:
        raise ValueError("Apple Intelligence profile has no [Rule] section")
    rule_lines = profile.splitlines()[rule_start + 1:]
    present_rules = {line.strip().split(" #", 1)[0].casefold() for line in rule_lines}
    if not required_rules.issubset(present_rules):
        raise ValueError("Apple Intelligence profile is missing an explicit Apple route")
    return profile


def remove_skip_proxy_entry(profile: str, entry_to_remove: str) -> str:
    """Remove one exact domain or wildcard from [General].skip-proxy."""
    lines = profile.splitlines()
    in_general = False
    updated: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_general = stripped.lower() == "[general]"
            updated.append(line)
            continue
        if in_general and stripped.lower().startswith("skip-proxy") and "=" in line:
            prefix, value = line.split("=", 1)
            entries = [item for item in value.split(",") if item.strip().casefold() != entry_to_remove.casefold()]
            line = prefix + "=" + ",".join(entries)
        updated.append(line)
    return "\n".join(updated) + "\n"


def add_apple_intelligence_rules(profile: str) -> str:
    """Put exact Apple routes before broad/upstream routing rules."""
    lines = profile.splitlines()
    try:
        rule_start = next(index for index, line in enumerate(lines) if line.strip().lower() == "[rule]")
    except StopIteration as exc:
        raise ValueError("Johnshall profile has no [Rule] section") from exc
    rule_end = next(
        (index for index in range(rule_start + 1, len(lines)) if lines[index].strip().startswith("[")),
        len(lines),
    )

    targets = {APPLE_INTELLIGENCE_HOST.casefold(), APPLE_MAPS_HOST.casefold()}
    kept_lines: list[str] = []
    for index, line in enumerate(lines):
        if not rule_start < index < rule_end:
            kept_lines.append(line)
            continue
        route = line.split(" #", 1)[0].strip()
        if not route or route.startswith("#"):
            kept_lines.append(line)
            continue
        fields = [field.strip() for field in next(csv.reader([route], skipinitialspace=True))]
        rule_type = fields[0].upper() if fields else ""
        domain = fields[1].casefold() if len(fields) > 1 else ""
        policy = fields[2].upper() if len(fields) > 2 else ""
        is_managed_host = rule_type in {"DOMAIN", "DOMAIN-SUFFIX"} and domain in targets
        is_broad_direct = (
            rule_type == "DOMAIN-SUFFIX"
            and domain == "ls.apple.com"
            and policy == "DIRECT"
        )
        if not is_managed_host and not is_broad_direct:
            kept_lines.append(line)

    rule_start = next(index for index, line in enumerate(kept_lines) if line.strip().lower() == "[rule]")
    overrides = [
        "# Apple Intelligence variant: proxy the region check; keep only the exact Maps hostname direct.",
        f"DOMAIN,{APPLE_INTELLIGENCE_HOST},Proxy",
        f"DOMAIN,{APPLE_MAPS_HOST},DIRECT",
    ]
    kept_lines[rule_start + 1:rule_start + 1] = overrides
    return "\n".join(kept_lines) + "\n"


def remove_tailscale_cgnat_bypass(profile: str) -> str:
    """Remove only Tailscale's CGNAT range from [General] bypass-tun."""
    lines = profile.splitlines()
    in_general = False
    updated: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_general = stripped.lower() == "[general]"
            updated.append(line)
            continue
        if in_general and stripped.lower().startswith("bypass-tun") and "=" in line:
            prefix, value = line.split("=", 1)
            ranges = [item for item in value.split(",") if item.strip() != "100.64.0.0/10"]
            line = prefix + "=" + ",".join(ranges)
        updated.append(line)
    return "\n".join(updated) + "\n"


def add_tailscale_rules(profile: str) -> str:
    """Route MagicDNS names and literal tailnet IPs to Shadowrocket's Tailscale module."""
    rules = [
        "DOMAIN-SUFFIX,ts.net,TAILSCALE",
        "IP-CIDR,100.64.0.0/10,TAILSCALE,no-resolve",
    ]
    lines = profile.splitlines()
    try:
        rule_index = next(index for index, line in enumerate(lines) if line.strip().lower() == "[rule]")
    except StopIteration as exc:
        raise ValueError("Johnshall profile has no [Rule] section") from exc

    existing = {line.strip().lower() for line in lines[rule_index + 1:]}
    missing = [rule for rule in rules if rule.lower() not in existing]
    if not missing:
        return profile
    lines[rule_index + 1:rule_index + 1] = [
        "# Tailscale module routes; enable Tailscale in Shadowrocket settings.",
        *missing,
    ]
    return "\n".join(lines) + "\n"


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
        "shadowrocket_full_profile_source": SOURCE_URL,
        "shadowrocket_apple_intelligence_profile": "config/shadowrocket-apple-intelligence.conf",
        "shadowrocket_maps_profile": "config/shadowrocket-full.conf",
        "shadowrocket_dns_reference": VAN_DNS_REFERENCE,
        "shadowrocket_rules_inline": True,
        "shadowrocket_tailscale_rules_added": 2,
        "tailscale_cgnat_removed_from_bypass_tun": "100.64.0.0/10",
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

    write_text(
        output / "config/shadowrocket-full.conf",
        shadowrocket_full_profile(source_text),
    )
    write_text(
        output / "config/shadowrocket-apple-intelligence.conf",
        shadowrocket_apple_intelligence_profile(source_text),
    )

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
  <p>上游构建时间：<code>{escaped_build}</code>；代理规则 {len(proxy_rules)} 条，直连规则 {len(direct_rules)} 条；Shadowrocket 配置另含 2 条 Tailscale 规则。</p>
  <h2>Mihomo</h2>
  <ul>
    <li><a href="mihomo/sr_cnip_proxy.yaml">代理规则 provider</a></li>
    <li><a href="mihomo/sr_cnip_direct.yaml">直连规则 provider</a></li>
    <li><a href="config/mihomo-rules.yaml">provider 与路由片段</a></li>
    <li><a href="config/mihomo-dns.yaml">DNS 分流片段</a></li>
  </ul>
  <h2>Shadowrocket</h2>
  <ul>
    <li><a href="config/shadowrocket-full.conf">地图优先配置（保留 Apple 地图的 ls.apple.com 通配直连）</a></li>
    <li><a href="config/shadowrocket-apple-intelligence.conf">Apple Intelligence 代理优先配置</a></li>
    <li><a href="shadowrocket/sr_cnip_proxy.list">代理规则集</a></li>
    <li><a href="shadowrocket/sr_cnip_direct.list">直连规则集</a></li>
  </ul>
  <p>两个 Shadowrocket 配置均内嵌上游规则、使用 AliDNS/Cloudflare DoH 并修复 Tailscale 路由。Apple Intelligence 版本移除了 <code>*.ls.apple.com</code> 绕过并代理地区检测；Apple 地图只保留精确域名直连，导入后请在 iOS/macOS 实测地图表现。</p>
  <p>规则源：<a href="{SOURCE_URL}">Johnshall sr_cnip.conf</a> · DNS参考：<a href="{VAN_DNS_REFERENCE}">Van426326 sr_cnip.conf</a></p>
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
