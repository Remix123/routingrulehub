#!/usr/bin/env python3
"""Build a Shadowrocket RULE-SET for messaging apps and international AI tools."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES_BASE = "https://remix123.github.io/routingrulehub"
V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"
TANNAYE_AI_URL = (
    "https://raw.githubusercontent.com/TannayeJ/ai-vendor-rules/"
    "main/generated/quantumultx/all-ai-global.list"
)
TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"


class RuleSourceError(RuntimeError):
    pass


def fetch_text(url: str) -> str:
    try:
        response = subprocess.run(
            [
                "curl", "--fail", "--location", "--silent", "--show-error",
                "--retry", "3", "--max-time", "60", url,
            ],
            check=True,
            capture_output=True,
            timeout=90,
        )
        text = response.stdout.decode("utf-8-sig")
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise RuleSourceError(f"Could not fetch {url}: {exc}") from exc
    if not text.strip() or "<!doctype html" in text[:512].lower():
        raise RuleSourceError(f"Empty or HTML response from {url}")
    return text


def domain_rule(kind: str, value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or any(ch.isspace() for ch in value) or "," in value:
        raise RuleSourceError(f"Invalid domain rule value: {value!r}")
    if kind not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        raise RuleSourceError(f"Unsupported domain rule type: {kind}")
    return f"{kind},{value}"


def parse_domain_category(
    category: str,
    seen: set[str] | None = None,
    source_text: str | None = None,
) -> tuple[list[str], list[str]]:
    """Convert a v2fly domain-list-community category to Shadowrocket rules."""
    seen = seen or set()
    if category in seen:
        return [], []
    seen.add(category)
    url = f"{V2FLY_BASE}/{category}"
    text = source_text if source_text is not None else fetch_text(url)
    rules: list[str] = []
    unsupported: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        token = parts[0]
        if token.startswith("include:"):
            included, skipped = parse_domain_category(token.removeprefix("include:"), seen)
            rules.extend(included)
            unsupported.extend(skipped)
        elif token.startswith("full:"):
            rules.append(domain_rule("DOMAIN", token.removeprefix("full:")))
        elif token.startswith("domain:"):
            rules.append(domain_rule("DOMAIN-SUFFIX", token.removeprefix("domain:")))
        elif token.startswith("regexp:"):
            unsupported.append(f"{category}: {token} (Shadowrocket has no equivalent domain-regex rule)")
        elif ":" in token:
            unsupported.append(f"{category}: {token} (unknown upstream selector)")
        else:
            rules.append(domain_rule("DOMAIN-SUFFIX", token))
    return rules, unsupported


def wildcard_keyword(pattern: str) -> str:
    chunks = [chunk for chunk in pattern.lower().split("*") if chunk]
    if not chunks:
        raise RuleSourceError(f"Cannot safely approximate wildcard: {pattern}")
    keyword = max(chunks, key=len)
    if len(keyword) < 8:
        raise RuleSourceError(f"Wildcard fragment is too broad to approximate: {pattern}")
    return domain_rule("DOMAIN-KEYWORD", keyword)


def parse_quantumultx_ai(text: str) -> tuple[list[str], list[str]]:
    """Convert generated Quantumult X HOST rules into Shadowrocket rule-set lines."""
    mapping = {
        "HOST": "DOMAIN",
        "HOST-SUFFIX": "DOMAIN-SUFFIX",
        "HOST-KEYWORD": "DOMAIN-KEYWORD",
    }
    rules: list[str] = []
    lossy: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split(",")]
        kind = fields[0].upper()
        if kind in mapping and len(fields) >= 2:
            rules.append(domain_rule(mapping[kind], fields[1]))
        elif kind == "HOST-WILDCARD" and len(fields) >= 2:
            converted = wildcard_keyword(fields[1])
            rules.append(converted)
            lossy.append(f"{line} => {converted} (keyword approximation; see README)")
        else:
            raise RuleSourceError(f"Unsupported Quantumult X rule syntax: {line}")
    return rules, lossy


def parse_telegram_cidrs(text: str) -> list[str]:
    rules: list[str] = []
    for raw_line in text.splitlines():
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        network = ipaddress.ip_network(value, strict=False)
        kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        rules.append(f"{kind},{network.with_prefixlen},no-resolve")
    if not rules:
        raise RuleSourceError("Telegram CIDR feed contained no networks")
    return rules


def normalize_rule(rule: str) -> str:
    fields = [field.strip() for field in rule.split(",")]
    kind = fields[0].upper()
    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        return domain_rule(kind, fields[1])
    if kind in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(fields[1], strict=False)
        expected = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        if kind != expected:
            raise RuleSourceError(f"Address family mismatch in rule: {rule}")
        suffix = ",no-resolve" if any(x.lower() == "no-resolve" for x in fields[2:]) else ""
        return f"{kind},{network.with_prefixlen}{suffix}"
    raise RuleSourceError(f"Unsupported final rule type: {kind}")


def suffix_contains(parent: str, child: str) -> bool:
    return child == parent or child.endswith("." + parent)


def remove_redundant_rules(rules: list[str]) -> tuple[list[str], int, int]:
    """Remove exact duplicates and domain/IP rules covered by broader rules."""
    unique: list[str] = []
    seen: set[str] = set()
    exact_duplicates = 0
    for raw in rules:
        rule = normalize_rule(raw)
        if rule in seen:
            exact_duplicates += 1
            continue
        seen.add(rule)
        unique.append(rule)

    suffixes = [
        fields[1]
        for rule in unique
        if (fields := rule.split(",", 2))[0] == "DOMAIN-SUFFIX"
    ]
    networks: list[tuple[str, ipaddress._BaseNetwork]] = []
    for rule in unique:
        fields = rule.split(",", 3)
        if fields[0] in {"IP-CIDR", "IP-CIDR6"}:
            networks.append((fields[0], ipaddress.ip_network(fields[1], strict=False)))

    reduced: list[str] = []
    redundant = 0
    for rule in unique:
        fields = rule.split(",", 3)
        kind, value = fields[0], fields[1]
        if kind == "DOMAIN":
            if any(suffix_contains(suffix, value) for suffix in suffixes):
                redundant += 1
                continue
        elif kind == "DOMAIN-SUFFIX":
            if any(parent != value and suffix_contains(parent, value) for parent in suffixes):
                redundant += 1
                continue
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(value, strict=False)
            if any(
                other_kind == kind and other != network and network.subnet_of(other)
                for other_kind, other in networks
            ):
                redundant += 1
                continue
        reduced.append(rule)
    return reduced, exact_duplicates, redundant


def generate(output: Path) -> dict[str, object]:
    whatsapp_url = f"{V2FLY_BASE}/whatsapp"
    telegram_url = f"{V2FLY_BASE}/telegram"
    source_texts = {
        "whatsapp": fetch_text(whatsapp_url),
        "telegram": fetch_text(telegram_url),
        "ai_global": fetch_text(TANNAYE_AI_URL),
        "telegram_cidrs": fetch_text(TELEGRAM_CIDR_URL),
    }

    whatsapp_rules, whatsapp_unsupported = parse_domain_category(
        "whatsapp", source_text=source_texts["whatsapp"]
    )
    telegram_rules, telegram_unsupported = parse_domain_category(
        "telegram", source_text=source_texts["telegram"]
    )
    ai_rules, lossy_conversions = parse_quantumultx_ai(source_texts["ai_global"])
    telegram_ip_rules = parse_telegram_cidrs(source_texts["telegram_cidrs"])

    sections = [
        ("WhatsApp", whatsapp_rules),
        ("Telegram", telegram_rules + telegram_ip_rules),
        ("International AI services", ai_rules),
    ]
    flattened = [rule for _, section_rules in sections for rule in section_rules]
    normalized, exact_duplicates, redundant = remove_redundant_rules(flattened)

    lines = [
        "# NAME: Messaging and International AI",
        "# AUTO-GENERATED. Do not edit by hand; run scripts/generate_ai_messaging.py.",
        "# Shadowrocket RULE-SET: match rules only; select the policy in the parent [Rule] entry.",
        "# Codex uses OpenAI/ChatGPT routing domains; no separate Codex domain set is published upstream.",
        "# QX HOST-WILDCARD entries are represented by a narrow DOMAIN-KEYWORD approximation.",
        f"# Sources: v2fly/domain-list-community (MIT), TannayeJ/ai-vendor-rules (MIT), {TELEGRAM_CIDR_URL}",
    ]
    group_by_rule: dict[str, str] = {}
    for title, section_rules in sections:
        for rule in section_rules:
            group_by_rule.setdefault(normalize_rule(rule), title)
    emitted_groups: set[str] = set()
    for rule in normalized:
        group = group_by_rule.get(rule, "Combined")
        if group not in emitted_groups:
            lines.extend(["", f"# {group}"])
            emitted_groups.add(group)
        lines.append(rule)
    output_path = output / "shadowrocket/ai-messaging.list"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    source_urls = {
        "whatsapp_domains": whatsapp_url,
        "telegram_domains": telegram_url,
        "ai_global": TANNAYE_AI_URL,
        "telegram_cidrs": TELEGRAM_CIDR_URL,
    }
    source_sha256 = {
        key: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for key, value in source_texts.items()
    }
    metadata: dict[str, object] = {
        "name": "Messaging and International AI",
        "pages_url": f"{PAGES_BASE}/shadowrocket/ai-messaging.list",
        "rule_count": len(normalized),
        "source_rule_count": len(flattened),
        "exact_duplicates_removed": exact_duplicates,
        "subsumed_rules_removed": redundant,
        "counts": {
            "whatsapp_domain_rules": sum(1 for x in whatsapp_rules),
            "telegram_domain_rules": len(telegram_rules),
            "telegram_ip_rules": len(telegram_ip_rules),
            "international_ai_source_rules": len(ai_rules),
        },
        "sources": source_urls,
        "source_sha256": source_sha256,
        "lossy_conversions": lossy_conversions,
        "unsupported_source_rules": whatsapp_unsupported + telegram_unsupported,
        "notes": [
            "OpenAI/ChatGPT rules can route Codex traffic using shared domains; Codex is not an independent vendor list.",
            "The combined rule set sends all matched services through the single policy selected by the RULE-SET line.",
            "Place the RULE-SET before broader Google, Microsoft, Twitter/X, GEOIP and FINAL rules.",
        ],
        "licenses": {
            "v2fly/domain-list-community": "MIT",
            "TannayeJ/ai-vendor-rules": "MIT; generated domain data is sourced from v2fly/domain-list-community",
            "Telegram CIDRs": "Telegram official machine-readable network list",
        },
    }
    metadata_path = output / "shadowrocket/ai-messaging.metadata.json"
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "public")
    args = parser.parse_args()
    metadata = generate(args.output)
    print(
        f"Generated {metadata['rule_count']} Shadowrocket rules; "
        f"removed {metadata['exact_duplicates_removed']} exact duplicates and "
        f"{metadata['subsumed_rules_removed']} subsumed rules."
    )


if __name__ == "__main__":
    main()
