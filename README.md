# Johnshall CNIP rules for Mihomo and Shadowrocket

This repository follows Johnshall's `sr_cnip.conf` and republishes its routing rules in client-referenceable formats. The generated files contain no proxy credentials.

## Published files

### Mihomo

- [Proxy rules provider](https://remix123.github.io/mihomo-cnip-doh-rules/mihomo/sr_cnip_proxy.yaml)
- [Direct rules provider](https://remix123.github.io/mihomo-cnip-doh-rules/mihomo/sr_cnip_direct.yaml)
- [Rule-provider and rules snippet](https://remix123.github.io/mihomo-cnip-doh-rules/config/mihomo-rules.yaml)
- [DNS snippet](https://remix123.github.io/mihomo-cnip-doh-rules/config/mihomo-dns.yaml)

Add the provider entries to the existing `rule-providers:` section. Put the generated `RULE-SET` entries after app-specific rules and before broader China/GEOIP rules. Keep a single final `MATCH,Proxy`. If the current config already has `GEOIP,CN,DIRECT`, replace it with the generated direct provider entry to avoid duplicate classification.

The DNS snippet follows the split previously selected for Mihomo: `geosite:cn` and proxy-node hostnames use Ali DoH directly; other DNS queries use Cloudflare DoH through the existing `Proxy` group. Merge these keys into the existing `dns:` mapping and retain its current fake-IP settings. The `geosite:cn` policy requires the Mihomo geosite data to be available.

### Shadowrocket

- [Proxy rule set](https://remix123.github.io/mihomo-cnip-doh-rules/shadowrocket/sr_cnip_proxy.list)
- [Direct rule set](https://remix123.github.io/mihomo-cnip-doh-rules/shadowrocket/sr_cnip_direct.list)
- [Shadowrocket rule snippet](https://remix123.github.io/mihomo-cnip-doh-rules/config/shadowrocket-rules.conf)

Add the two `RULE-SET` entries to the active Shadowrocket `[Rule]` section. Keep them after app-specific rules and before a general China/GEOIP rule or `FINAL,PROXY`. These files contain matching rules only; the DNS settings remain in the Shadowrocket profile's `[General]` section.

## Upstream and schedule

The source is [Johnshall's `sr_cnip.conf`](https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf). GitHub Actions fetches it every day at 10:30 China Standard Time, after Johnshall's scheduled 07:00 China Standard Time build, and can also be run manually from the Actions page. Generated files and metadata are committed only when their contents change, then deployed to GitHub Pages.

## Source attribution and license

The routing data is derived from Johnshall/Shadowrocket-ADBlock-Rules-Forever and retains its [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) attribution and share-alike terms. See the upstream [repository](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) and `public/metadata.json` for the source build time and SHA-256 digest.
