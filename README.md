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

- [Complete DNS and routing profile](https://remix123.github.io/mihomo-cnip-doh-rules/config/shadowrocket-full.conf)
- [Proxy rule set](https://remix123.github.io/mihomo-cnip-doh-rules/shadowrocket/sr_cnip_proxy.list)
- [Direct rule set](https://remix123.github.io/mihomo-cnip-doh-rules/shadowrocket/sr_cnip_direct.list)

The full Shadowrocket profile is built from Johnshall's complete `sr_cnip.conf`: it preserves the original General options (including `skip-proxy` and `bypass-tun`) and keeps all routing rules inline. It does not use GitHub Pages rule links. Only DNS-related fields are replaced, using [Van426326's DNS strategy](https://raw.githubusercontent.com/Van426326/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf) and the AliDNS/Cloudflare endpoints from Rabbit-DoH.yaml: Cloudflare DoH through the selected proxy for general/proxy DNS; AliDNS DoH direct for direct rules and proxy-node bootstrap; Cloudflare DoH through the proxy as fallback; system DNS disabled; hard-coded Google/Cloudflare DNS hijacked; IPv6 disabled. Import it from Shadowrocket's Config page and keep/add your proxy nodes separately.

The standalone `.list` files are optional for clients that support remote rule sets. The complete Shadowrocket profile embeds the full upstream `[Rule]` section and does not depend on Pages rule links.

## Upstream and schedule

The full Shadowrocket profile and routing rules are fetched from [Johnshall's `sr_cnip.conf`](https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf). Its DNS fields are replaced during generation using [Van426326's `sr_cnip.conf`](https://raw.githubusercontent.com/Van426326/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf) and the AliDNS/Cloudflare resolver split in your `Rabbit-DoH.yaml`. GitHub Actions fetches Johnshall's profile every day at 10:30 China Standard Time and publishes the generated artifacts to Pages.

## Source attribution and license

The routing data is derived from Johnshall/Shadowrocket-ADBlock-Rules-Forever and retains its [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) attribution and share-alike terms. See the upstream [repository](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) and `public/metadata.json` for the source build time and SHA-256 digest.
