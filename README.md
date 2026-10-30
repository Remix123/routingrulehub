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

The full Shadowrocket profile is built from Johnshall's complete `sr_cnip.conf`: it preserves the original General options (including `skip-proxy` and `bypass-tun`) and keeps all routing rules inline. It does not use GitHub Pages rule links. DNS uses Van426326's split and the AliDNS/Cloudflare endpoints from Rabbit-DoH.yaml. For Tailscale, the generator removes only `100.64.0.0/10` from `bypass-tun` and places MagicDNS plus Tailscale-CGNAT rules before the upstream rules. This addresses [Johnshall issue #566](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/566#issuecomment-5639067960), where the bypass route conflicts with Tailscale's route.

Enable the Tailscale module in Shadowrocket Settings for the `TAILSCALE` policy to work. The module is available from Shadowrocket 2.2.89; by default it handles tailnet traffic and does not use an exit node. If you need advertised subnet routes, enable “Use Tailscale Subnet”; if such a subnet overlaps one of the remaining `bypass-tun` private ranges, remove only the overlapping subnet from `bypass-tun`. The module behavior and route examples are described in the [Shadowrocket Tailscale manual](https://github.com/LOWERTOP/Shadowrocket/wiki).

Import the profile from Shadowrocket's Config page and keep/add your proxy nodes separately.

The standalone `.list` files are optional for clients that support remote rule sets. The complete Shadowrocket profile embeds the full upstream `[Rule]` section and does not depend on Pages rule links.

## Upstream and schedule

The full Shadowrocket profile and routing rules are fetched from [Johnshall's `sr_cnip.conf`](https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf). Generation replaces its DNS fields using [Van426326's `sr_cnip.conf`](https://raw.githubusercontent.com/Van426326/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf) and the AliDNS/Cloudflare resolver split in `Rabbit-DoH.yaml`, removes the Tailscale CGNAT range from `bypass-tun`, and adds two Tailscale route policies. GitHub Actions fetches Johnshall's profile every day at 10:30 China Standard Time and publishes the generated artifacts to Pages.

## Source attribution and license

The routing data is derived from Johnshall/Shadowrocket-ADBlock-Rules-Forever and retains its [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) attribution and share-alike terms. See the upstream [repository](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) and `public/metadata.json` for the source build time and SHA-256 digest.
