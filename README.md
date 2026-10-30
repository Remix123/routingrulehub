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

- [Maps-priority full profile](https://remix123.github.io/mihomo-cnip-doh-rules/config/shadowrocket-full.conf)
- [Apple Intelligence proxy-priority full profile](https://remix123.github.io/mihomo-cnip-doh-rules/config/shadowrocket-apple-intelligence.conf)
- [Proxy rule set](https://remix123.github.io/mihomo-cnip-doh-rules/shadowrocket/sr_cnip_proxy.list)
- [Direct rule set](https://remix123.github.io/mihomo-cnip-doh-rules/shadowrocket/sr_cnip_direct.list)

Both full Shadowrocket profiles are built from Johnshall's complete `sr_cnip.conf`, keep routing rules inline, and include the Tailscale routing fix. They do not depend on GitHub Pages rule links. The Maps-priority profile retains its existing DNS settings. The Apple Intelligence profile is being tested with direct Cloudflare and AliDNS DoH3 resolvers, queried in parallel, and conventional HTTPS DoH fallback with HTTP/3 disabled (`#no-h3`). Because the main resolvers run in parallel, either provider can supply the address used by IP/GEOIP rules; check Shadowrocket's connection log if a domestic CDN is still routed through the proxy.

Use the **Maps-priority** profile to preserve the upstream `*.ls.apple.com` `skip-proxy` behavior that was reported to make Apple Maps load domestic Amap data on iOS and macOS ([issue #343](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/343)). This also sends Apple's `gspe1-ssl.ls.apple.com` region check directly, so Apple Intelligence may detect the local network region ([issue #601](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/601)).

Use the **Apple Intelligence proxy-priority** profile to remove that wildcard bypass and explicitly route `gspe1-ssl.ls.apple.com` through `Proxy`. It keeps only `gspe19-cn-ssl.ls.apple.com` as an exact direct Maps rule. The upstream reports that a broader bypass was needed for Mac Maps, so verify Apple Maps on iOS and macOS after importing this profile. These two complete profiles are alternatives; the standalone `.list` files remain upstream routing data and do not contain the profile-specific Apple overrides.

The generator also removes only `100.64.0.0/10` from `bypass-tun` and places MagicDNS plus Tailscale-CGNAT rules before upstream rules. This addresses [Johnshall issue #566](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/566#issuecomment-5639067960), where the bypass route conflicts with Tailscale's route.

Enable the Tailscale module in Shadowrocket Settings for the `TAILSCALE` policy to work. The module is available from Shadowrocket 2.2.89; by default it handles tailnet traffic and does not use an exit node. If you need advertised subnet routes, enable “Use Tailscale Subnet”; if such a subnet overlaps one of the remaining `bypass-tun` private ranges, remove only the overlapping subnet from `bypass-tun`. The module behavior and route examples are described in the [Shadowrocket Tailscale manual](https://github.com/LOWERTOP/Shadowrocket/wiki).

Import the profile from Shadowrocket's Config page and keep/add your proxy nodes separately.

The standalone `.list` files are optional for clients that support remote rule sets. The complete Shadowrocket profile embeds the full upstream `[Rule]` section and does not depend on Pages rule links.

## Upstream and schedule

The full Shadowrocket profile and routing rules are fetched from [Johnshall's `sr_cnip.conf`](https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf). Generation replaces its DNS fields using [Van426326's `sr_cnip.conf`](https://raw.githubusercontent.com/Van426326/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf) and the AliDNS/Cloudflare resolver split in `Rabbit-DoH.yaml`, removes the Tailscale CGNAT range from `bypass-tun`, and adds two Tailscale route policies. GitHub Actions fetches Johnshall's profile every day at 10:30 China Standard Time and publishes the generated artifacts to Pages.

## Source attribution and license

The routing data is derived from Johnshall/Shadowrocket-ADBlock-Rules-Forever and retains its [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) attribution and share-alike terms. See the upstream [repository](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) and `public/metadata.json` for the source build time and SHA-256 digest.
