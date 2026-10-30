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

The Maps-priority profile is built from Johnshall's complete `sr_cnip.conf`. The Apple Intelligence profile uses the `[Rule]` snapshot from [`sources/apple-rules.conf`](sources/apple-rules.conf), preserving its inline rules and 11 remote `RULE-SET` references, and both profiles include the Tailscale routing fix. Neither profile depends on GitHub Pages rule links.

The Apple Intelligence profile applies domain rules first. `DIRECT` domain rules use AliDNS DoH3. `PROXY` domain rules are resolved by the selected proxy route. A domain that reaches IP/GEOIP classification without an earlier domain match uses Cloudflare DoH3 (`dns-server`) to obtain an address, then the IP rules choose `DIRECT` or `PROXY`. If DoH3 fails, the profile has conventional HTTPS DoH fallback with HTTP/3 disabled (`#no-h3`). `proxy-dns-server` is for resolving proxy-node hostnames. IP/GEOIP decisions can still vary with CDN answers and Shadowrocket's GeoIP database; check the connection log if a destination takes an unexpected route.

Use the **Maps-priority** profile to preserve the upstream `*.ls.apple.com` `skip-proxy` behavior that was reported to make Apple Maps load domestic Amap data on iOS and macOS ([issue #343](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/343)). This also sends Apple's `gspe1-ssl.ls.apple.com` region check directly, so Apple Intelligence may detect the local network region ([issue #601](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/601)).

Use the **Apple Intelligence proxy-priority** profile to remove that wildcard bypass and explicitly route `gspe1-ssl.ls.apple.com` through `Proxy`. It keeps only `gspe19-cn-ssl.ls.apple.com` as an exact direct Maps rule. The upstream reports that a broader bypass was needed for Mac Maps, so verify Apple Maps on iOS and macOS after importing this profile. These two complete profiles are alternatives; the standalone `.list` files remain upstream routing data and do not contain the profile-specific Apple overrides.

The generator also removes only `100.64.0.0/10` from `bypass-tun` and places MagicDNS plus Tailscale-CGNAT rules before upstream rules. This addresses [Johnshall issue #566](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/issues/566#issuecomment-5639067960), where the bypass route conflicts with Tailscale's route.

Enable the Tailscale module in Shadowrocket Settings for the `TAILSCALE` policy to work. The module is available from Shadowrocket 2.2.89; by default it handles tailnet traffic and does not use an exit node. If you need advertised subnet routes, enable “Use Tailscale Subnet”; if such a subnet overlaps one of the remaining `bypass-tun` private ranges, remove only the overlapping subnet from `bypass-tun`. The module behavior and route examples are described in the [Shadowrocket Tailscale manual](https://github.com/LOWERTOP/Shadowrocket/wiki).

Import the profile from Shadowrocket's Config page and keep/add your proxy nodes separately.

The standalone `.list` files are optional for clients that support remote rule sets. The complete Shadowrocket profile embeds the full upstream `[Rule]` section and does not depend on Pages rule links.

## Upstream and schedule

The Maps-priority profile and Mihomo rules are generated from [Johnshall's `sr_cnip.conf`](https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_cnip.conf). The Apple Intelligence profile takes its embedded and remote rules from the checked-in Apple.conf snapshot; the remote lists are fetched by Shadowrocket using the URLs in the configuration. Generation applies the AliDNS/Cloudflare DNS split, removes the Tailscale CGNAT range from `bypass-tun`, and adds two Tailscale route policies. GitHub Actions refreshes Johnshall-derived artifacts every day at 10:30 China Standard Time and publishes the complete `public/` directory to Pages. The Apple.conf inline snapshot changes when this repository's source file is updated; its remote `RULE-SET` lists remain independently updateable at their source URLs.

## Source attribution and license

Johnshall-derived routing data retains its [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) attribution and share-alike terms. The Apple.conf snapshot and its remote rule lists follow the terms of their respective sources. See the upstream [Johnshall repository](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever), the source URLs in [`sources/apple-rules.conf`](sources/apple-rules.conf), and `public/metadata.json` for source details and digests.
