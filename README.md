# byteonabeach MultiCIDR Shield

A Zoraxy router plugin for blocking incoming connections from multiple user-managed IP/CIDR blocklists.

This version was inspired by the original Data-Shield blocklist plugin by [@yax](https://github.com/kianby/zoraxy-datashield-blocklist) and keeps the same general idea, but adds multi-source management, per-source stats, and a richer admin UI.

## What it does

- Accepts any number of blocklist source URLs in the Zoraxy plugin panel
- Supports raw GitHub URLs, GitHub `blob` URLs, and plain text list endpoints
- Parses single IPs and CIDRs
- Merges all enabled sources into one in-memory blocker
- Tracks stats per source: loaded entries, hits, refresh time, and last error
- Stores your source list on disk so it survives restarts
- Skips private, loopback, link-local, multicast, and unspecified addresses automatically

## Build

```bash
go build -o byteonabeach-multicidr-shield .
```

If your Go toolchain tries to download a newer version, build with the installed toolchain explicitly:

```bash
GOTOOLCHAIN=local go build -o byteonabeach-multicidr-shield .
```

## Install

Copy the built binary into a dedicated plugin directory in Zoraxy, for example:

```bash
cp byteonabeach-multicidr-shield /path/to/zoraxy/plugins/byteonabeach-multicidr-shield/
```

Then restart Zoraxy.

## UI features

The plugin page now includes:

- Global summary cards
- Per-source loaded/unique/hit counters
- Pause/resume per source
- Refresh per source or refresh all sources
- Remove source
- Reset runtime hit counters
- Config file path display for easier troubleshooting

## Notes

- Overlapping sources are allowed. If the same IP/CIDR appears in multiple enabled sources, more than one source may receive a hit.
- Runtime hit counters reset when you click reset or restart the plugin.
- The default source is the original Data-Shield critical IPv4 list, so the plugin works immediately after install.

## License

See [LICENSE](LICENSE).
