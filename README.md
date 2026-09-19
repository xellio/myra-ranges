# myra-ranges

Keeps an nginx allow-list in sync with the **Myra CDN IP ranges**, so the
origin server only accepts requests from Myra (and the LAN). Uses
[myrasec-go](https://github.com/Myra-Security-GmbH/myrasec-go) to read the
ranges from the Myra API.

What it does on every run:

1. `ListIPRanges` (all pages), keep only *enabled* ranges that are valid now,
   normalize + dedupe + sort (IPv4 first).
2. Render `snippets/myra-only.conf`: `extra_allow` entries from the config
   (localhost, LAN), one `allow <cidr>;` per Myra range, `deny all;`.
3. Compare with the file on disk (effective allow/deny lines only, comments
   ignored). Unchanged → exit `0`.
4. Changed → keep the old file as `<snippet>.prev`, write the new one, run
   `nginx -t`; on failure restore the old file and exit `1`; on success
   `systemctl reload nginx` and exit `3`.

Safety: refuses to deploy fewer than `min_ranges` ranges (a broken API answer
must never lock the CDN out).

## Build

```sh
make            # ./bin/myra-ranges for the local platform
make linux-arm64
```

## Configure

```sh
cp config.example.yml config.yml && chmod 600 config.yml   # then fill in apikey+secret or token
```

## Run

```sh
./bin/myra-ranges -c config.yml --print      # list the current Myra ranges, nothing else
./bin/myra-ranges -c config.yml --dry-run    # show what would change
sudo ./bin/myra-ranges -c config.yml         # apply (needs root for /etc/nginx + reload)
sudo ./bin/myra-ranges -c config.yml --force # rewrite + test + reload even if unchanged (replace a hand-written file)
```

Comparison is canonical: `allow 1.2.3.4/32;` and `allow 1.2.3.4;` are the same
rule, comments and order are ignored — so a hand-written snippet with the same
rules reads as "unchanged".

Exit codes: `0` unchanged · `3` changed (applied, or would be in dry-run) · `1` error.

## Deployment in the homelab

Lives on **server (.111)** in `~/Projects/myra-ranges` (source + `bin/` +
`config.yml`, like `myra-dyn`). Triggered daily at 03:00 by the **hermes
agent** (no-agent cron job `Myra IP Ranges` → `myra-ranges-refresh.sh` over
SSH, result to Telegram) and on demand. The rendered snippet is included by
every public vhost — see `hosts/server/nginx/README.md` in the home-setup
repo. When the ranges change, update `network/myra-ip-ranges.md` and
`hosts/server/nginx/snippets/myra-only.conf` there (the Telegram message
carries the diff).
