# myra-ranges

Keeps an nginx allow-list in sync with the **Myra Security CDN IP ranges**,
so your origin server only accepts requests that actually come through Myra
(plus whatever you add yourself, e.g. localhost or your LAN). Anyone hitting
the origin IP directly with a forged `Host` header gets a 403 instead of a
free pass around the CDN/WAF.

Uses [myrasec-go](https://github.com/Myra-Security-GmbH/myrasec-go) to read
the ranges from the Myra API.

## How it works

Every run:

1. `ListIPRanges` (all pages); keep only ranges that are *enabled* and valid
   right now; normalize, dedupe, sort (IPv4 first).
2. Render the snippet: `extra_allow` entries from the config, one
   `allow <cidr>;` per Myra range, `deny all;`.
3. Compare with the file on disk. The comparison is canonical - only the
   effective `allow`/`deny` rules count, comments and order are ignored,
   and `1.2.3.4/32` equals `1.2.3.4`. Unchanged -> exit `0`, nothing touched.
4. Changed -> keep the old file as `<snippet>.prev`, write the new one, run
   `nginx -t`. Test fails -> restore the old file, exit `1`. Test passes ->
   `systemctl reload nginx`, exit `3`.

Safety net: it refuses to deploy fewer than `min_ranges` ranges, so a broken
or empty API answer can never lock the CDN out of your origin.

## Install

```sh
git clone https://github.com/xellio/myra-ranges && cd myra-ranges
make                 # ./bin/myra-ranges for the local platform
make linux-arm64     # cross-compile (e.g. for a Raspberry Pi)
cp config.example.yml config.yml && chmod 600 config.yml
```

Fill in `apikey` + `secret` (or `token`) from the Myra app. The other keys:

| key | default | meaning |
|-----|---------|---------|
| `snippet` | `/etc/nginx/snippets/myra-only.conf` | file to render |
| `nginx_test` | `nginx -t` | run after writing; failure = rollback |
| `nginx_reload` | `systemctl reload nginx` | run after a successful test |
| `extra_allow` | `[]` | CIDRs/IPs always allowed in addition to Myra (localhost, LAN, monitoring) |
| `min_ranges` | `8` | refuse to deploy fewer Myra ranges than this |

Include the snippet in every public `server {}` block:

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    include snippets/myra-only.conf;
    ...
}
```

Note: `return` directives (redirects, `return 404`) run *before* nginx's
access phase, so a block that only redirects will still answer outsiders
with the redirect - nothing behind it is reachable, but don't be surprised.

## Run

```sh
./bin/myra-ranges -c config.yml --print      # list the current Myra ranges, nothing else
./bin/myra-ranges -c config.yml --dry-run    # show what would change
sudo ./bin/myra-ranges -c config.yml         # apply (root: writes /etc/nginx, reloads)
sudo ./bin/myra-ranges -c config.yml --force # rewrite + test + reload even if unchanged
```

Exit codes: `0` unchanged, `3` changed (applied or would be in dry-run), `1` error.

Run it from cron (or whatever scheduler you have) once a day; the exit code
tells a wrapper whether to notify. Keep a copy of the rendered snippet in
your infrastructure repo - the file on the server is generated and will be
overwritten.

## Development

```sh
make test
```

## License

MIT
