# myra-ranges

[![CI](https://github.com/xellio/myra-ranges/actions/workflows/ci.yml/badge.svg)](https://github.com/xellio/myra-ranges/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/xellio/myra-ranges.svg)](https://pkg.go.dev/github.com/xellio/myra-ranges)
[![Go Report Card](https://goreportcard.com/badge/github.com/xellio/myra-ranges)](https://goreportcard.com/report/github.com/xellio/myra-ranges)
[![Go Version](https://img.shields.io/github/go-mod/go-version/xellio/myra-ranges)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

myra-ranges keeps an IP address allow-list for your web server in sync with
the **Myra Security CDN IP ranges**, so your origin only accepts requests that
actually come through Myra (plus whatever you add yourself, e.g. localhost or
your LAN). Anyone hitting the origin IP directly with a forged `Host` header
is turned away instead of getting a free pass around the CDN/WAF.

Currently implemented servers:

| `server` | rendered file | default path |
|----------|---------------|--------------|
| `nginx` | snippet with `allow <cidr>;` lines and a final `deny all;` | `/etc/nginx/snippets/myra-only.conf` |
| `haproxy` | ACL pattern file, one `<cidr>` per line | `/etc/haproxy/myra-only.lst` |

Uses [myrasec-go](https://github.com/Myra-Security-GmbH/myrasec-go) to read
the ranges from the Myra API.

## How it works

Every run:

1. `ListIPRanges` (all pages); keep only ranges that are *enabled* and valid
   right now; normalize, dedupe, sort (IPv4 first).
2. Render the allow-list (the `extra_allow` entries from the config plus the
   Myra ranges) in the format of the configured server.
3. Compare with the file on disk. The comparison is canonical - only the
   effective rules count, comments and order are ignored, and `1.2.3.4/32`
   equals `1.2.3.4`. Unchanged -> exit `0`, nothing touched.
4. Changed -> keep the old file as `<output>.prev`, write the new one, run
   the server's config test. Test fails -> restore the old file, exit `1`.
   Test passes -> reload the server, exit `3`.

Safety net: it refuses to deploy fewer than `min_ranges` ranges, so a broken
or empty API answer can never lock the CDN out of your origin.

## Install

```sh
git clone https://github.com/xellio/myra-ranges && cd myra-ranges
make                 # ./bin/myra-ranges for the local platform
make linux-arm64     # cross-compile (e.g. for a Raspberry Pi)
cp config.example.yml config.yml && chmod 600 config.yml
```

Fill in `apikey` + `secret` (or `token`) from the Myra app and pick your
`server`. The other keys:

| key | default | meaning |
|-----|---------|---------|
| `server` | `nginx` | server type, see the table above |
| `output` | per server, see above | file to render |
| `test` | nginx: `nginx -t`, haproxy: `haproxy -c -f /etc/haproxy/haproxy.cfg` | run after writing; failure = rollback |
| `reload` | `systemctl reload <server>` | run after a successful test |
| `extra_allow` | `[]` | CIDRs/IPs always allowed in addition to Myra (localhost, LAN, monitoring) |
| `min_ranges` | `8` | refuse to deploy fewer Myra ranges than this |
| `log_level` | `info` | `debug`, `info` or `warning`, see below |

`test` and `reload` are split on whitespace and run directly (no shell, no
quoting). Wrap anything fancier in a small script and point the option at it.

`log_level`:

| level | shows |
|-------|-------|
| `debug` | everything from `info`, plus each test/reload command and its output |
| `info` | status, diff, warnings and errors; test/reload output only when a command fails |
| `warning` | only warnings and errors - quiet mode for cron |

## Server setup

The rendered file alone does nothing - hook it into your server config once.

### nginx

Include the snippet in every public `server {}` block:

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    include snippets/myra-only.conf;
    ...
}
```

Outsiders get a `403`. Note: `return` directives (redirects, `return 404`)
run *before* nginx's access phase, so a block that only redirects will still
answer outsiders with the redirect - nothing behind it is reachable, but
don't be surprised.

### HAProxy

Load the pattern file into an ACL in every public frontend:

```haproxy
frontend https
    bind :443 ssl crt /etc/haproxy/certs/
    acl from_myra src -f /etc/haproxy/myra-only.lst
    tcp-request connection reject unless from_myra
    ...
```

`tcp-request connection reject` drops outsiders before the TLS handshake. If
you prefer a proper `403` answer, use
`http-request deny deny_status 403 unless from_myra` instead. Run
myra-ranges once before adding the ACL - HAProxy refuses to start if the
pattern file does not exist.

## Run

```sh
./bin/myra-ranges -c config.yml --print      # list the current Myra ranges, nothing else
./bin/myra-ranges -c config.yml --dry-run    # show what would change
sudo ./bin/myra-ranges -c config.yml         # apply (root: writes the file, reloads)
sudo ./bin/myra-ranges -c config.yml --force # rewrite + test + reload even if unchanged
```

Exit codes: `0` unchanged, `3` changed (applied or would be in dry-run), `1` error.

Run it from cron (or whatever scheduler you have) once a day; the exit code
tells a wrapper whether to notify. Keep a copy of the rendered file in your
infrastructure repo - the file on the server is generated and will be
overwritten.

## Development

```sh
make test
```

Adding a server type means adding an entry to `serverTypes` in `main.go`
(defaults plus how a line of the file is rendered). If the file format is
new, also teach `canonicalRule` to read it back, so unchanged lists are
detected.

## License

MIT
