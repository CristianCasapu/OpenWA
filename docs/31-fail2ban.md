# 31 — Intrusion Prevention (fail2ban)

OpenWA can ban IP addresses that repeatedly send a **wrong API key** or a **malformed/unauthorized
request**, dropping their traffic for 24 hours by default. Because the OpenWA container is
**unprivileged** — `cap_drop: ALL`, no `NET_ADMIN`, no host network, Docker reachable only through a
read-only socket-proxy — it **cannot run fail2ban or touch the host firewall itself**. So the work is
split:

- **OpenWA (in the container)** writes a dedicated, format-stable **security log** and **generates the
  fail2ban filter + jail** from the settings on _Dashboard → Infrastructure → Intrusion Prevention_.
- **fail2ban (on the host)** tails that log and enforces the bans.

This is a deliberate trust boundary: the app produces config and log lines; the host, which actually
owns the firewall, is the thing that bans. The app never gains firewall access.

## What OpenWA writes

All paths are under the mounted data volume (`/app/data` in the container, e.g. `./data` on the host).

| Path                                 | Written by | Contents                                                            |
| ------------------------------------ | ---------- | ------------------------------------------------------------------- |
| `data/logs/openwa-security.log`      | app        | One line per blocked event: timestamp, reason, surface, client IP.  |
| `data/fail2ban/filter.d/openwa.conf` | app        | The fail2ban **filter** (`failregex`) matching those lines.         |
| `data/fail2ban/jail.d/openwa.local`  | app        | The fail2ban **jail** (`enabled`, thresholds, `logpath`, DROP ban). |
| `data/fail2ban/status.json`          | **host**   | Optional. Ban counts the dashboard reads back (see below).          |

A security log line looks exactly like this (no secrets, no request body, no path — only an IP and a
coarse reason):

```
2026-08-10T12:34:56.789Z OPENWA-SECURITY v=1 event=block reason=wrong_api_key surface=rest ip=203.0.113.9
```

`reason` is `wrong_api_key` (a rejected/absent API key) or `invalid_request` (a 400/401/403/404 HTTP
response, or an invalid WebSocket/MCP frame). `surface` is `rest`, `ws`, or `mcp`. Rate-limit 429s are
**not** logged — rate limiting is a separate control.

The filter and jail are regenerated **at every boot** and **after every Infrastructure save**, so they
always exist and always match the current settings. The `failregex` is generated from the very same
code that emits the log line, and a test asserts the two still match — so a format change cannot
silently disable banning.

## One-time host setup

fail2ban must be installed and running **on the host** (not in the OpenWA container), and told to
include OpenWA's generated files. Replace `<DATA>` with the absolute path of the OpenWA data volume on
the host (e.g. `/srv/openwa/data`, or the Docker volume mountpoint).

```bash
# 1. Install fail2ban (Debian/Ubuntu shown)
sudo apt-get update && sudo apt-get install -y fail2ban

# 2. Symlink OpenWA's generated filter + jail into fail2ban's config dirs
sudo ln -sf <DATA>/fail2ban/filter.d/openwa.conf /etc/fail2ban/filter.d/openwa.conf
sudo ln -sf <DATA>/fail2ban/jail.d/openwa.local  /etc/fail2ban/jail.d/openwa.local

# 3. Reload fail2ban to pick them up
sudo systemctl reload fail2ban

# 4. Confirm the jail is active
sudo fail2ban-client status openwa
```

The symlinks mean you set this up once: every later change you make in the dashboard rewrites the
linked files in place, and fail2ban re-reads them on its next reload (or immediately for values it
polls). Then enable the jail from _Dashboard → Infrastructure → Intrusion Prevention_ and click
**Save**.

> **Docker note.** fail2ban runs on the **host**, not as a compose service, because it needs the host
> firewall and network namespace. Point `<DATA>` at the host-side path of the `openwa-data` volume
> (`docker volume inspect openwa_openwa-data` shows the mountpoint), or use a host bind-mount for
> `./data` so the path is stable.

## The DROP ban action

The generated jail uses:

```ini
banaction = iptables-allports[blocktype=DROP]
```

`DROP` (silently discard the packets), not `REJECT` (actively refuse) — a probing client learns
nothing and simply times out. `allports` covers every port the host exposes for OpenWA.

### nftables hosts

On a host using nftables instead of legacy iptables, edit the linked jail (or set it globally in
`/etc/fail2ban/jail.local`) to:

```ini
banaction = nftables-allports[blocktype=drop]
```

`blocktype` values follow the action's own convention (`DROP` for the iptables action, `drop` for
nftables).

## Tuning (from the dashboard)

| Setting     | Env key             | Default        | Meaning                                         |
| ----------- | ------------------- | -------------- | ----------------------------------------------- |
| Enable      | `FAIL2BAN_ENABLED`  | `false`        | Generate the jail as `enabled`.                 |
| Max retries | `FAIL2BAN_MAXRETRY` | `5`            | Failures within the window before a ban.        |
| Find time   | `FAIL2BAN_FINDTIME` | `600` (10 min) | Sliding window over which failures are counted. |
| Ban time    | `FAIL2BAN_BANTIME`  | `86400` (24 h) | How long a banned IP is dropped.                |

These are dashboard-managed (saved to `data/.env.generated`) and can also be pinned from the
environment (`.env` / container env) like every other infra key. A pinned value wins and the dashboard
control then shows it as managed by the environment.

## Log rotation

OpenWA rotates its own security log in-process: at `FAIL2BAN_LOG_MAX_BYTES` (default 10 MB) the current
file is renamed to `openwa-security.log.1` and a fresh file started (depth 1). If you prefer host-side
rotation, add a `logrotate` stanza and drop the in-app cap higher — just keep fail2ban pointed at the
live `openwa-security.log`.

## Optional: surface ban counts in the dashboard

The dashboard's Intrusion Prevention card can show how many IPs are currently banned. OpenWA cannot run
`fail2ban-client` (it is unprivileged), so a **host** action writes `data/fail2ban/status.json` and the
app reads it (degrading to "no host status yet" when it is absent). A simple cron on the host:

```bash
# /etc/cron.d/openwa-fail2ban-status — every minute, write the count OpenWA reads back.
* * * * * root banned=$(fail2ban-client status openwa | sed -n 's/.*Currently banned:\s*//p'); \
  printf '{"enabled":true,"bannedCount":%s,"updatedAt":"%s"}\n' "${banned:-0}" "$(date -Is)" \
  > <DATA>/fail2ban/status.json
```

Include a `bannedIps` array if you want the list rendered too:
`{"enabled":true,"bannedCount":2,"bannedIps":["203.0.113.9","198.51.100.7"],"updatedAt":"…"}`.

## Trust boundary summary

- The app writes **config and logs onto the shared volume**. It has no way to add a firewall rule.
- The host owns **fail2ban and the firewall**. It reads the app's files and enforces bans.
- Nothing the app writes can escalate: the filter/jail are plain text the host operator reviewed once
  when wiring the include, and the log carries only an IP and a coarse reason — never a key, secret, or
  request body.
