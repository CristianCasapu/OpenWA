<p align="center">
  <img src="docs/logo/openwa_logo.webp" alt="OpenWA Logo" width="200"/>
</p>

<h1 align="center">OpenWA <sub>· hardened fork</sub></h1>
<p align="center">
  <strong>Self-hosted WhatsApp API Gateway — security-hardened and maintained by Cristian Casapu</strong>
</p>

<p align="center">
  <a href="#-about-this-fork">About this fork</a> •
  <a href="#-what-this-fork-adds">What this fork adds</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#-api-examples">API</a> •
  <a href="#-credits--license">Credits &amp; License</a>
</p>

<p align="center">
  <a href="https://github.com/CristianCasapu/OpenWA/actions/workflows/ci.yml"><img src="https://github.com/CristianCasapu/OpenWA/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"/></a>
  <img src="https://img.shields.io/github/package-json/v/CristianCasapu/OpenWA?label=version&color=blue" alt="Version"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"/>
  <img src="https://img.shields.io/badge/node-22_LTS-brightgreen.svg" alt="Node"/>
  <img src="https://img.shields.io/github/package-json/dependency-version/CristianCasapu/OpenWA/@nestjs/core?label=NestJS&color=red" alt="NestJS"/>
  <img src="https://img.shields.io/badge/docker-ready-blue.svg" alt="Docker"/>
  <img src="https://img.shields.io/github/package-json/dependency-version/CristianCasapu/OpenWA/dev/typescript?label=TypeScript&color=3178C6" alt="TypeScript"/>
</p>

---

## 🔱 About this fork

This repository is a **fork of [`rmyndharis/OpenWA`](https://github.com/rmyndharis/OpenWA)** (© Yudhi Armyndharis and the OpenWA Contributors), maintained by **[Cristian Casapu](https://github.com/CristianCasapu)** under the same MIT license.

The upstream project is a large, AI-assisted codebase. This fork exists to take that starting point and make it **safe to actually self-host**: it adds a coherent security layer, verification gates, and CI automation on top of the original feature set. Treat it as a **work in progress** — a hardening effort rather than a finished, guaranteed-stable product. If you need the canonical upstream, use the [source repository](https://github.com/rmyndharis/OpenWA); if you want the hardening work described below, you're in the right place.

OpenWA itself is a free, open-source WhatsApp API Gateway for developers who want full control over their messaging infrastructure — no vendor lock-in, no hidden paywalls. It is built on a **pluggable architecture**: database engine (SQLite/PostgreSQL), backup/migration storage (Local/S3), and cache layer (disabled/Redis) are all chosen through configuration rather than code changes. Message media is returned inline to API and webhook consumers; it is not automatically persisted to the storage backend.

|                               |                                                                                                         |
| ----------------------------- | ------------------------------------------------------------------------------------------------------- |
| 🔐 **Security-first fork**    | Peppered key hashing, brute-force lockout, fail2ban, dashboard 2FA — see [below](#-what-this-fork-adds) |
| 🔓 **100% Open Source**       | MIT-licensed, no feature locks, full source access                                                      |
| 🏗️ **Pluggable Architecture** | Swap adapters for database, storage, and cache via config                                               |
| 🖥️ **Full Dashboard**         | Modern React UI for session, webhook, and API-key management                                            |
| 🔹 **Multi-Session Ready**    | Run multiple WhatsApp sessions concurrently on one instance                                             |
| 🐳 **Docker Native**          | Production-ready with minimal configuration                                                             |

---

## 🛡️ What this fork adds

The changes below are the reason this fork exists. Each landed as a reviewed, gated change on top of upstream:

| Area                           | Hardening added in this fork                                                                                                                                                                                                                                                 |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **API-key hashing**            | Keys are stored as **HMAC hashes with a server-side pepper** (`API_KEY_PEPPER`), so a leaked database alone cannot be used to recover or replay keys.                                                                                                                        |
| **Brute-force lockout**        | Per-client-IP **auth lockout** (`AUTH_LOCKOUT_*`) rejects a burst of unknown keys with HTTP 429 for a cooldown window; a successful auth clears the counter.                                                                                                                 |
| **fail2ban integration**       | A structured **security event log** (`wrong_api_key` / `invalid_request`) plus **auto-generated fail2ban filter + jail config**, managed from the dashboard, so the host firewall can drop repeat offenders.                                                                 |
| **Dashboard 2FA (TOTP)**       | **Google Authenticator / TOTP** for admin keys. An enrolled key becomes interactive-only: it is refused as a plain bearer credential without a post-TOTP dashboard session token, so a stolen key can't be replayed headless. Includes a host-side `mfa:reset` recovery CLI. |
| **Cloudflare-aware client IP** | `CF_MODE` (`off`/`tunnel`/`proxy`) honors `CF-Connecting-IP` **only from a trusted proxy peer**, so rate-limiting, IP allow-lists, and audit key on the real visitor IP behind Cloudflare instead of the edge.                                                               |
| **CI automation**              | An **auto-PR workflow** opens a draft pull request for every working branch, and the existing CI (lint, full-program type-check, format, OpenAPI snapshot, tests) gates changes.                                                                                             |

See [`SECURITY.md`](./SECURITY.md), [`docs/31-fail2ban.md`](./docs/31-fail2ban.md), and [`docs/32-2fa.md`](./docs/32-2fa.md) for details.

---

## ⚠️ Before you connect a number — please read

OpenWA is an unofficial, community-maintained gateway. It connects to WhatsApp through **reverse-engineered clients** (the [`whatsapp-web.js`](https://github.com/pedroslopez/whatsapp-web.js) project and [`@whiskeysockets/baileys`](https://github.com/WhiskeySockets/Baileys)), **not** through Meta's official Cloud API. This has real consequences you should understand before you link a phone number.

### What this means in practice

- **There is always a non-zero risk of account restriction or ban.** WhatsApp's anti-abuse systems actively look for unofficial automation. No amount of code quality on our side can make that risk zero.
- **Pick the right number.** Never connect your primary personal or business number to an automated gateway. Use a **dedicated number** you can afford to lose. If you're running this for paying clients, pass that guidance on to them.
- **The two engines trade off differently:**

  | Engine            | Ban-risk profile                                                                                        | Resource cost                     |
  | ----------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------- |
  | `whatsapp-web.js` | Lower — drives a real headless Chromium that looks like genuine WhatsApp Web traffic.                   | High RAM (~300–500 MB / session). |
  | `baileys`         | Higher — speaks the multi-device WebSocket protocol directly and is easier for WhatsApp to fingerprint. | Low RAM (~30–80 MB / session).    |

  If account safety is your top priority and you can afford the memory, prefer `whatsapp-web.js`. If you need density and accept the trade-off, use `baileys`.

### Safe-sending guidelines

These are practical guardrails, not guarantees — but they materially reduce the chance of WhatsApp flagging the account:

1. **Warm up fresh numbers.** For the first several days, behave like a normal human user: scan the QR, exchange a handful of messages with saved contacts, join a group or two, set a profile photo. Don't blast on day one.
2. **Don't cold-blast strangers.** Sending the first-ever message to a large batch of numbers that have never messaged you is the single most reliable way to get restricted — on either engine.
3. **Rate-limit yourself.** OpenWA ships with a configurable rate limiter (`RATE_LIMIT_*` env vars). Use it. A few messages per minute per session is sustainable; "thousands in an hour" is not.
4. **Use opted-in recipients.** The safest workloads are replies and alerts to people who already expect to hear from you (OTP to your own users, order updates, support replies).
5. **Keep a fallback.** For anything auth-critical or revenue-critical, keep an SMS / email / official-Cloud-API path. Do not bet a login flow solely on an unofficial client.
6. **Mind the hosting IP.** Cheap datacenter IPs are flagged more aggressively than residential ones. A residential proxy (supported per-session via the proxy settings) can help; it is not a license to spam.

### Compliance

For any deployment where ethical, legal, or regulatory compliance matters (healthcare, finance, large-scale commercial messaging, anything touching end users in the EU/EEA under DMA/GDPR framings), treat OpenWA as **not approved** and use Meta's [official WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api). OpenWA is an excellent fit for personal projects, internal tooling, automation hobbyists, and learning — it is not a drop-in replacement for the official API in regulated environments.

📖 For the deeper, maintainer-side risk analysis, see [Risk Management (`docs/16`)](./docs/16-risk-management.md).

---

## 🎯 Features

### Core

| Feature       | Status | Description                                                                  |
| ------------- | ------ | ---------------------------------------------------------------------------- |
| REST API      | ✅     | Full WhatsApp API via HTTP endpoints                                         |
| Multi-Session | ✅     | Manage multiple WhatsApp accounts                                            |
| Webhooks      | ✅     | Real-time events with HMAC signature and optional smart pre-dispatch filters |
| Web Dashboard | ✅     | Visual management interface                                                  |
| API Key Auth  | ✅     | Peppered API-key authentication (this fork)                                  |
| 2FA (TOTP)    | ✅     | Google Authenticator for admin keys (this fork)                              |
| Swagger Docs  | ✅     | Interactive API documentation                                                |

### Messaging

| Feature           | Status | Description                                               |
| ----------------- | ------ | --------------------------------------------------------- |
| Text Messages     | ✅     | Send/receive text messages                                |
| Media Messages    | ✅     | Images, videos, documents, audio                          |
| Message Reactions | ✅     | React to messages with emoji                              |
| Message Editing   | ✅     | Send edits + live `message.edited` events on both engines |
| Bulk Messaging    | ✅     | Send to multiple recipients                               |
| Message Status    | ✅     | Track delivery and read receipts                          |

### Advanced

| Feature             | Status | Description                                                                        |
| ------------------- | ------ | ---------------------------------------------------------------------------------- |
| Groups API          | ✅     | Create, manage, join (invite code), and configure groups                           |
| Profile Management  | ✅     | Set own display name, about text, and profile picture                              |
| Call Handling       | ✅     | `call.received` events, reject calls, per-session auto-reject                      |
| Channels/Newsletter | ✅     | WhatsApp Channels support                                                          |
| Labels Management   | ✅     | Organize chats with labels                                                         |
| Proxy Support       | ✅     | Per-session proxy configuration                                                    |
| Rate Limiting       | ✅     | Configurable request limits                                                        |
| Brute-force lockout | ✅     | Per-IP auth lockout + fail2ban integration (this fork)                             |
| CIDR Whitelisting   | ✅     | IP-based access control (Cloudflare-aware in this fork)                            |
| Audit Logging       | ✅     | Audit trail for API-key, session, integration-instance, and infra admin operations |

### Infrastructure

| Feature          | Status | Description                              |
| ---------------- | ------ | ---------------------------------------- |
| SQLite           | ✅     | Zero-config embedded database            |
| PostgreSQL       | ✅     | Production-grade database                |
| Redis Cache      | ✅     | Optional performance caching             |
| S3/MinIO Storage | ✅     | Media-directory backup/migration backend |
| Docker           | ✅     | One-command deployment                   |
| Health Checks    | ✅     | Kubernetes-ready probes                  |
| Data Migration   | ✅     | Export/import between backends           |

---

## 🚀 Quick Start

### Option A: Docker (Recommended)

```bash
# Clone this fork and start
git clone https://github.com/CristianCasapu/OpenWA.git
cd OpenWA
docker compose -f docker-compose.dev.yml up -d

# Access (the dashboard is bundled into the API image and served on the same port)
# Dashboard: http://localhost:2785
# API: http://localhost:2785/api
# Swagger: http://localhost:2785/api/docs
```

> **Using Podman instead of Docker?**
> Podman rootless mode requires the socket to be running and `DOCKER_HOST` to be set:
>
> ```bash
> systemctl --user start podman.socket
> systemctl --user enable podman.socket
> export DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock
> ```
>
> Add the `export` line to your `~/.bashrc` to make it permanent.

### Option B: Local Development

```bash
# Clone this fork
git clone https://github.com/CristianCasapu/OpenWA.git
cd OpenWA

# Install the locked dependencies (includes dashboard)
npm ci

# Start API + Dashboard (config is auto-generated on first run)
npm run dev

# Access (in dev the dashboard runs on the Vite server with hot reload)
# Dashboard: http://localhost:2886
# API: http://localhost:2785/api
# Swagger: http://localhost:2785/api/docs
```

Use `npm install` instead when intentionally changing dependencies. OpenWA's committed lockfile uses
registry artifacts only, so npm 12 works with its secure default that blocks Git dependencies; do not
disable that policy globally.

---

## 🔒 Security Architecture

Beyond the fork-specific hardening [listed above](#-what-this-fork-adds), the base stack ships two structural protections worth calling out.

### Docker Socket Proxy

The production stack never exposes `/var/run/docker.sock` directly to the application container. Instead, a dedicated `docker-proxy` sidecar (based on [`tecnativa/docker-socket-proxy`](https://github.com/Tecnativa/docker-socket-proxy)) acts as the sole gateway to the Docker daemon:

```
openwa-api  ──TCP 2375──▶  docker-proxy  ──unix──▶  /var/run/docker.sock
```

Only the operations needed for container orchestration are enabled (`CONTAINERS`, `IMAGES`, `VOLUMES`, `INFO`, `PING`, plus the `POST` method switch). The application connects via the `DOCKER_HOST=tcp://docker-proxy:2375` environment variable, which `DockerService` detects automatically. Note this is an operational gateway, not a fine-grained privilege boundary: with `POST` enabled the proxy admits every method to the enabled paths and cannot scope container-create payloads, so a compromised API container would be host-root-equivalent — see `SECURITY.md` for the full threat model, mitigations, and how to disable the proxy if you don't use the built-in datastore orchestration.

### Non-root Container Execution

The production image never runs the Node.js process as root. On startup, the container follows this chain:

```
dumb-init (PID 1)
  └─ docker-entrypoint.sh (root — fixes named-volume ownership via chown)
       └─ gosu openwa node dist/main  (drops to the openwa user)
```

- **dumb-init** is PID 1 and forwards signals (SIGTERM, etc.) for graceful shutdown.
- **docker-entrypoint.sh** runs as root only long enough to `chown` the named-volume mount points so the `openwa` user can write to them.
- **gosu** performs a clean `exec`-based privilege drop — no `su` or `sudo` wrappers, so the node process is the direct child of dumb-init.

Named volumes (e.g. `openwa-data`) get their ownership corrected automatically on every start, so no manual `chown` step is needed after volume creation.

---

## 🏭 Production Deployment

For production, use the main `docker-compose.yml` with optional services:

```bash
# Basic production (SQLite, local storage)
docker compose up -d

# With PostgreSQL database
docker compose --profile postgres up -d

# Full stack (PostgreSQL, Redis, MinIO)
docker compose --profile full up -d
```

| Profile    | Services              |
| ---------- | --------------------- |
| `postgres` | PostgreSQL database   |
| `redis`    | Redis cache           |
| `minio`    | S3-compatible storage |
| `full`     | All services above    |

> The dashboard is bundled into the API image and served by NestJS on the API port, so it
> needs no profile — it is always available wherever `openwa-api` runs. For TLS/public exposure,
> put your own reverse proxy (nginx, Caddy, a cloud load balancer, or a k8s Ingress) in front;
> see the nginx example in `docs/12-troubleshooting-faq.md`.

> **Development vs Production**
>
> - Development (`docker-compose.dev.yml`): SQLite, local storage, API serves the bundled dashboard
> - Production (`docker-compose.yml`): Configurable database, profiles for optional services

## 🔌 Ports

| Service         | Port            | Description                                     |
| --------------- | --------------- | ----------------------------------------------- |
| API & Dashboard | `2785`          | REST API + bundled web dashboard (same port)    |
| Swagger         | `2785/api/docs` | Interactive API docs                            |
| Dashboard (dev) | `2886`          | Vite dev server with hot reload (`npm run dev`) |

---

## 📡 API Examples

### Create a Session

```bash
curl -X POST http://localhost:2785/api/sessions \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"name": "my-bot"}'
```

### Start Session & Get QR Code

```bash
# Start the session
curl -X POST http://localhost:2785/api/sessions/{sessionId}/start \
  -H "X-API-Key: YOUR_API_KEY"

# Get QR code (scan with WhatsApp)
curl http://localhost:2785/api/sessions/{sessionId}/qr \
  -H "X-API-Key: YOUR_API_KEY"
```

### Send a Message

```bash
curl -X POST http://localhost:2785/api/sessions/{sessionId}/messages/send-text \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "chatId": "628123456789@c.us",
    "text": "Hello from OpenWA!"
  }'
```

### Setup Webhook

```bash
curl -X POST http://localhost:2785/api/sessions/{sessionId}/webhooks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "url": "https://your-server.com/webhook",
    "events": ["message.received", "session.status"],
    "secret": "your-hmac-secret"
  }'
```

> **Smart filters (optional):** add a `filters` object to fire the webhook only when conditions match
> (AND), e.g. `{ "conditions": [{ "field": "sender", "operator": "is", "value": ["1234567890@c.us"] }] }`.
> Fields: `sender` / `recipient` / `body` / `type` / `mentions` / `fromMe` / `hasMedia` / `isGroup`. A
> webhook with no filters behaves exactly as before. See the API specification for the full schema.

## 🤖 MCP Server (AI Agents)

OpenWA can expose a **curated set of tools over the [Model Context Protocol](https://modelcontextprotocol.io)** so AI agents (Claude, Cursor, …) can drive WhatsApp. It is **off by default** and **additive** — every REST route keeps working unchanged.

Set `MCP_ENABLED=true` to mount a stateless Streamable-HTTP transport at **`POST /mcp`** on the existing server (same port, no extra process). It exposes a focused set of curated tools (sessions, messaging, contacts, basic group ops, webhook reads, labels, automation-rule reads) rather than the full API, so agents aren't overwhelmed and destructive operations stay off the agent path.

```bash
MCP_ENABLED=true npm run start:prod   # or set MCP_ENABLED in your .env / compose
```

Point an MCP client at it (e.g. for Claude Code, a `.mcp.json` at your project root):

```json
{
  "mcpServers": {
    "openwa": {
      "type": "http",
      "url": "http://localhost:2785/mcp",
      "headers": { "Authorization": "Bearer YOUR_API_KEY" }
    }
  }
}
```

The key can be passed as `Authorization: Bearer …` or `X-API-Key: …`. Every tool call goes through the **same API-key auth, role, and per-session scoping** as REST.

**Security guidance:**

- **Mint a dedicated, least-privilege key** for the agent — a non-admin, **session-scoped** key (`OPERATOR` role at most). The plaintext key is shown only once on creation; to rotate, create a new key and delete the old one.
- The key **must not** carry an IP allow-list (`allowedIps`) — there is no genuine client IP over MCP, so such a key is rejected.
- Set **`MCP_READONLY=true`** to mount only the read tools (no sends/writes).
- Set **`MCP_RATE_LIMIT_MAX`** / **`MCP_RATE_LIMIT_WINDOW_MS`** to bound tool calls per API key per window.
- **Do not expose `/mcp` to the public internet** without a fronting auth proxy.

---

## 🛠 Tech Stack

| Layer         | Technology                                              |
| ------------- | ------------------------------------------------------- |
| **Runtime**   | Node.js 22 LTS                                          |
| **Framework** | NestJS 11.x                                             |
| **Language**  | TypeScript 6.x                                          |
| **WA Engine** | whatsapp-web.js (default) / baileys — set `ENGINE_TYPE` |
| **Database**  | SQLite / PostgreSQL                                     |
| **Cache**     | Redis (optional)                                        |
| **Storage**   | Local / S3 / MinIO                                      |
| **ORM**       | TypeORM                                                 |
| **Container** | Docker + Docker Compose                                 |

---

## 📚 Documentation

Comprehensive documentation lives in the `docs/` folder:

| Document                                           | Description                 |
| -------------------------------------------------- | --------------------------- |
| [Project Overview](./docs/01-project-overview.md)  | Introduction and goals      |
| [Architecture](./docs/03-system-architecture.md)   | System design               |
| [Security](./docs/04-security-design.md)           | Security implementation     |
| [Database](./docs/05-database-design.md)           | Data models and migrations  |
| [API Spec](./docs/06-api-specification.md)         | Complete API reference      |
| [Development](./docs/08-development-guidelines.md) | Coding standards            |
| [fail2ban](./docs/31-fail2ban.md)                  | Intrusion prevention (fork) |
| [2FA / TOTP](./docs/32-2fa.md)                     | Dashboard two-factor (fork) |

---

## 🤝 Contributing

Contributions to this fork are welcome:

1. **Fork** this repository
2. **Create** your feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

Please read the [Development Guidelines](./docs/08-development-guidelines.md) for coding standards and best practices.

---

## 🙏 Credits & License

This is a fork of **[`rmyndharis/OpenWA`](https://github.com/rmyndharis/OpenWA)** by **Yudhi Armyndharis and the OpenWA Contributors**, whose work is the foundation everything here builds on. All credit for the original architecture and feature set belongs to them.

Fork maintenance and the security-hardening work described above are by **[Cristian Casapu](https://github.com/CristianCasapu)**.

Both the original project and this fork are licensed under the **MIT License** — free for personal and commercial use. Under the terms of that license, the original copyright and permission notice are retained in [`LICENSE`](./LICENSE) alongside the fork maintainer's notice. See [LICENSE](./LICENSE) for the full text.

---

<div align="center">

**OpenWA** — Self-hosted WhatsApp API Gateway · hardened fork

[📖 Documentation](./docs/README.md) · [🔌 API Docs](http://localhost:2785/api/docs) · [🐛 Report Bug](https://github.com/CristianCasapu/OpenWA/issues) · [💡 Request Feature](https://github.com/CristianCasapu/OpenWA/issues)

<br/>

<sub>Fork maintained by <a href="https://github.com/CristianCasapu">Cristian Casapu</a> · originally <a href="https://github.com/rmyndharis/OpenWA">OpenWA</a> by <a href="https://github.com/rmyndharis">Yudhi Armyndharis</a> and the OpenWA Community</sub>

</div>
