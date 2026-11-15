# Deploy — Proof Gatekeeper

The service is a plain Node.js HTTP server (`POST /agent`, `GET /health`).
It listens on `$PORT` (default 3000). Any host that can run a Docker
image or a Node app from this repo works.

## Environment variables (set on the host — never in the repo)

| variable | value |
| --- | --- |
| `PORT` | set automatically by Railway / Render / Fly.io (leave unset locally = 3000) |
| `AGENT_GAMES_HMAC_SECRET` | from the Agent Games dashboard → **Rotate Secret** (copy the plaintext once) |
| `KURIER_API_KEY` | from the Kurier dashboard (leave empty to run without Kurier; see below) |
| `REQUIRE_KURIER_FINALIZED` | `true` (default) — APPROVE only when the Kurier job reaches `Finalized` |
| `KURIER_POLL_BUDGET_MS` | `40000` (default, must fit inside the 60 s task deadline) |
| `GATEKEEPER_VK_HASH` | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` (protocol constant, already the default) |

The service refuses to start without `AGENT_GAMES_HMAC_SECRET`. With no
`KURIER_API_KEY` and `REQUIRE_KURIER_FINALIZED=true`, every task is
REJECTED with `PROOF_NOT_FINALIZED` (fail closed) — set the key, or set
`REQUIRE_KURIER_FINALIZED=false` to approve on locally verified proofs.

## Option A — Railway (recommended: free tier, deploys from GitHub)

1. railway.app → New Project → Deploy from GitHub repo → pick
   `JodienX/zkAria`.
2. Service settings → Root Directory: `gatekeeper`.
3. Railway detects the Dockerfile and builds it (circuit artifacts are
   downloaded + checksum-verified during the build).
4. Variables tab → add the variables above.
5. Settings → Networking → Generate Domain → copy the public HTTPS URL.
6. Check `https://<your-domain>/health` returns `{"ok": true}`.

## Option B — Render (free tier)

1. render.com → New → Web Service → connect `JodienX/zkAria`.
2. Root Directory: `gatekeeper`. Runtime: Docker (uses the Dockerfile).
3. Environment → add the variables above.
4. Deploy → copy the `https://<service>.onrender.com` URL.
5. Check `/health`. Note: Render free tier sleeps after inactivity —
   the first request after idle can be slow; keep that in mind for the
   60 s deadline, or use a paid instance.

## Option C — Fly.io

1. `fly launch` inside `gatekeeper/` (uses the Dockerfile), then
   `fly secrets set AGENT_GAMES_HMAC_SECRET=... KURIER_API_KEY=...`.
2. `fly deploy` → `https://<app>.fly.dev`.

## Option D — VPS (Docker)

```bash
docker build -t gatekeeper ./gatekeeper
docker run -d --restart unless-stopped -p 3000:3000 \
  -e AGENT_GAMES_HMAC_SECRET='...' -e KURIER_API_KEY='...' \
  --name gatekeeper gatekeeper
```

Put it behind HTTPS (Caddy / nginx + Let's Encrypt) — the platform
requires a public HTTPS URL, plain HTTP will not be accepted.

## After deploy — activate on the dashboard

1. Agent Games dashboard → Manage Agents → set the endpoint URL to
   `https://<your-domain>/agent` (the full handler path, not the root).
2. Rotate Secret on the dashboard and set the new value as
   `AGENT_GAMES_HMAC_SECRET` (redeploy / restart after changing it).
3. Run **preflight** from the dashboard — it must pass before the agent
   is marked active.
4. Dashboard → **Practice** — send unscored practice tasks first. This
   confirms the live Kurier job-status path and the `task_id` encoding
   assumption (see README → Known limitations) before any scored round.
5. Only then enter the Proof Gatekeeper event (competition closes
   21 Nov 2026).
