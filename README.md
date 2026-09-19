# Zero-Trust Verified File Escrow

An HTML file is held server-side and is **not** released to the other party until they
have uploaded a video *and* you have personally watched it and pressed Approve.

## Flow

| Status | User A (creator) | User B (guest) |
|---|---|---|
| `waiting_for_b` | Sees the share link | Must upload a video |
| `pending_approval` | Streams the video, Approve / Reject | "Waiting for approval" — nothing downloadable |
| `released` | Downloads the video | Downloads the HTML |
| `empty` | Rejected: both files deleted. Can re-lock on the same link | Nothing available |

## Run locally

```bash
npm install
npm start          # http://localhost:3000
```

## Who is allowed to do what

User A is identified by an `ownerToken` returned **once**, at creation, and kept in their
browser's `localStorage`. User B only ever receives the `exchangeId`.

Every creator-only route (`/api/preview-video`, `/api/approve`, `/api/reject`,
`/api/download-video`, `/api/relock`) requires that token and returns a flat `403` without it.
`/api/download-html` returns `403` for everyone until the status is `released`.
`/api/status/:id` returns a *scoped* view: a guest cannot even see that a video exists.

Because both roles share a browser origin, do not test A and B in the same browser
profile — the second tab will read the first tab's token out of `localStorage`.
Use a private window for the User B side.

## Verifying an exotic video

`/api/preview-video/:id` is a raw, `Range`-capable stream, so the `<video>` player can seek.
If the browser cannot decode the container (common with `.mkv`, `.avi`, some `.mov`),
the UI detects it — including the case where Chrome silently hangs instead of raising
an error — and points you at **Download raw file to check in VLC**. The file is never
released to User B by previewing it.

## Deploy

### Render (free tier)

```bash
git init && git add -A && git commit -m "Zero-trust file escrow"
gh repo create zero-trust-escrow --private --source=. --push
```

Then on Render: **New → Blueprint**, pick the repo. `render.yaml` sets the build/start
commands, health check and limits. Or **New → Web Service** with
build `npm install`, start `npm start` — no port config needed, the app reads `process.env.PORT`.

### Hatchable / Heroku-style

`Procfile` is included. Push the repo and it boots with no further configuration.

## Free-tier caveats

These are properties of the host, not bugs:

- **Ephemeral disk.** A redeploy or restart wipes `uploads/`. In-memory exchanges are
  dropped at the same moment, so links do not outlive a restart — deliberate, since a
  live link pointing at a deleted file is worse than a dead one.
- **Cold starts.** Render's free tier sleeps after ~15 min idle. A sleeping instance
  loses all in-flight exchanges. Complete a swap in one sitting, or use a paid instance.
- **Large uploads.** Free-tier bandwidth makes multi-GB videos slow and restart-prone.
  Lower `MAX_VIDEO_MB` if you want uploads to fail fast rather than crawl.

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | Set automatically by the host |
| `MAX_HTML_MB` | `10` | Max locked HTML size |
| `MAX_VIDEO_MB` | `2048` | Max video size |
| `EXCHANGE_TTL_HOURS` | `24` | Files and sessions are swept after this |
| `UPLOAD_DIR` | `./uploads` | Where files are stored |
| `PURGE_UPLOADS_ON_BOOT` | `true` | Delete orphaned uploads at startup |
