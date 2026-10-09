# Élan Editor (Railway)

Original Élan editor page (from elan-editor-handoff-11ed9046.html) behind an owner-only login.
- `/` login page; after admin login it serves the editor page (never a public file).
- Session: server memory only, browser-session cookie, no "remember me"; 2h idle / 10h max.
- `/api/editor` saves `design/home.json` to GitHub (used when the site-side bridge is connected).

## Railway variables (set in Railway, never in code)
`GITHUB_TOKEN`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `EDITOR_SITE_ORIGIN`,
`EDITOR_TARGET_BRANCH` (default `editor-staging`; `main` needs `EDITOR_ALLOW_MAIN=1`), `GITHUB_REPO` (optional).

Start: `npm start`. Health: `/health`. Tests: `npm test`.
