HISABI BONDHU - CLOUDFLARE DOMAIN LIVE PATCH
=============================================

Purpose:
- Deploy from GitHub to the existing Cloudflare Worker named: pos
- Make https://pos.<your-subdomain>.workers.dev/ show the website UI, not a deployment placeholder.

GitHub repository root MUST contain:
  package.json
  wrangler.jsonc
  worker.js
  public/

Cloudflare Build settings:
  Root directory: /
  Build command: leave empty
  Deploy command: npx wrangler deploy

Important:
- Upload the CONTENTS of this ZIP to the GitHub repo root. Do not upload the ZIP itself.
- Do not put these files inside another wrapper folder.
- public/index.html must remain present.
- This patch intentionally has no mandatory D1/R2 binding in wrangler.jsonc, so the domain can deploy/live first.
- D1/R2 can be connected after the site is live.
