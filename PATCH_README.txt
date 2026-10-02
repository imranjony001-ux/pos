HISABI BONDHU - CLOUDFLARE WEBSITE UI PATCH
===========================================

Apply this patch on top of your current GitHub repo.

IMPORTANT:
1. Extract this ZIP first.
2. Upload the CONTENTS directly to the GitHub repository root.
3. Replace/overwrite worker.js, wrangler.jsonc and package.json when GitHub asks.
4. Upload the whole public/ folder. It is NOT empty.
5. Cloudflare settings:
   Root directory: /
   Build command: empty
   Deploy command: npx wrangler deploy
6. Push/commit and retry build.

What this patch changes:
- Removes the old "Worker deployed successfully" placeholder page.
- Adds the Hisabi Bondhu landing website UI.
- Adds General Business, Pharmacy, Tailor and Family portal landing/login pages.
- Adds static dashboard shells that can read Worker API/D1 after D1 is bound.
- Adds non-empty public/ assets so Cloudflare Static Assets deploy correctly.
- Keeps existing Worker API/login code.

D1/R2 NOTE:
This patch intentionally does not hard-code a D1 database_id or R2 bucket name because those IDs must come from your Cloudflare account. The website UI will deploy now. Login/data APIs require the DB/UPLOADS bindings to be added later.
