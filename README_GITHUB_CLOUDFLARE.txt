GITHUB -> CLOUDFLARE BUILD STRUCTURE

Upload the CONTENTS of this folder to the ROOT of the GitHub repository.
Do NOT upload this whole folder as a wrapper folder.

GitHub repository root must show these directly:
  package.json
  wrangler.jsonc
  worker.js
  public/
  migrations/
  seed/
  r2_seed/

Cloudflare build settings:
  Root directory: /
  Build command: (empty / none)
  Deploy command: npx wrangler deploy

Important:
- There is NO src/ dependency.
- Wrangler entry point is root worker.js.
- D1 DB and R2 bindings must be connected after the code deploys.
