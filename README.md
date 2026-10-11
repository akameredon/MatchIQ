# MatchIQ backend (Cloudflare Workers, free plan)

Setup (once):
1. npm i -g wrangler && wrangler login
2. wrangler kv namespace create MATCHIQ      -> copy the id into wrangler.toml
3. wrangler secret put ADMIN_PASSWORD        -> choose your admin password
4. wrangler secret put SESSION_SECRET        -> type any long random string
5. wrangler deploy

Then open https://<your-worker>.workers.dev/admin, log in as "admin", paste your football-data.org token, Save.
The public site is at the root URL. Visitors never see or need the token.
