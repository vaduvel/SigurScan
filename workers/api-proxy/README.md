# SigurScan API Proxy

Cloudflare Worker that exposes the stable production endpoint
`https://api.sigurscan.com` and transparently forwards requests to the current
Cloud Run backend.

The Worker:

- preserves request paths, query parameters, bodies, and API-key headers;
- disables edge caching for API responses;
- rewrites redirects that expose the raw Cloud Run origin;
- provides Cloudflare-managed DNS and TLS for the public API hostname.

## Commands

```bash
npm ci
npm test
npm run deploy
```

The Cloud Run origin is a non-secret Wrangler variable in `wrangler.jsonc`.
Provider and application secrets remain configured only on Cloud Run.
