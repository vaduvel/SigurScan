# Cloudflare API Domain

SigurScan exposes its production backend through:

```text
https://api.sigurscan.com
```

The hostname is implemented as a transparent Cloudflare Worker custom domain.
It forwards requests to Cloud Run while keeping the public API address stable.

## Architecture

```text
Android / web client
  -> api.sigurscan.com
  -> Cloudflare Worker
  -> Cloud Run sigurscan-api
```

Cloudflare manages DNS and TLS. Cloud Run continues to run the complete backend.
The Worker does not contain provider keys, application API keys, or verdict
logic.

## Operational Rules

- Do not cache API responses at the Cloudflare edge.
- Do not add verdict or parsing logic to the proxy.
- Update only `ORIGIN_URL` when migrating the backend.
- Keep the raw Cloud Run URL available temporarily for rollback and smoke tests.
