# Output Contract

## Supabase row: `fast_preview_cache`

```json
{
  "url_hash": "sha256(final_url_normalized)",
  "original_url": "https://tracking.example/path",
  "final_url": "https://brand.ro/page",
  "final_domain": "brand.ro",
  "redirect_chain": ["https://tracking.example/path", "https://brand.ro/page"],
  "http_status": 200,
  "page_title": "Page title",
  "screenshot_path": "{url_hash}.png",
  "screenshot_w": 1365,
  "screenshot_h": 2400,
  "content_hash": "sha256(png_bytes)",
  "captured_at": "2026-06-09T12:00:00.000Z",
  "expires_at": "2026-06-23T12:00:00.000Z",
  "source_email_id": ["message-id-or-filename.eml"],
  "reachable": true,
  "status": "ready",
  "source": "precapture_worker",
  "seed_category": "courier",
  "visual_only": true,
  "verdict_role": "none",
  "error": null
}
```

`screenshot_path` is the object key inside the private Supabase Storage bucket `previews`.
The backend is responsible for creating short-lived signed URLs for Android.

## Alias row: `fast_preview_alias_cache`

```json
{
  "alias_hash": "sha256(original_or_tracking_url_normalized)",
  "original_url": "https://tracking.example/path",
  "final_url_hash": "sha256(final_url_normalized)",
  "captured_at": "2026-06-09T12:00:00.000Z",
  "expires_at": "2026-06-23T12:00:00.000Z"
}
```

## Error examples

```text
reserved_domain_skipped
blocked_private_ip:127.0.0.1
dns_error:ENOTFOUND
capture_failed:Timeout 20000ms exceeded
capture_failed:redirect_hops_exceeded:12
http_status:404
blocked_by_origin:http_status:403
transient_capture_failure:capture_failed:net::ERR_HTTP2_PROTOCOL_ERROR
```

## UI interpretation

| status | reachable | screenshot_path | UI |
|---|---:|---|---|
| ready | true | present | show cached preview |
| dead | false | null/present | preview unavailable |
| skipped / blocked | false | null | not persisted; UI receives no cache entry |
| error | false | null | preview unavailable |

This cache is visual-only. It must never be consumed as verdict evidence.
The database enforces `visual_only = true` and `verdict_role = "none"`.
Rows with status `skipped` or `blocked` are not persisted, and no alias row is created.
