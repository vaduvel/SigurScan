import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHttpsRedirect,
  buildPublicResponse,
  buildUpstreamRequest,
  STRICT_TRANSPORT_SECURITY,
} from "../src/index.js";

const ORIGIN = "https://sigurscan-api-tvszku44fq-ew.a.run.app";

test("redirects plain HTTP requests to the same HTTPS URL", () => {
  const input = new Request("http://api.sigurscan.com/v1/scan/orchestrated?mode=full");
  const output = buildHttpsRedirect(input);

  assert.equal(output.status, 308);
  assert.equal(output.headers.get("location"), "https://api.sigurscan.com/v1/scan/orchestrated?mode=full");
  assert.equal(output.headers.get("cache-control"), "no-store");
  assert.equal(output.headers.get("strict-transport-security"), STRICT_TRANSPORT_SECURITY);
  assert.equal(output.headers.get("x-sigurscan-edge"), "cloudflare");
});

test("preserves path, query, API key, method, and body", async () => {
  const input = new Request("https://api.sigurscan.com/v1/scan/orchestrated?mode=full", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": "test-key",
    },
    body: JSON.stringify({ text: "mesaj" }),
  });

  const output = buildUpstreamRequest(input, ORIGIN);

  assert.equal(output.url, `${ORIGIN}/v1/scan/orchestrated?mode=full`);
  assert.equal(output.method, "POST");
  assert.equal(output.headers.get("x-api-key"), "test-key");
  assert.equal(output.headers.get("x-forwarded-host"), "api.sigurscan.com");
  assert.equal(output.headers.get("x-forwarded-proto"), "https");
  assert.deepEqual(await output.json(), { text: "mesaj" });
});

test("does not attach a body to GET requests", () => {
  const input = new Request("https://api.sigurscan.com/health");
  const output = buildUpstreamRequest(input, ORIGIN);

  assert.equal(output.method, "GET");
  assert.equal(output.body, null);
});

test("marks responses as non-cacheable and rewrites origin redirects", () => {
  const upstream = new Response(null, {
    status: 307,
    headers: {
      location: `${ORIGIN}/docs`,
    },
  });

  const output = buildPublicResponse(upstream, ORIGIN);

  assert.equal(output.headers.get("cache-control"), "no-store");
  assert.equal(output.headers.get("strict-transport-security"), STRICT_TRANSPORT_SECURITY);
  assert.equal(output.headers.get("x-sigurscan-edge"), "cloudflare");
  assert.equal(output.headers.get("location"), "https://api.sigurscan.com/docs");
});

test("does not rewrite redirects to external providers", () => {
  const upstream = new Response(null, {
    status: 302,
    headers: {
      location: "https://example.com/report",
    },
  });

  const output = buildPublicResponse(upstream, ORIGIN);

  assert.equal(output.headers.get("location"), "https://example.com/report");
});
