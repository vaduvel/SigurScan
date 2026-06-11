const PUBLIC_HOST = "api.sigurscan.com";
export function buildUpstreamRequest(request, originUrl) {
  const incomingUrl = new URL(request.url);
  const upstreamUrl = new URL(originUrl);
  upstreamUrl.pathname = incomingUrl.pathname;
  upstreamUrl.search = incomingUrl.search;

  const forwardedRequest = new Request(upstreamUrl, request);
  const headers = new Headers(forwardedRequest.headers);
  headers.delete("host");
  headers.set("x-forwarded-host", incomingUrl.host);
  headers.set("x-forwarded-proto", "https");
  headers.set("x-sigurscan-edge", "cloudflare");

  return new Request(forwardedRequest, {
    headers,
    redirect: "manual",
  });
}

export function buildPublicResponse(upstreamResponse, originUrl) {
  const headers = new Headers(upstreamResponse.headers);
  const location = headers.get("location");

  if (location) {
    const origin = new URL(originUrl);
    const redirect = new URL(location, origin);
    if (redirect.origin === origin.origin) {
      redirect.protocol = "https:";
      redirect.host = PUBLIC_HOST;
      headers.set("location", redirect.toString());
    }
  }

  // API responses must never be cached at the edge unless an endpoint opts in later.
  headers.set("cache-control", "no-store");
  headers.set("x-sigurscan-edge", "cloudflare");

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    try {
      const upstreamRequest = buildUpstreamRequest(request, env.ORIGIN_URL);
      const upstreamResponse = await fetch(upstreamRequest, {
        cf: { cacheEverything: false },
      });
      return buildPublicResponse(upstreamResponse, env.ORIGIN_URL);
    } catch (error) {
      console.error(JSON.stringify({
        event: "api_proxy_error",
        error: error instanceof Error ? error.message : String(error),
      }));
      return Response.json(
        { detail: "Serviciul SigurScan este temporar indisponibil." },
        {
          status: 502,
          headers: {
            "cache-control": "no-store",
            "x-sigurscan-edge": "cloudflare",
          },
        },
      );
    }
  },
};
