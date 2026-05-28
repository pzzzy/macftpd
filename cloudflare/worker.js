const ORIGIN = "https://macftpd-origin.example.com";
const PUBLIC_CACHE = "public, max-age=300, stale-while-revalidate=60";
const RELEASE_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
};

function originRequestFor(request, url) {
  const pathname = url.pathname.startsWith("/.well-known/acme-challenge/")
    ? `/public${url.pathname}`
    : url.pathname;
  const originURL = new URL(pathname + url.search, ORIGIN);
  const headers = new Headers(request.headers);
  headers.set("X-Forwarded-Host", url.host);
  headers.set("X-Forwarded-Proto", "https");
  headers.set("X-Macftpd-Public-Host", url.host);
  headers.delete("X-Original-URL");
  headers.delete("X-Rewrite-URL");
  return new Request(originURL, {
    method: request.method,
    headers,
    body: request.body,
    redirect: "manual",
  });
}

function applyReleaseHeaders(response) {
  for (const [key, value] of Object.entries(RELEASE_HEADERS)) {
    response.headers.set(key, value);
  }
  return response;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const originRequest = originRequestFor(request, url);
    const isAcme = url.pathname.startsWith("/.well-known/acme-challenge/");

    if ((request.method === "GET" || request.method === "HEAD") && (url.pathname.startsWith("/public/") || isAcme)) {
      const cache = caches.default;
      const cached = await cache.match(request);
      if (cached) {
        const hit = new Response(cached.body, cached);
        hit.headers.set("X-Macftpd-Cache", "HIT");
        return hit;
      }

      const response = await fetch(originRequest);
      const out = new Response(response.body, response);
      out.headers.set("Cache-Control", isAcme ? "no-store" : PUBLIC_CACHE);
      if (!isAcme) {
        out.headers.set("CDN-Cache-Control", PUBLIC_CACHE);
        out.headers.set("Cloudflare-CDN-Cache-Control", PUBLIC_CACHE);
      }
      out.headers.set("X-Macftpd-Cache", "MISS");
      applyReleaseHeaders(out);

      if (!isAcme && response.status === 200) {
        ctx.waitUntil(cache.put(request, out.clone()));
      }
      return out;
    }

    const response = await fetch(originRequest);
    const out = new Response(response.body, response);
    out.headers.set("Cache-Control", "no-store");
    out.headers.set("X-Macftpd-Cache", "BYPASS");
    return applyReleaseHeaders(out);
  },
};
