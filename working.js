// Cloudflare Worker CORS proxy
const ALLOWED_METHODS = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"];
const HOP_BY_HOP = new Set(["connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailers","transfer-encoding","upgrade"]);

function isForbiddenHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local")) return true;
  if (h.startsWith("127.") || h.startsWith("10.") || h.startsWith("192.168.")) return true;
  const m = h.match(/^172\.(\d+)\./); if (m && +m[1] >= 16 && +m[1] <= 31) return true;
  if (h === "0.0.0.0" || h === "169.254.169.254" || h === "[::1]") return true;
  return false;
}
function corsHeaders(origin="*"){ return {
  "access-control-allow-origin": origin,
  "access-control-allow-credentials": "true",
  "access-control-allow-methods": ALLOWED_METHODS.join(","),
  "access-control-allow-headers": "*",
  "access-control-expose-headers": "*",
};}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health")
      return new Response("ok", { status:200, headers:corsHeaders("*") });

    if (url.pathname !== "/proxy")
      return new Response("Not found", { status:404, headers:corsHeaders("*") });

    if (request.method === "OPTIONS")
      return new Response(null, { status:204, headers:corsHeaders(request.headers.get("origin")||"*") });

    if (!ALLOWED_METHODS.includes(request.method))
      return new Response("Method not allowed", { status:405, headers:corsHeaders("*") });

    const target = url.searchParams.get("url");
    if (!target) return new Response("Missing ?url=", { status:400, headers:corsHeaders("*") });

    let targetURL;
    try { targetURL = new URL(target); } catch { return new Response("Invalid target URL", { status:400, headers:corsHeaders("*") }); }
    if (!["http:", "https:"].includes(targetURL.protocol))
      return new Response("Only http/https allowed", { status:400, headers:corsHeaders("*") });
    if (isForbiddenHost(targetURL.hostname))
      return new Response("Forbidden host", { status:403, headers:corsHeaders("*") });

    if (env.PROXY_KEY) {
      if ((request.headers.get("x-proxy-key")||"") !== env.PROXY_KEY)
        return new Response("Unauthorized", { status:401, headers:corsHeaders("*") });
    }

    const init = { method: request.method, headers: new Headers(), redirect: "follow" };
    if (!["GET","HEAD"].includes(request.method)) { init.body = request.body; init.duplex = "half"; }

    for (const [k, v] of request.headers) {
      const lk = k.toLowerCase();
      if (HOP_BY_HOP.has(lk)) continue;
      if (lk === "host" || lk === "origin" || lk === "referer") continue;
      if (lk.startsWith("cf-") || lk.startsWith("x-forwarded-")) continue;
      if (lk === "x-proxy-key") continue;
      init.headers.set(k, v);
    }

    let upstream;
    try { upstream = await fetch(targetURL.toString(), init); }
    catch (e) { return new Response("Upstream fetch failed: " + (e?.message || e), { status:502, headers:corsHeaders("*") }); }

    const out = new Headers(corsHeaders(request.headers.get("origin")||"*"));
    for (const [k,v] of upstream.headers) if (!HOP_BY_HOP.has(k.toLowerCase())) out.set(k, v);
    out.set("cache-control", "no-store");

    return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out });
  }
};
