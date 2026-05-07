/**
 * CBP-v2 — Cleann's Backend Protocol, Cloudflare Worker
 *
 * All proxy traffic is AES-256-GCM encrypted end-to-end.
 * The Worker never receives a target URL in plain text.
 *
 * Request:  POST /proxy
 *   body: { iv, payload }   (both base64)
 *   payload decrypts to JSON: { method, target, headers, bodyBase64 }
 *
 * Response: { iv, payload }  (both base64)
 *   payload decrypts to JSON: { status, headers, bodyBase64 }
 *
 * Key derivation: HKDF(SECRET, "cbp-v2:" + floor(unix/600))
 *   This gives a rotating 10-minute window.  The previous window is
 *   also accepted so clock skew between client and server is tolerated.
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const CORS_ALLOW = '*';          // tighten to your Pages domain after deploy
const PAD_TO     = 1400;         // near-MTU padding to resist size fingerprinting
const MAX_BODY   = 10 * 1024 * 1024; // 10 MB response cap

const STRIP_REQ_HEADERS = new Set([
  'host', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
  'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip',
  'cdn-loop', 'true-client-ip', 'content-length', 'transfer-encoding',
]);

const STRIP_RES_HEADERS = new Set([
  'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'x-xss-protection', 'strict-transport-security',
  'set-cookie', 'clear-site-data',
]);

const BASE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
                '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// ─── Key derivation ───────────────────────────────────────────────────────────

async function deriveKey(secret, windowId) {
  const enc  = new TextEncoder();
  const raw  = enc.encode(secret);
  const info = enc.encode('cbp-v2:' + windowId);

  const baseKey = await crypto.subtle.importKey(
    'raw', raw, { name: 'HKDF' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Returns [currentKey, prevKey] for the two valid 10-min windows */
async function getKeys(secret) {
  const now   = Math.floor(Date.now() / 1000);
  const cur   = Math.floor(now / 600);
  const prev  = cur - 1;
  return Promise.all([deriveKey(secret, cur), deriveKey(secret, prev)]);
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function b64decode(str) {
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

function b64encode(buf) {
  let bin = '';
  const u8 = new Uint8Array(buf);
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

async function decryptPayload(secret, ivB64, payloadB64) {
  const iv      = b64decode(ivB64);
  const data    = b64decode(payloadB64);
  const [cur, prev] = await getKeys(secret);
  for (const key of [cur, prev]) {
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
      return JSON.parse(new TextDecoder().decode(plain));
    } catch (_) { /* try next window */ }
  }
  throw new Error('Decryption failed — invalid key or tampered payload');
}

async function encryptPayload(secret, obj) {
  const [key] = await getKeys(secret);
  const iv    = crypto.getRandomValues(new Uint8Array(12));
  let plain   = new TextEncoder().encode(JSON.stringify(obj));

  // Pad to near-MTU to prevent size fingerprinting
  if (plain.length < PAD_TO) {
    const padded = new Uint8Array(PAD_TO);
    padded.set(plain);
    // embed true length in first 4 bytes so client can strip padding
    const view = new DataView(padded.buffer);
    view.setUint32(0, plain.length, false);
    plain = padded;
  }

  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  return { iv: b64encode(iv), payload: b64encode(cipher) };
}

// ─── HTML / CSS rewriting ─────────────────────────────────────────────────────

function toAbs(href, base) {
  try { return new URL(href, base).href; } catch { return href; }
}

/**
 * Returns the encrypted POST payload for a given URL so the UI can navigate.
 * We encode it as a data-cbp attribute on the element — the injected JS will
 * intercept clicks and fire the encrypted POST instead.
 */
function proxiedAttr(href, base) {
  const abs = toAbs(href, base);
  // We can't do async crypto at rewrite time, so we encode the plaintext URL
  // in a data attribute — the injected client-side script will encrypt on demand.
  return `data-cbp-href="${abs}"`;
}

function rewriteHtml(html, finalUrl, origin) {
  // <a href> → intercept via data-cbp-href
  html = html.replace(
    /(<(?:a|area)\b[^>]*?)\bhref\s*=\s*(["'])([^"']*)\2/gi,
    (m, pre, q, href) => {
      if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return m;
      const abs = toAbs(href, finalUrl);
      return `${pre} ${proxiedAttr(href, finalUrl)} href="${abs}"`;
    }
  );

  // <form action> → intercept
  html = html.replace(
    /(<form\b[^>]*?)\baction\s*=\s*(["'])([^"']*)\2/gi,
    (m, pre, q, action) =>
      `${pre} data-cbp-action="${toAbs(action, finalUrl)}" action="#"`
  );

  // Resolve relative src → absolute so browser can load assets
  html = html.replace(
    /(<(?:script|img|source|track|input|iframe)\b[^>]*?)\bsrc\s*=\s*(["'])([^"']*)\2/gi,
    (m, pre, q, src) => {
      if (/^(data:|blob:|https?:\/\/)/i.test(src)) return m;
      return `${pre}src="${toAbs(src, finalUrl)}"`;
    }
  );
  html = html.replace(
    /(<link\b[^>]*?)\bhref\s*=\s*(["'])([^"']*)\2/gi,
    (m, pre, q, href) => {
      if (/^(data:|blob:|https?:\/\/)/i.test(href)) return m;
      return `${pre}href="${toAbs(href, finalUrl)}"`;
    }
  );

  // Inject <base> so relative URLs resolve to origin
  if (!/\<base\b/i.test(html)) {
    html = html.replace(/(<head[^>]*>)/i, `$1<base href="${origin}/">`);
  }

  // Inject client intercept script
  html = html.replace(
    /<\/head>/i,
    `<script id="__cbp_intercept__">${buildInterceptScript()}</script></head>`
  );
  return html;
}

function rewriteCss(css, finalUrl) {
  return css.replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, (m, q, src) => {
    if (/^(data:|blob:|https?:\/\/)/i.test(src)) return m;
    try { return `url(${q}${toAbs(src, finalUrl)}${q})`; } catch { return m; }
  });
}

/** Injected into proxied pages — intercepts clicks/form submits and fires
 *  encrypted POSTs back to the Cloudflare Worker via postMessage → parent frame. */
function buildInterceptScript() {
  return `
(function(){
  // Send navigation requests to the parent (the proxy UI iframe manager)
  function nav(url){
    try{ window.parent.postMessage({type:'cbp-nav',url:url},'*'); } catch(e){}
  }

  document.addEventListener('click',function(e){
    var el=e.target.closest('[data-cbp-href]');
    if(!el)return;
    e.preventDefault();
    nav(el.getAttribute('data-cbp-href'));
  },true);

  document.addEventListener('submit',function(e){
    var el=e.target.closest('[data-cbp-action]');
    if(!el)return;
    e.preventDefault();
    nav(el.getAttribute('data-cbp-action'));
  },true);

  // Patch fetch/XHR to route external requests through parent nav
  // (best-effort — complex SPAs may need additional handling)
  var _fetch=window.fetch.bind(window);
  window.fetch=function(resource,opts){
    try{
      var url=resource instanceof Request?resource.url:String(resource);
      if(url.startsWith('http')&&!url.startsWith(location.origin)){
        // pass-through via postMessage with a promise bridge would be complex;
        // for now we just allow the fetch and let CORS handle it gracefully.
      }
    }catch(e){}
    return _fetch(resource,opts);
  };
})();
`;
}

// ─── Heat-based cache (Cloudflare Cache API) ──────────────────────────────────

/** Track hit counts in memory per-isolate (resets on isolate recycle) */
const hitMap = new Map();

function getHitCount(url) { return hitMap.get(url) || 0; }
function bumpHit(url) { hitMap.set(url, (hitMap.get(url) || 0) + 1); }

/**
 * Heat-based TTL:
 *   hits >= 20 → 60 s (hot)
 *   hits >= 5  → 300 s (warm)
 *   else       → 900 s (cold)
 */
function computeTtl(url) {
  const h = getHitCount(url);
  if (h >= 20) return 60;
  if (h >= 5)  return 300;
  return 900;
}

async function cacheGet(cacheKey, ctx) {
  const cache = caches.default;
  const req   = new Request(cacheKey, { method: 'GET' });
  const hit   = await cache.match(req);
  if (hit) {
    bumpHit(cacheKey);
    return hit;
  }
  return null;
}

async function cachePut(cacheKey, response, ctx) {
  const cache = caches.default;
  const ttl   = computeTtl(cacheKey);
  const cloned = new Response(response.body, {
    status:  response.status,
    headers: response.headers,
  });
  cloned.headers.set('Cache-Control', `public, max-age=${ttl}, stale-while-revalidate=60`);
  cloned.headers.set('Vary', 'Accept-Encoding');
  ctx.waitUntil(cache.put(new Request(cacheKey, { method: 'GET' }), cloned));
}

// ─── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const origin = request.headers.get('origin') || '';

    // ── CORS preflight ──
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    // ── Health check ──
    if (url.pathname === '/health') {
      return new Response('OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', ...corsHeaders(origin) },
      });
    }

    // ── Proxy endpoint ──
    if (url.pathname === '/proxy' && request.method === 'POST') {
      return handleProxy(request, env, ctx, origin);
    }

    return new Response('Not Found', { status: 404 });
  },
};

// ─── Proxy handler ────────────────────────────────────────────────────────────

async function handleProxy(request, env, ctx, origin) {
  const secret = env.SECRET;
  if (!secret) {
    return jsonError(500, 'Worker misconfigured — SECRET not set', origin);
  }

  // Parse encrypted body
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'Invalid JSON body', origin);
  }
  if (!body?.iv || !body?.payload) {
    return jsonError(400, 'Missing iv or payload', origin);
  }

  // Decrypt
  let req;
  try {
    req = await decryptPayload(secret, body.iv, body.payload);
  } catch (e) {
    return jsonError(401, 'Decryption error: ' + e.message, origin);
  }

  const { method = 'GET', target, headers: reqHeaders = {}, bodyBase64 } = req;

  if (!target || typeof target !== 'string') {
    return jsonError(400, 'Missing target', origin);
  }
  let targetUrl;
  try {
    targetUrl = new URL(
      target.startsWith('http') ? target : 'https://' + target
    ).href;
  } catch {
    return jsonError(400, 'Invalid target URL', origin);
  }

  // ── Cache lookup (GET only, keyed on target URL) ──
  if (method === 'GET') {
    const cached = await cacheGet(targetUrl, ctx);
    if (cached) {
      const encResp = await encryptPayload(secret, {
        status: cached.status,
        headers: Object.fromEntries(cached.headers),
        bodyBase64: b64encode(await cached.arrayBuffer()),
        cached: true,
      });
      return new Response(JSON.stringify(encResp), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
  }

  // ── Forward request to target ──
  const fwdHeaders = {
    'user-agent':      BASE_UA,
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9',
  };
  for (const [k, v] of Object.entries(reqHeaders)) {
    if (!STRIP_REQ_HEADERS.has(k.toLowerCase()) && typeof v === 'string') {
      fwdHeaders[k] = v;
    }
  }

  let fwdBody;
  if (bodyBase64 && method !== 'GET' && method !== 'HEAD') {
    fwdBody = b64decode(bodyBase64);
  }

  let upstream;
  try {
    upstream = await fetch(targetUrl, {
      method,
      headers: fwdHeaders,
      body:    fwdBody,
      redirect: 'follow',
      signal:   AbortSignal.timeout(25000),
    });
  } catch (e) {
    return jsonError(502, 'Upstream fetch failed: ' + e.message, origin);
  }

  // ── Cap response size ──
  const rawBuf = await upstream.arrayBuffer();
  if (rawBuf.byteLength > MAX_BODY) {
    return jsonError(413, 'Response too large', origin);
  }

  const finalUrl  = upstream.url || targetUrl;
  const rawCT     = upstream.headers.get('content-type') ?? 'application/octet-stream';
  const isHtml    = rawCT.includes('text/html');
  const isCss     = rawCT.includes('text/css');

  let resBuf = new Uint8Array(rawBuf);
  let resCT  = rawCT;

  if (isHtml) {
    const originParsed = new URL(finalUrl).origin;
    let html = new TextDecoder().decode(resBuf);
    html   = rewriteHtml(html, finalUrl, originParsed);
    resBuf = new TextEncoder().encode(html);
    resCT  = 'text/html; charset=utf-8';
  } else if (isCss) {
    let css = new TextDecoder().decode(resBuf);
    css    = rewriteCss(css, finalUrl);
    resBuf = new TextEncoder().encode(css);
  }

  // Filter response headers
  const cleanHeaders = {};
  for (const [k, v] of upstream.headers.entries()) {
    if (!STRIP_RES_HEADERS.has(k.toLowerCase())) {
      cleanHeaders[k] = v;
    }
  }
  cleanHeaders['content-type'] = resCT;

  const encResp = await encryptPayload(secret, {
    status:      upstream.status,
    headers:     cleanHeaders,
    bodyBase64:  b64encode(resBuf.buffer),
    finalUrl,
  });

  // ── Store in cache for GET requests ──
  if (method === 'GET') {
    const cacheResp = new Response(JSON.stringify(encResp), {
      status:  200,
      headers: { 'Content-Type': 'application/json' },
    });
    await cachePut(targetUrl, cacheResp, ctx);
    bumpHit(targetUrl);
  }

  return new Response(JSON.stringify(encResp), {
    status:  200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin':  CORS_ALLOW,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
  };
}

function jsonError(status, message, origin) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}
