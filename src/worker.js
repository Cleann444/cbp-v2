// cbp-v2/src/worker.js – Stealth encrypted proxy with Browser Rendering (env secret)
import puppeteer from "@cloudflare/puppeteer";

async function getKey(secret, epoch) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${secret}:${epoch}`);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptObject(obj, epoch, secret) {
  const plain = JSON.stringify(obj);
  const plainBytes = new TextEncoder().encode(plain);
  const key = await getKey(secret, epoch);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes);
  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv);
  result.set(new Uint8Array(encrypted), iv.length);
  return result;
}

async function decryptObject(binary, epoch, secret) {
  const iv = binary.slice(0, 12);
  const ciphertext = binary.slice(12);
  const key = await getKey(secret, epoch);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  const json = new TextDecoder().decode(decrypted);
  return JSON.parse(json);
}

export default {
  async fetch(request, env, ctx) {
    const SECRET = env.SECRET;
    if (!SECRET) {
      return new Response('Server configuration error: SECRET not set', { status: 500 });
    }

    const url = new URL(request.url);
    const workerOrigin = `${url.protocol}//${url.hostname}`;

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    if (url.pathname === '/health') {
      return new Response('OK', { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } });
    }

    if (url.pathname === '/api/proxy') {
      if (request.method !== 'POST') {
        return new Response('Method not allowed', { status: 405, headers: { 'Access-Control-Allow-Origin': '*' } });
      }

      let encryptedBody;
      try {
        encryptedBody = new Uint8Array(await request.arrayBuffer());
      } catch (e) {
        return new Response('Invalid body', { status: 400, headers: { 'Access-Control-Allow-Origin': '*' } });
      }

      const epoch = Math.floor(Date.now() / 600000);
      let requestObj;
      try {
        requestObj = await decryptObject(encryptedBody, epoch, SECRET);
      } catch (e) {
        return new Response(`Decryption error: ${e.message}`, { status: 400, headers: { 'Access-Control-Allow-Origin': '*' } });
      }

      const { method, target, headers, bodyBase64 } = requestObj;
      let browser = null;
      try {
        browser = await puppeteer.launch(env.MYBROWSER);
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36');
        await page.goto(target, { waitUntil: 'domcontentloaded' });
        const renderedHtml = await page.content();
        await browser.close();
        const finalUrl = page.url();
        const responseObj = {
          status: 200,
          headers: { 'content-type': 'text/html' },
          bodyBase64: btoa(unescape(encodeURIComponent(renderedHtml))),
          finalUrl: finalUrl
        };
        const encryptedResponse = await encryptObject(responseObj, epoch, SECRET);
        return new Response(encryptedResponse, {
          status: 200,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Access-Control-Allow-Origin': '*'
          }
        });
      } catch (err) {
        if (browser) await browser.close();
        return new Response(`Browser error: ${err.message}`, { status: 502, headers: { 'Access-Control-Allow-Origin': '*' } });
      }
    }

    return new Response('Not found', { status: 404, headers: { 'Access-Control-Allow-Origin': '*' } });
  }
};
