// Innermost daily nudge sender.
// Deploy as its OWN Cloudflare Worker (not a Pages Function -- Pages doesn't
// support Cron Triggers). Bind the SAME KV namespace used by subscribe.js
// as PUSH_SUBS, and set two secrets: VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY
// (same values used in innermost.html and generated alongside this file).
// Set a Cron Trigger of "*/15 * * * *" (every 15 minutes) in the Worker's
// Triggers tab in the Cloudflare dashboard.

const TIME_TO_HOUR = { morning: 8, afternoon: 14, evening: 19 };
const NUDGE_TITLE = 'Innermost';
const NUDGE_BODY = "Anything good happen today? Make sure you log it in Innermost.";

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runNudgeSweep(env));
  },
  // lets you trigger a manual test via a plain HTTP request during setup
  async fetch(request, env) {
    await runNudgeSweep(env);
    return new Response('Sweep complete.');
  }
};

async function runNudgeSweep(env) {
  const list = await env.PUSH_SUBS.list({ prefix: 'sub:' });
  for (const key of list.keys) {
    const raw = await env.PUSH_SUBS.get(key.name);
    if (!raw) continue;
    let record;
    try { record = JSON.parse(raw); } catch (e) { continue; }

    const targetHour = TIME_TO_HOUR[record.time] ?? 19;
    const tz = record.tz || 'UTC';
    let localHour, localDateStr;
    try {
      const fmt = new Intl.DateTimeFormat('en-CA', { timeZone: tz, hour: 'numeric', hour12: false, year: 'numeric', month: '2-digit', day: '2-digit' });
      const parts = fmt.formatToParts(new Date());
      localHour = parseInt(parts.find(p => p.type === 'hour').value, 10) % 24;
      localDateStr = `${parts.find(p=>p.type==='year').value}-${parts.find(p=>p.type==='month').value}-${parts.find(p=>p.type==='day').value}`;
    } catch (e) {
      continue; // bad/unknown timezone string, skip rather than guess
    }

    if (localHour !== targetHour) continue;
    if (record.lastSentDate === localDateStr) continue; // already sent today

    try {
      await sendWebPush(record.subscription, { title: NUDGE_TITLE, body: NUDGE_BODY }, env);
      record.lastSentDate = localDateStr;
      await env.PUSH_SUBS.put(key.name, JSON.stringify(record));
    } catch (err) {
      if (err && (err.status === 404 || err.status === 410)) {
        // subscription expired or was revoked -- clean it up
        await env.PUSH_SUBS.delete(key.name);
      }
      // other errors: leave the record as-is, try again next sweep
    }
  }
}

// ---------------- Web Push (RFC 8291 / RFC 8292) ----------------
function b64url(buf) {
  let str = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

async function importVapidPrivateKey(privB64url, pubB64url) {
  const priv = b64urlDecode(privB64url);
  const pub = b64urlDecode(pubB64url);
  const x = pub.slice(1, 33), y = pub.slice(33, 65);
  const jwk = { kty: 'EC', crv: 'P-256', d: b64url(priv), x: b64url(x), y: b64url(y), ext: true };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
async function makeVapidJWT(endpoint, vapidPrivB64, vapidPubB64, subjectEmail) {
  const origin = new URL(endpoint).origin;
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud: origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: `mailto:${subjectEmail}` };
  const signingInput = b64url(new TextEncoder().encode(JSON.stringify(header))) + '.' + b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await importVapidPrivateKey(vapidPrivB64, vapidPubB64);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(signingInput));
  return signingInput + '.' + b64url(new Uint8Array(sig));
}

async function hkdfExtract(saltBytes, ikmBytes) {
  const key = await crypto.subtle.importKey('raw', saltBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, ikmBytes);
  return new Uint8Array(sig);
}
async function hkdfExpand(prk, info, length) {
  const key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const input = concat(info, new Uint8Array([1]));
  const sig = await crypto.subtle.sign('HMAC', key, input);
  return new Uint8Array(sig).slice(0, length);
}

async function encryptPayload(payloadObj, subscription) {
  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));
  const uaPublicRaw = b64urlDecode(subscription.keys.p256dh);
  const authSecret = b64urlDecode(subscription.keys.auth);

  const uaPublicKey = await crypto.subtle.importKey('raw', uaPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const asKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', asKeyPair.publicKey));

  const sharedSecretBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: uaPublicKey }, asKeyPair.privateKey, 256);
  const ecdhSecret = new Uint8Array(sharedSecretBits);

  const prkKey = await hkdfExtract(authSecret, ecdhSecret);
  const keyInfo = concat(new TextEncoder().encode('WebPush: info\0'), uaPublicRaw, asPublicRaw);
  const ikm = await hkdfExpand(prkKey, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hkdfExtract(salt, ikm);
  const cek = await hkdfExpand(prk, new TextEncoder().encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdfExpand(prk, new TextEncoder().encode('Content-Encoding: nonce\0'), 12);

  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const recordPad = concat(plaintext, new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cekKey, recordPad));

  const recordSize = new Uint8Array(4);
  new DataView(recordSize.buffer).setUint32(0, 4096);
  const keyIdLen = new Uint8Array([asPublicRaw.length]);
  const header = concat(salt, recordSize, keyIdLen, asPublicRaw);
  return concat(header, ciphertext);
}

async function sendWebPush(subscription, payloadObj, env) {
  const body = await encryptPayload(payloadObj, subscription);
  const jwt = await makeVapidJWT(subscription.endpoint, env.VAPID_PRIVATE_KEY, env.VAPID_PUBLIC_KEY, 'support@innermost.app');
  const res = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`
    },
    body
  });
  if (!res.ok) {
    const err = new Error('Push send failed: ' + res.status);
    err.status = res.status;
    throw err;
  }
}
