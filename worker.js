// Connect Pay worker: stands between a Solana badge and Quidli Connect.
//
// The badge holds no key. Every request it makes arrives signed by the badge
// server, saying which badge and which app sent it. This worker checks that
// signature, lets only the badges you list through, enforces the caps below,
// and calls Connect with a key that never leaves your Cloudflare account.
//
// Settings, both secrets (the Deploy to Cloudflare button asks for them):
//   CONNECT_API_KEY  your Connect API key (connect.quid.li, Enable API access)
//   BADGE_IDS        the badges allowed to pay, e.g. "7K2Q9M" or "7K2Q9M,4HX2PD"
// Optional var APP_ID: the badge app's id, only if you publish the app under
// another id (default "connect-pay").

const CONNECT = 'https://api.connect.quid.li';
const BADGE_SERVER = 'https://badge-api.solana.com';

// What a badge may send. `token` is null for a chain's native token; `max` is
// the most one payment may be. The badge reads this list from GET /assets, so
// changing it here is all it takes. Chain ids: GET https://api.connect.quid.li/chains
export const ASSETS = [
  { id: 'usdc-sol', label: 'USDC', chain: 'Solana', chainId: 1399811149, dec: 6,
    token: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    max: '5', amounts: ['0.10', '0.50', '1', '2', '5'] },
  { id: 'sol', label: 'SOL', chain: 'Solana', chainId: 1399811149, dec: 9, token: null,
    max: '0.05', amounts: ['0.001', '0.005', '0.01', '0.05'] },
  { id: 'eth-base', label: 'ETH', chain: 'Base', chainId: 8453, dec: 18, token: null,
    max: '0.002', amounts: ['0.0001', '0.0005', '0.001'] },
];

// The badge gives up after 6 s, so Connect gets a little less than that.
const CONNECT_TIMEOUT_MS = 4500;

// ---------------------------------------------------------------------------
// Who is calling: the badge server's signature (LUA_API.md, "What your server
// receives").

const keys = new Map(); // X-Badge-Key id -> CryptoKey
const seen = new Map(); // X-Badge-Request -> time, for a minute
let fetching = null;
let fetchedAt = 0;

async function badgeKey(id) {
  if (!keys.has(id) && !fetching && Date.now() - fetchedAt > 60_000) {
    fetchedAt = Date.now();
    fetching = (async () => {
      const k = await (await fetch(`${BADGE_SERVER}/api/http/key`)).json();
      const raw = Uint8Array.from(atob(k.key), (c) => c.charCodeAt(0));
      keys.set(k.id, await crypto.subtle.importKey('raw', raw, 'Ed25519', false, ['verify']));
    })()
      .catch(() => { fetchedAt = 0; })
      .finally(() => { fetching = null; });
  }
  if (!keys.has(id) && fetching) await fetching;
  return keys.get(id) ?? null;
}

function once(id, time) {
  for (const [k, t] of seen) if (Date.now() - t > 60_000) seen.delete(k);
  if (seen.has(id)) return false;
  seen.set(id, time);
  return true;
}

/** The badge behind a request from the app, or null when it can't be trusted. */
async function fromBadge(req, body, app) {
  const h = (n) => req.headers.get(n) ?? '';
  const time = Number(h('x-badge-time'));
  const id = h('x-badge-request');
  if (h('x-badge-app') !== app || !(Math.abs(Date.now() - time) < 60_000) || !id) return null;
  const key = await badgeKey(h('x-badge-key'));
  if (!key) return null;
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
  const signed = ['badge-http-v1', req.method, req.url,
    [...hash].map((b) => b.toString(16).padStart(2, '0')).join(''),
    app, h('x-badge-id'), h('x-badge-user'), h('x-badge-time'), id].join('\n');
  let sig;
  try {
    sig = Uint8Array.from(atob(h('x-badge-signature')), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
  if (!(await crypto.subtle.verify('Ed25519', key, sig, new TextEncoder().encode(signed)))) return null;
  if (!once(id, time)) return null; // a replay
  return { badge: h('x-badge-id'), user: h('x-badge-user') };
}

// ---------------------------------------------------------------------------
// Amounts, as strings of digits: token amounts go past what a double holds.

/** "1.5", 6 -> "1500000", or null when the text isn't a positive amount. */
export function toUnits(text, dec) {
  const m = typeof text === 'string' && /^(\d*)(?:\.(\d+))?$/.exec(text);
  if (!m || (m[1] === '' && m[2] === undefined)) return null;
  const frac = m[2] ?? '';
  if (frac.length > dec) return null;
  const units = (m[1] + frac + '0'.repeat(dec - frac.length)).replace(/^0+/, '');
  return units === '' ? null : units;
}

const over = (a, b) => a.length !== b.length ? a.length > b.length : a > b;

// ---------------------------------------------------------------------------

// Answers to the badge: 200 with a result, or 4xx with {text} when the worker
// refused the request before doing anything. The app treats a 5xx as "no
// final answer", so the worker itself never answers with one.
const json = (status, data) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json' },
});

/** Connect's own words for an error answer, if it sent any. */
function said(data, status) {
  let m = data?.message;
  if (Array.isArray(m)) m = m[0];
  if (typeof m !== 'string' || !m) m = data?.error;
  return typeof m === 'string' && m ? m : `Connect answered ${status}`;
}

/** { status, data } for any answer from Connect, null when there was none in time. */
async function connect(env, method, path, body) {
  const headers = { accept: 'application/json', 'x-api-key': env.CONNECT_API_KEY };
  if (body) headers['content-type'] = 'application/json';
  try {
    const res = await fetch(CONNECT + path, {
      method, headers, body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(CONNECT_TIMEOUT_MS),
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data: data && typeof data === 'object' ? data : {} };
  } catch {
    return null;
  }
}

// GET /score/<handle>: a handle's social reputation, cut down to what the badge shows.
async function score(env, handle) {
  if (!/^\w{1,15}$/.test(handle)) return json(400, { text: "That isn't an X handle" });
  const r = await connect(env, 'GET', `/scores/twitter/${handle}`);
  if (!r) return json(200, { text: "Connect didn't answer in time." });
  if (r.status !== 200) return json(200, { text: said(r.data, r.status) });
  const lines = [];
  for (const group of [r.data.categories?.socials, r.data.categories?.wallets]) {
    for (const s of Array.isArray(group) ? group : []) {
      if (lines.length < 3 && s?.label) lines.push(`${String(s.label).slice(0, 40)}: ${s.value}`);
    }
  }
  return json(200, { score: r.data.quidliScore ?? null, lines });
}

// POST /pay {id, handle, asset, amount}. The answer's `state` tells the badge
// what to do with the payment it saved:
//   sent        done
//   processing  nothing sent yet, ask again shortly with the same id
//   failed      this request sent nothing
//   unknown     no final answer: it may have gone through, retry with the same id
async function pay(env, body) {
  let p;
  try { p = JSON.parse(body); } catch { p = null; }
  const failed = (text) => json(200, { state: 'failed', text });
  if (!p || typeof p !== 'object') return failed('Bad request');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(p.id ?? '')) return failed('Bad payment id');
  if (!/^\w{1,15}$/.test(p.handle ?? '')) return failed("That isn't an X handle");
  const a = ASSETS.find((x) => x.id === p.asset);
  if (!a) return failed('This worker does not offer that asset');
  const units = toUnits(p.amount, a.dec);
  if (!units) return failed('Not an amount');
  if (over(units, toUnits(a.max, a.dec))) return failed(`Most per payment: ${a.max} ${a.label}`);

  const drop = {
    idempotencyKey: p.id,
    chainId: a.chainId,
    recipients: [{ type: 'twitter', username: p.handle }],
    amountInWeiPerRecipient: units,
  };
  if (a.token) drop.tokenContract = a.token;
  const r = await connect(env, 'POST', '/drop', drop);
  if (!r) return json(200, { state: 'unknown', text: "Connect didn't answer in time." });
  if (r.status === 200 || r.status === 201) return json(200, { state: 'sent' });
  if (r.status === 202) return json(200, { state: 'processing' });
  if (r.status >= 500) return json(200, { state: 'unknown', text: said(r.data, r.status) });
  if (r.status === 401 || r.status === 403) return failed("Connect refused the worker's API key.");
  return failed(said(r.data, r.status));
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') {
      return new Response('Connect Pay worker. It answers signed requests from the badge app only.\n');
    }
    const body = req.method === 'POST' ? await req.text() : '';
    if (body.length > 2048) return json(413, { text: 'Request too big' });

    const who = await fromBadge(req, body, env.APP_ID || 'connect-pay');
    if (!who) return json(401, { text: 'Not a signed request from the badge app.' });
    const allowed = (env.BADGE_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (!allowed.includes(who.badge)) {
      return json(403, { text: `Badge ${who.badge} isn't on this worker's list (BADGE_IDS).` });
    }
    if (!env.CONNECT_API_KEY) return json(403, { text: 'The worker has no CONNECT_API_KEY yet.' });

    if (req.method === 'GET' && url.pathname === '/assets') {
      return json(200, { assets: ASSETS.map(({ id, label, chain, dec, max, amounts }) => ({ id, label, chain, dec, max, amounts })) });
    }
    if (req.method === 'GET' && url.pathname.startsWith('/score/')) {
      return score(env, url.pathname.slice('/score/'.length));
    }
    if (req.method === 'POST' && url.pathname === '/pay') return pay(env, body);
    return json(404, { text: 'No such path' });
  },
};
