// Connect Pay worker: stands between a Solana badge and Quidli Connect.
//
// The badge holds no key. Every request it makes arrives signed by the badge
// server, saying which badge and which app sent it. This worker checks that
// signature, lets only your badges through, and calls Connect with a key that
// never leaves your Cloudflare account.
//
// Settings, both secrets (the Deploy to Cloudflare button asks for them):
//   CONNECT_API_KEY  your Connect API key (connect.quid.li, Enable API access)
//   BADGE_IDS        the badges allowed to pay, e.g. "7K2Q9M" or "7K2Q9M,4HX2PD"
// Optional var APP_ID: the badge app's id, only if you publish the app under
// another id (default "connect-pay").

const CONNECT = 'https://api.connect.quid.li';
const BADGE_SERVER = 'https://badge-api.solana.com';
const SOLANA = 1399811149; // Connect's chain id for Solana mainnet

// The badge offers whatever your Connect wallet holds on Solana: SOL and any SPL
// token. To offer a token, send some to the wallet. Some SOL is always kept
// back, because every send pays a fee in SOL (and a token sent to someone new
// pays about 0.002 SOL to open their token account).
const SOL_KEEP = 10_000_000n;  // 0.01 SOL, never offered
const SOL_MIN = 1_000_000n;    // 0.001 SOL, the smallest SOL payment (a new account needs 0.00089)
const MAX_ASSETS = 8;          // the badge's list stays short

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

/** "1500000", 6 -> "1.5" */
export function fromUnits(units, dec) {
  if (dec === 0) return units;
  const s = units.padStart(dec + 1, '0');
  const frac = s.slice(-dec).replace(/0+$/, '');
  return s.slice(0, -dec) + (frac ? '.' + frac : '');
}

/** Up to four round amounts (1, 2 or 5 times a power of ten) from `min` to `max`, smallest first. */
export function quickPicks(max, min) {
  const out = [];
  for (let p = 1n; p <= max; p *= 10n) {
    for (const m of [1n, 2n, 5n]) if (m * p <= max && m * p >= min) out.push(m * p);
  }
  return out.slice(-4);
}

const MINT = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/; // a Solana address, base58

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

// What the badge's font can draw: Connect writes X as "𝕏", and labels may hold other symbols.
const plain = (v) => String(v ?? '').replace(/𝕏/gu, 'X').replace(/[^\x20-\x7e]/g, '').replace(/\s+/g, ' ').trim();

/** "X reputation: 1985 (reputable)" from one of Connect's score entries. */
export function scoreLine(s) {
  const ref = typeof s.reference === 'string' && s.reference !== String(s.value) ? plain(s.reference) : '';
  return `${plain(s.label).slice(0, 40)}: ${plain(s.value)}${ref ? ` (${ref.slice(0, 20)})` : ''}`;
}

// GET /score/<handle>: a handle's social reputation, cut down to what the badge shows.
// `score` is the Quidli score, null for someone who isn't a Connect member; `lines`
// are what Connect knows anyway (an X reputation from Ethos, say).
async function score(env, handle) {
  if (!/^\w{1,15}$/.test(handle)) return json(400, { text: "That isn't an X handle" });
  const r = await connect(env, 'GET', `/scores/twitter/${handle}`);
  if (!r) return json(200, { text: "Connect didn't answer in time." });
  if (r.status !== 200) return json(200, { text: said(r.data, r.status) });
  const lines = [];
  for (const group of [r.data.categories?.socials, r.data.categories?.wallets]) {
    for (const s of Array.isArray(group) ? group : []) {
      if (lines.length < 3 && s?.label) lines.push(scoreLine(s));
    }
  }
  return json(200, { score: r.data.quidliScore ?? null, lines });
}

// GET /assets: what the wallet can send now, as the badge shows it. `max` is
// the most one payment can be: the wallet's balance, less the SOL kept for fees.
// `wallet` is the wallet's Solana address, which the badge shows as a QR code
// to top it up (sent with an empty list too: that's when it's needed most).
async function assets(env) {
  const r = await connect(env, 'GET', `/drop/balance?chainId=${SOLANA}`);
  if (!r) return json(200, { text: "Connect didn't answer in time." });
  if (r.status === 401 || r.status === 403) return json(200, { text: "Connect refused the worker's API key." });
  if (r.status !== 200) return json(200, { text: said(r.data, r.status) });
  const wallet = MINT.test(r.data.walletAddress ?? '') ? { wallet: r.data.walletAddress } : {};
  const list = [];
  for (const x of Array.isArray(r.data.assets) ? r.data.assets : []) {
    const native = x?.type === 'native';
    const dec = x?.decimals;
    if (!Number.isInteger(dec) || dec < 0 || dec > 30 || !/^\d{1,40}$/.test(x.balanceInWei ?? '')) continue;
    if (!native && !MINT.test(x.tokenContract ?? '')) continue;
    const max = BigInt(x.balanceInWei) - (native ? SOL_KEEP : 0n);
    const min = native ? SOL_MIN : 1n;
    if (max < min) continue;
    const symbol = String(x.symbol ?? '').replace(/[^\x20-\x7e]/g, '').trim().slice(0, 10);
    const a = {
      id: native ? 'sol' : x.tokenContract,
      label: symbol || (native ? 'SOL' : x.tokenContract.slice(0, 4) + '..'),
      chain: 'Solana',
      dec,
      max: fromUnits(String(max), dec),
      amounts: quickPicks(max, min).map((u) => fromUnits(String(u), dec)),
    };
    if (native) list.unshift(a); else list.push(a);
  }
  if (!list.length) return json(200, { text: 'The Connect wallet has nothing to send on Solana yet. Add some SOL first.', ...wallet });
  return json(200, { assets: list.slice(0, MAX_ASSETS), ...wallet });
}

// POST /pay {id, handle, asset, units}: `asset` is "sol" or a token's mint
// address, `units` the amount in the token's smallest unit (the badge has the
// decimals from /assets). The answer's `state` tells the badge what to do with
// the payment it saved:
//   sent        done
//   processing  nothing sent yet, ask again shortly with the same id
//   failed      this request sent nothing
//   unknown     no final answer: it may have gone through, retry with the same id
async function pay(env, body) {
  let p;
  try { p = JSON.parse(body); } catch { p = null; }
  const failed = (text) => json(200, { state: 'failed', text });
  if (!p || typeof p !== 'object') return failed('Bad request');
  if (typeof p.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(p.id)) return failed('Bad payment id');
  if (typeof p.handle !== 'string' || !/^\w{1,15}$/.test(p.handle)) return failed("That isn't an X handle");
  const sol = p.asset === 'sol';
  if (!sol && !(typeof p.asset === 'string' && MINT.test(p.asset))) return failed('Not a token');
  if (!(typeof p.units === 'string' && /^[1-9]\d{0,39}$/.test(p.units))) return failed('Not an amount');
  if (sol && BigInt(p.units) < SOL_MIN) return failed('The smallest SOL payment is 0.001 SOL.');

  const drop = {
    idempotencyKey: p.id,
    chainId: SOLANA,
    recipients: [{ type: 'twitter', username: p.handle }],
    amountInWeiPerRecipient: p.units,
  };
  if (!sol) drop.tokenContract = p.asset;
  const r = await connect(env, 'POST', '/drop', drop);
  if (!r) return json(200, { state: 'unknown', text: "Connect didn't answer in time." });
  if (r.status === 200 || r.status === 201) return json(200, { state: 'sent' });
  if (r.status === 202) return json(200, { state: 'processing' });
  if (r.status >= 500) return json(200, { state: 'unknown', text: said(r.data, r.status) });
  if (r.status === 401 || r.status === 403) return failed("Connect refused the worker's API key.");
  const text = said(r.data, r.status);
  // Connect's "Insufficient funds" on a token send is often the SOL for fees.
  if (!sol && /insufficient/i.test(text)) return failed(`${text}. Sending a token also takes about 0.002 SOL in fees.`);
  return failed(text);
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

    if (req.method === 'GET' && url.pathname === '/assets') return assets(env);
    if (req.method === 'GET' && url.pathname.startsWith('/score/')) {
      return score(env, url.pathname.slice('/score/'.length));
    }
    if (req.method === 'POST' && url.pathname === '/pay') return pay(env, body);
    return json(404, { text: 'No such path' });
  },
};
