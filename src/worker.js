import PUBLIC from './public.html';
import ADMIN from './admin.html';

const enc = new TextEncoder();
const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', ...h } });
const html = (t) => new Response(t, { headers: { 'content-type': 'text/html;charset=utf-8', 'cache-control': 'no-store' } });

async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sameSecret(a, b, key) { return (await hmac(key, a)) === (await hmac(key, b)); }

async function isAdmin(req, env) {
  const c = (req.headers.get('cookie') || '').match(/mq_session=([^;]+)/);
  if (!c) return false;
  const [exp, sig] = c[1].split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return sig === await hmac(env.SESSION_SECRET, 'session:' + exp);
}

async function fd(path, token) {
  const r = await fetch('https://api.football-data.org/v4' + path, { headers: { 'X-Auth-Token': token } });
  if (!r.ok) throw new Error('football-data.org returned ' + r.status);
  return r.json();
}

async function getFixtures(date, env) {
  const token = await env.KV.get('token');
  if (!token) return { error: 'not_configured' };
  const key = 'fx:' + date;
  const cached = await env.KV.get(key, 'json');
  if (cached) return cached;
  const data = await fd(`/matches?dateFrom=${date}&dateTo=${date}`, token);
  const matches = (data.matches || []).filter(m => m.homeTeam?.id && m.awayTeam?.id);
  const codes = [...new Set(matches.map(m => m.competition?.code).filter(Boolean))].slice(0, 6);
  const rates = {};
  for (const code of codes) {
    let st = await env.KV.get('st:' + code, 'json');
    if (!st) {
      try {
        const s = await fd(`/competitions/${code}/standings`, token);
        const total = (s.standings || []).find(x => x.type === 'TOTAL');
        st = {};
        (total?.table || []).forEach(r => { if (r.playedGames > 0) st[r.team.id] = [r.goalsFor / r.playedGames, r.goalsAgainst / r.playedGames]; });
      } catch { st = {}; }
      await env.KV.put('st:' + code, JSON.stringify(st), { expirationTtl: 43200 });
    }
    rates[code] = st;
  }
  const out = { date, fixtures: matches.map(m => {
    const r = rates[m.competition?.code] || {};
    const h = r[m.homeTeam.id], a = r[m.awayTeam.id];
    return { id: String(m.id), utc: m.utcDate, comp: m.competition?.name || '', h: m.homeTeam.shortName || m.homeTeam.name, a: m.awayTeam.shortName || m.awayTeam.name,
      hF: h ? h[0] : null, hA: h ? h[1] : null, aF: a ? a[0] : null, aA: a ? a[1] : null };
  }) };
  await env.KV.put(key, JSON.stringify(out), { expirationTtl: 3600 });
  return out;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname;

    if (p === '/') return html(PUBLIC);
    if (p === '/admin') return html(ADMIN);

    if (p === '/api/fixtures') {
      const date = url.searchParams.get('date') || '';
      const t = Date.parse(date);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(t) || Math.abs(t - Date.now()) > 8 * 864e5) return json({ error: 'bad_date' }, 400);
      try { return json(await getFixtures(date, env), 200, { 'cache-control': 'public, max-age=300' }); }
      catch (e) { return json({ error: 'upstream', message: e.message }, 502); }
    }

    if (p === '/api/admin/login' && req.method === 'POST') {
      const ip = req.headers.get('cf-connecting-ip') || 'x', rk = 'rl:' + ip;
      const tries = Number(await env.KV.get(rk)) || 0;
      if (tries >= 5) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
      const b = await req.json().catch(() => ({}));
      const ok = await sameSecret(String(b.username || ''), env.ADMIN_USER, env.SESSION_SECRET)
              && await sameSecret(String(b.password || ''), env.ADMIN_PASSWORD, env.SESSION_SECRET);
      if (!ok) { await env.KV.put(rk, String(tries + 1), { expirationTtl: 900 }); return json({ error: 'Wrong username or password.' }, 401); }
      const exp = Date.now() + 12 * 3600e3;
      const sig = await hmac(env.SESSION_SECRET, 'session:' + exp);
      return json({ ok: true }, 200, { 'set-cookie': `mq_session=${exp}.${sig}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200` });
    }
    if (p === '/api/admin/logout') return json({ ok: true }, 200, { 'set-cookie': 'mq_session=; Max-Age=0; Path=/' });

    if (p.startsWith('/api/admin/')) {
      if (!(await isAdmin(req, env))) return json({ error: 'Not logged in.' }, 401);
      if (p === '/api/admin/status') {
        const t = await env.KV.get('token');
        return json({ set: !!t, hint: t ? '…' + t.slice(-4) : null });
      }
      if (p === '/api/admin/token' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        const token = String(b.token || '').trim();
        if (!/^[A-Za-z0-9]{20,64}$/.test(token)) return json({ error: 'That does not look like a football-data.org token.' }, 400);
        try { await fd('/competitions/PL', token); } catch (e) { return json({ error: 'Token rejected: ' + e.message }, 400); }
        await env.KV.put('token', token);
        return json({ ok: true, hint: '…' + token.slice(-4) });
      }
    }
    return new Response('Not found', { status: 404 });
  }
};
