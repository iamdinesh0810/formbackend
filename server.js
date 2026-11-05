import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import nodemailer from 'nodemailer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const {
  BRAND_NAME = 'YourBrand', PUBLIC_URL = 'http://localhost:3000', PORT = 3000,
  ADMIN_USER = 'admin', ADMIN_PASSWORD = '', DB_PATH = './data/forms.db',
  SMTP_URL = '', MAIL_FROM = 'forms@localhost', MONTHLY_LIMIT = 250,
} = process.env;

if (!ADMIN_PASSWORD) { console.error('Set ADMIN_PASSWORD'); process.exit(1); }

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS forms(
  id INTEGER PRIMARY KEY, name TEXT, api_key TEXT UNIQUE, to_email TEXT,
  allowed_domains TEXT DEFAULT '', redirect_url TEXT DEFAULT '', webhook_url TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS submissions(
  id INTEGER PRIMARY KEY, form_id INTEGER, data TEXT, ip_hash TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_sub_form ON submissions(form_id, created_at);
`);

const mailer = SMTP_URL ? nodemailer.createTransport(SMTP_URL) : null;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// IPs are stored only as a salted hash (data minimisation, helps with nDSG/GDPR)
const SALT = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');
const hashIp = ip => crypto.createHash('sha256').update(SALT + ip).digest('hex').slice(0, 16);

const app = express();
app.set('trust proxy', 1);

// ---------- public submit endpoint ----------
const hits = new Map(); // ip -> timestamps (simple in-memory rate limit)
function rateLimited(ip, max = 5, windowMs = 60_000) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < windowMs);
  arr.push(now); hits.set(ip, arr);
  return arr.length > max;
}
setInterval(() => hits.clear(), 10 * 60_000).unref();

app.use('/submit', (req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, X-API-Key' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.post('/submit', express.urlencoded({ extended: true, limit: '100kb' }), express.json({ limit: '100kb' }), async (req, res) => {
  const wantsHtml = (req.get('accept') || '').includes('text/html');
  const fail = (code, msg) => wantsHtml
    ? res.status(code).send(`<!doctype html><meta charset=utf-8><body style="font-family:sans-serif;max-width:32rem;margin:4rem auto"><h2>${esc(msg)}</h2><p><a href="javascript:history.back()">Back</a></p>`)
    : res.status(code).json({ ok: false, error: msg });

  const body = { ...(req.body || {}) };
  const key = body.apiKey || req.get('x-api-key');
  delete body.apiKey;
  const form = key && db.prepare('SELECT * FROM forms WHERE api_key=?').get(String(key));
  if (!form) return fail(400, 'Invalid API key');

  if (rateLimited(req.ip)) return fail(429, 'Too many requests, please try again shortly');

  if (form.allowed_domains) {
    const origin = req.get('origin') || req.get('referer') || '';
    let host = ''; try { host = new URL(origin).hostname; } catch {}
    const ok = form.allowed_domains.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
      .some(d => host === d || host.endsWith('.' + d));
    if (!ok) return fail(403, 'Domain not allowed');
  }

  const redirect = body._redirect || form.redirect_url;
  const honeypot = body._gotcha;
  delete body._redirect; delete body._gotcha;

  const finish = () => (redirect && wantsHtml)
    ? res.redirect(303, redirect)
    : wantsHtml ? res.send(`<!doctype html><meta charset=utf-8><body style="font-family:sans-serif;max-width:32rem;margin:4rem auto"><h2>Thank you!</h2><p>Your message was sent.</p>`)
    : res.json({ ok: true });

  if (honeypot) return finish(); // bots think they succeeded; nothing is stored

  const { c } = db.prepare("SELECT COUNT(*) c FROM submissions WHERE form_id=? AND created_at > datetime('now','-30 days')").get(form.id);
  if (c >= Number(MONTHLY_LIMIT)) return fail(429, 'Monthly submission limit reached');

  if (!Object.keys(body).length) return fail(400, 'Empty submission');

  db.prepare('INSERT INTO submissions(form_id,data,ip_hash) VALUES(?,?,?)').run(form.id, JSON.stringify(body), hashIp(req.ip));
  finish();
  deliver(form, body).catch(e => console.error('delivery error', e.message));
});

async function deliver(form, data) {
  const text = Object.entries(data).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n');
  if (form.to_email) {
    const mail = { from: `"${BRAND_NAME}" <${MAIL_FROM}>`, to: form.to_email, subject: `New submission: ${form.name}`, text };
    const replyTo = typeof data.email === 'string' && /^[^@\s]+@[^@\s]+$/.test(data.email) ? data.email : null;
    if (replyTo) mail.replyTo = replyTo;
    if (mailer) await mailer.sendMail(mail); else console.log('[email disabled]', mail);
  }
  if (form.webhook_url) {
    await fetch(form.webhook_url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ form: form.name, submittedAt: new Date().toISOString(), data }), signal: AbortSignal.timeout(8000) });
  }
}

// ---------- admin dashboard ----------
function auth(req, res, next) {
  const [u, p] = Buffer.from((req.get('authorization') || '').split(' ')[1] || '', 'base64').toString().split(/:(.*)/s);
  const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
  if (u !== undefined && eq(u, ADMIN_USER) && eq(p, ADMIN_PASSWORD)) return next();
  res.set('WWW-Authenticate', 'Basic realm="Admin"').sendStatus(401);
}
const page = (title, inner) => `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title)} · ${esc(BRAND_NAME)}</title><style>
body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top}
input{padding:.4rem;margin:.2rem 0;width:100%;box-sizing:border-box}button{padding:.5rem 1rem;cursor:pointer}
pre{background:#f4f4f4;padding:1rem;overflow:auto}.row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
</style></head><body><h1><a href="/admin" style="text-decoration:none;color:inherit">${esc(BRAND_NAME)}</a></h1>${inner}</body></html>`;

app.use('/admin', auth, express.urlencoded({ extended: false }));

app.get('/admin', (req, res) => {
  const forms = db.prepare(`SELECT f.*, (SELECT COUNT(*) FROM submissions s WHERE s.form_id=f.id) n FROM forms f ORDER BY id DESC`).all();
  res.send(page('Forms', `
  <h2>Your forms</h2>
  <table><tr><th>Name</th><th>Sends to</th><th>Submissions</th></tr>
  ${forms.map(f => `<tr><td><a href="/admin/forms/${f.id}">${esc(f.name)}</a></td><td>${esc(f.to_email)}</td><td>${f.n}</td></tr>`).join('') || '<tr><td colspan=3>No forms yet</td></tr>'}</table>
  <h2>New form</h2>
  <form method=post action=/admin/forms>
  <div class=row><label>Name<input name=name required></label><label>Notify email<input name=to_email type=email required></label></div>
  <div class=row><label>Allowed domains (comma-separated, optional)<input name=allowed_domains placeholder="example.ch"></label>
  <label>Redirect URL after submit (optional)<input name=redirect_url type=url></label></div>
  <label>Webhook URL (optional)<input name=webhook_url type=url></label><br><br><button>Create form</button></form>`));
});

app.post('/admin/forms', (req, res) => {
  const b = req.body, key = 'sf_' + crypto.randomBytes(16).toString('hex');
  const r = db.prepare('INSERT INTO forms(name,api_key,to_email,allowed_domains,redirect_url,webhook_url) VALUES(?,?,?,?,?,?)')
    .run(b.name, key, b.to_email, b.allowed_domains || '', b.redirect_url || '', b.webhook_url || '');
  res.redirect(`/admin/forms/${r.lastInsertRowid}`);
});

app.get('/admin/forms/:id', (req, res) => {
  const f = db.prepare('SELECT * FROM forms WHERE id=?').get(req.params.id);
  if (!f) return res.sendStatus(404);
  const subs = db.prepare('SELECT * FROM submissions WHERE form_id=? ORDER BY id DESC LIMIT 200').all(f.id);
  const snippet = `<form action="${PUBLIC_URL}/submit" method="POST">
  <input type="hidden" name="apiKey" value="${f.api_key}">
  <input type="text" name="_gotcha" style="display:none" tabindex="-1" autocomplete="off">
  <input type="text" name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <button type="submit">Send</button>
</form>`;
  res.send(page(f.name, `
  <h2>${esc(f.name)}</h2><p>Notifies <b>${esc(f.to_email)}</b> · <a href="/admin/forms/${f.id}/export.csv">Export CSV</a></p>
  <h3>Embed code</h3><pre>${esc(snippet)}</pre>
  <h3>Submissions (${subs.length})</h3>
  <table><tr><th>Date</th><th>Data</th></tr>${subs.map(s => `<tr><td>${esc(s.created_at)}</td><td>${
    Object.entries(JSON.parse(s.data)).map(([k, v]) => `<b>${esc(k)}</b>: ${esc(typeof v === 'object' ? JSON.stringify(v) : v)}`).join('<br>')}</td></tr>`).join('') || '<tr><td colspan=2>None yet</td></tr>'}</table>
  <form method=post action="/admin/forms/${f.id}/delete" onsubmit="return confirm('Delete form and all submissions?')"><br><button>Delete form</button></form>`));
});

app.get('/admin/forms/:id/export.csv', (req, res) => {
  const rows = db.prepare('SELECT created_at, data FROM submissions WHERE form_id=? ORDER BY id').all(req.params.id).map(r => ({ created_at: r.created_at, ...JSON.parse(r.data) }));
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  // prefix risky leading chars to prevent spreadsheet formula injection
  const cell = v => { let s = typeof v === 'object' ? JSON.stringify(v ?? '') : String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  res.type('text/csv').send([cols.join(','), ...rows.map(r => cols.map(c => cell(r[c])).join(','))].join('\n'));
});

app.post('/admin/forms/:id/delete', (req, res) => {
  db.prepare('DELETE FROM submissions WHERE form_id=?').run(req.params.id);
  db.prepare('DELETE FROM forms WHERE id=?').run(req.params.id);
  res.redirect('/admin');
});

app.get('/', (_, res) => res.send(page('Home', `<p>Form backend. <a href="/admin">Admin</a></p>`)));
app.get('/healthz', (_, res) => res.send('ok'));

app.listen(PORT, () => console.log(`${BRAND_NAME} listening on :${PORT}`));
