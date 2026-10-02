// FreakDLC — сервер без зависимостей (только встроенный Node.js 18+)
// Регистрация / вход по логину и паролю, без почты. Пароли хранятся только в виде хэша (scrypt).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
// Файлы для скачивания: папка «загрузка» рядом с папкой сайта (../загрузка).
// Если её нет (залит только public) — берём public/downloads.
const DL = (() => {
  const sib = process.env.DOWNLOADS_DIR || path.join(__dirname, '..', 'загрузка');
  try { if (fs.statSync(sib).isDirectory()) return sib; } catch (e) {}
  return path.join(PUB, 'downloads');
})();
fs.mkdirSync(DATA, { recursive: true });

const UF = path.join(DATA, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(UF, 'utf8')); } catch (e) {}
const save = () => { const t = UF + '.tmp'; fs.writeFileSync(t, JSON.stringify(users)); fs.renameSync(t, UF); };

let SECRET = process.env.SECRET;
const SF = path.join(DATA, 'secret.txt');
if (!SECRET) { try { SECRET = fs.readFileSync(SF, 'utf8'); } catch (e) { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SF, SECRET); } }

const mac = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const sign = k => { const p = Buffer.from(JSON.stringify({ k, e: Date.now() + 30 * 864e5 })).toString('base64url'); return p + '.' + mac(p); };
const verify = t => {
  try {
    const [p, s] = String(t).split('.'), h = mac(p);
    if (s.length !== h.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(h))) return;
    const d = JSON.parse(Buffer.from(p, 'base64url'));
    if (d.e > Date.now() && users[d.k]) return d.k;
  } catch (e) {}
};
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64);
const DUMMY = crypto.randomBytes(16).toString('hex');

const hits = new Map();
const limited = ip => { const n = Date.now(), a = (hits.get(ip) || []).filter(t => n - t < 6e4); a.push(n); hits.set(ip, a); return a.length > 10; };

const send = (res, code, obj, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...h }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(r => { let b = ''; req.on('data', c => { b += c; if (b.length > 5e4) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(b || '{}')); } catch (e) { r({}); } }); });
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(a => a[0] && a[1]));
const setCookie = (req, v, age) => ({ 'Set-Cookie': `fd=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}` + (req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '') });

async function api(req, res, name) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const me = verify(cookies(req).fd);
  if (req.method === 'GET' && name === 'me') return send(res, 200, { user: me ? users[me].name : null });
  if (req.method === 'GET' && name === 'config') return me ? send(res, 200, { cfg: users[me].cfg || null }) : send(res, 401, { error: 'Нужен вход' });
  if (req.method !== 'POST') return send(res, 404, { error: 'Не найдено' });
  const b = await readBody(req);
  if (name === 'logout') return send(res, 200, { ok: 1 }, setCookie(req, '', 0));
  if (name === 'config') {
    if (!me) return send(res, 401, { error: 'Нужен вход' });
    users[me].cfg = b.cfg; save(); return send(res, 200, { ok: 1 });
  }
  if (name !== 'register' && name !== 'login') return send(res, 404, { error: 'Не найдено' });
  if (limited(ip)) return send(res, 429, { error: 'Слишком много попыток, подожди минуту' });
  const u = String(b.u || '').trim(), p = String(b.p || ''), k = u.toLowerCase();
  if (!/^[A-Za-z0-9_]{3,16}$/.test(u)) return send(res, 400, { error: 'Логин: 3–16 символов, латиница, цифры и _' });
  if (p.length < 6 || p.length > 64) return send(res, 400, { error: 'Пароль: от 6 до 64 символов' });
  if (name === 'register') {
    if (users[k]) return send(res, 409, { error: 'Такой логин уже занят' });
    const salt = crypto.randomBytes(16).toString('hex');
    users[k] = { name: u, salt, hash: hash(p, salt).toString('hex'), created: Date.now(), cfg: null };
    save();
    return send(res, 200, { user: u }, setCookie(req, sign(k), 30 * 86400));
  }
  const rec = users[k], h = hash(p, rec ? rec.salt : DUMMY);
  if (!rec || !crypto.timingSafeEqual(h, Buffer.from(rec.hash, 'hex'))) return send(res, 401, { error: 'Неверный логин или пароль' });
  send(res, 200, { user: rec.name }, setCookie(req, sign(k), 30 * 86400));
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.zip': 'application/zip', '.jar': 'application/java-archive', '.exe': 'application/octet-stream' };

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/api/')) return api(req, res, url.pathname.slice(5)).catch(() => send(res, 500, { error: 'Ошибка сервера' }));
  const pn = decodeURIComponent(url.pathname);
  let f;
  if (pn === '/') f = path.join(PUB, 'index.html');
  else if (pn === '/downloads' || pn.startsWith('/downloads/')) f = path.join(DL, pn.slice('/downloads'.length));
  else f = path.join(PUB, pn);
  if (!f.startsWith(PUB) && !f.startsWith(DL)) { res.writeHead(403); return res.end(); }
  fs.stat(f, (e, s) => {
    if (e || !s.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('404'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream' });
    fs.createReadStream(f).pipe(res);
  });
}).listen(PORT, () => console.log('FreakDLC: http://localhost:' + PORT + '\nСкачивания: ' + DL));
