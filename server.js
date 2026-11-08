#!/usr/bin/env node
'use strict';
/* Защищённый сервер: вход по логину и паролю, права проверяются на сервере, пароли только в виде хэшей.
   Запуск: node server.js   (PORT=3000, HOST=127.0.0.1 если стоит за nginx/caddy, DATA_FILE=data.json, TRUST_PROXY=1 за прокси) */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os');
const PORT = +process.env.PORT || 3000;
const DIR = __dirname;
const DATA = process.env.DATA_FILE || path.join(DIR, 'data.json');
const BACK = path.join(path.dirname(DATA), 'backups');
const TRUST = process.env.TRUST_PROXY === '1';
const OWNER = 'Владелец';
const ARR = ['orders','parts','phones','acc','accSales','stockSales','cash','staff','contacts','suppliers','services','adjust','log','returns','writeoffs','cancellations'];
const FLOOR = {orders:'nextId', cash:'nextCash', staff:'nextStaff'};
const SESSION_MS = 30 * 864e5, OV_MS = 300e3;
const SCHEMA = 1;   // версия структуры данных
const MIGRATIONS = [  // MIGRATIONS[n] переводит данные с версии n на n+1. Новые изменения структуры добавляются сюда.
  (state, d) => {}    // 0 -> 1: структура не менялась
];

let db = {rev:0, state:null, counters:{nextId:1001, nid:100000, nextCash:1, nextStaff:2}, users:{}, pin:null, sessions:{}};
if (fs.existsSync(DATA)) {
  try { db = Object.assign(db, JSON.parse(fs.readFileSync(DATA, 'utf8'))); }
  catch (e) {
    console.error('\nОШИБКА: файл данных ' + DATA + ' повреждён и не читается.');
    console.error('Сервер НЕ запущен, чтобы не затереть данные. Скопируйте этот файл в безопасное место,');
    console.error('затем скопируйте последнюю копию из папки backups на место data.json и запустите снова.\n');
    process.exit(1);
  }
}
if (db.state) (db.state.staff || []).forEach(m => { delete m.pass; delete m._pw; });
const mem = {};           // временные данные сессий (окно подтверждения кодом, неудачные попытки)
const fails = new Map();  // ограничение попыток входа

/* ---------- сохранение ---------- */
let timer = null, lastBackup = 0;
function save() { clearTimeout(timer); timer = setTimeout(saveNow, 300); }
function saveNow() {
  try {
    fs.mkdirSync(path.dirname(DATA), {recursive:true});
    const tmp = DATA + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db), {mode:0o600});
    fs.renameSync(tmp, DATA);
    backup();
  } catch (e) { console.error('Ошибка сохранения:', e.message); }
}
function backup() {
  const now = Date.now();
  if (now - lastBackup < 3600e3 || !db.state) return;
  lastBackup = now;
  try {
    fs.mkdirSync(BACK, {recursive:true});
    const iso = new Date().toISOString();
    fs.copyFileSync(DATA, path.join(BACK, 'data-' + iso.slice(0,13).replace('T','-') + '.json'));
    const day = path.join(BACK, 'daily-' + iso.slice(0,10) + '.json');
    if (!fs.existsSync(day)) fs.copyFileSync(DATA, day);
    const prune = (prefix, keep) => { const f = fs.readdirSync(BACK).filter(x => x.startsWith(prefix)).sort(); while (f.length > keep) fs.unlinkSync(path.join(BACK, f.shift())); };
    prune('data-', 72); prune('daily-', 60);
  } catch (e) {}
}

/* ---------- пароли, сессии ---------- */
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
function makeHash(pw) { const salt = crypto.randomBytes(16).toString('hex'); return {salt, hash: hashPw(pw, salt)}; }
function checkHash(rec, pw) {
  if (!rec) return false;
  const a = Buffer.from(hashPw(pw, rec.salt), 'hex'), b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const th = t => crypto.createHash('sha256').update(String(t)).digest('hex');
function newSession(uid) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[th(token)] = {uid, exp: Date.now() + SESSION_MS};
  save(); return token;
}
function session(req) {
  const t = req.headers['x-auth']; if (!t || !db.state) return null;
  const h = th(t), s = db.sessions[h];
  if (!s) return null;
  if (s.exp < Date.now()) { delete db.sessions[h]; return null; }
  const user = db.state.staff.find(m => m.id === s.uid && !m.off);
  if (!user) return null;
  if (s.exp - Date.now() < SESSION_MS - 3600e3) { s.exp = Date.now() + SESSION_MS; save(); }
  return {h, s, user, m: mem[h] || (mem[h] = {})};
}
function ipOf(req) {
  if (TRUST) { const x = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(); if (x) return x; }
  return req.socket.remoteAddress || '?';
}
function locked(key) { const f = fails.get(key); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 60000) : 0; }
function addFail(key, limit, lockMs) {
  const now = Date.now(), f = fails.get(key) || {arr:[], until:0};
  f.arr = f.arr.filter(t => now - t < 600e3); f.arr.push(now);
  if (f.arr.length >= limit) { f.until = now + lockMs; f.arr = []; }
  fails.set(key, f);
}
function serverLog(act, kind, who, whoId) {
  if (!db.state) return;
  (db.state.log || (db.state.log = [])).unshift({id: db.counters.nid++, ts: Date.now(), who: who || 'Система', whoId: whoId || 0, act, kind: kind || 'warn'});
  db.rev++; save();
}

/* ---------- данные: что видит каждый ---------- */
function view(u) {
  const s = db.state, out = {};
  ARR.forEach(k => out[k] = s[k] || []);
  out.set = s.set || {}; out.pinSet = !!db.pin;
  if (u.role === OWNER) return out;
  out.log = [];
  out.adjust = (s.adjust || []).filter(a => a.staffId === u.id);
  out.staff = (s.staff || []).map(m => m.id === u.id ? m : {id:m.id, name:m.name, role:m.role, roleTitle:m.roleTitle, off:m.off});
  return out;
}

/* ---------- права сотрудников (проверка на сервере) ---------- */
const diffKeys = (a, b) => Object.keys(Object.assign({}, a, b)).filter(k => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
function staffRule(u, S, o, cur) {
  const perm = p => !!(u.perms && u.perms[p]);
  const allow = p => { if (p && perm(p)) return true; if ((S.m.ovUntil || 0) > Date.now()) { S.m.ovUsed = true; return true; } return false; };
  const v = o.v, isNew = o.op === 'set' && !cur;
  switch (o.c) {
    case 'log': return o.op === 'set' && !cur;
    case 'cash':
      if (isNew) return true;
      if (o.op === 'del' && /^(sale|return):/.test((cur && cur.ref) || '')) return allow('cancelSale') || allow('cashEdit') || allow('refund');
      return allow('cashEdit');
    case 'orders': {
      if (isNew) return true;
      if (o.op === 'del') return cur.status === 'Принят' && allow('delOrder');
      const ch = diffKeys(cur, v);
      if (cur.status === 'Выдан') return ch.every(k => k === 'comment');
      if (JSON.stringify(cur.items || null) !== JSON.stringify(v.items || null)) {      // услуги и мастера
        if (!['Принят','Диагностика','В работе'].includes(cur.status)) return false;     // после «Готов» услуги не меняют
        const sum = a => (a || []).reduce((t, i) => t + (+i.price || 0), 0);
        const base = cur.items ? sum(cur.items) : +cur.price || 0;
        const moved = (cur.items || []).some(i => { const j = (v.items || []).find(x => x.id === i.id); return j && (+j.price || 0) !== (+i.price || 0); });
        if ((sum(v.items) !== base || moved) && !allow('price')) return false;
      }
      if (ch.includes('price') && !allow('price')) return false;
      return true;
    }
    case 'parts': {
      if (isNew || o.op === 'del') return allow('stock');
      const ch = diffKeys(cur, v);
      return (ch.length === 1 && ch[0] === 'qty') || allow('stock');
    }
    case 'phones': {
      if (isNew || o.op === 'del') return allow('phoneEdit');
      const ch = diffKeys(cur, v);
      if (!cur.sold && v.sold && ch.every(k => ['sold','soldPrice','soldDate','seller'].includes(k))) return +v.soldPrice >= +cur.min;
      if (cur.sold && !v.sold) return allow('cancelSale');
      return allow('phoneEdit');
    }
    case 'acc': {
      if (isNew || o.op === 'del') return allow('accEdit');
      const ch = diffKeys(cur, v);
      return (ch.length === 1 && ch[0] === 'qty') || allow('accEdit');
    }
    case 'accSales': case 'stockSales':
      if (isNew) return true;
      return o.op === 'del' && allow('cancelSale');
    case 'suppliers': return isNew || allow('supEdit');
    case 'contacts': return allow('contacts');
    case 'writeoffs': return isNew || allow('cancelSale');
    case 'cancellations': return isNew || allow('cancelSale');
    case 'returns': if (isNew) return !(+v.refund > 0) || allow('refund'); return allow('refund');
    default: return false;     // staff, services, adjust: только владелец
  }
}
function bump(o) {
  if (o.op !== 'set' || typeof o.id !== 'number') return;
  const c = db.counters; c.nid = Math.max(c.nid, o.id + 1);
  const f = FLOOR[o.c]; if (f) c[f] = Math.max(c[f], o.id + 1);
}
function applyOps(u, S, ops) {
  const owner = u.role === OWNER, rejected = []; let changed = false;
  ops.slice(0, 5000).forEach(o => {
    if (!o || typeof o !== 'object' || typeof o.c !== 'string') return;
    if (o.op === 'val') {
      if (o.c === 'set' && owner && o.v && typeof o.v === 'object') { db.state.set = o.v; changed = true; }
      else rejected.push({c:o.c, reason:'нет прав'});
      return;
    }
    if (!ARR.includes(o.c) || (o.op !== 'set' && o.op !== 'del')) return;
    const arr = db.state[o.c] || (db.state[o.c] = []), cur = arr.find(r => r.id === o.id);
    if (o.op === 'set' && (!o.v || typeof o.v !== 'object' || o.v.id !== o.id)) { rejected.push({c:o.c, id:o.id, reason:'неверные данные'}); return; }
    if (o.c === 'log') {                                   // журнал: только добавление, автор подставляется сервером
      if (o.op !== 'set' || cur) { rejected.push({c:o.c, id:o.id, reason:'журнал нельзя менять'}); return; }
      o.v.who = u.name; o.v.whoId = u.id; if (!(o.v.ts <= Date.now() + 60e3)) o.v.ts = Date.now();
    } else if (!owner && !staffRule(u, S, o, cur)) {
      rejected.push({c:o.c, id:o.id, reason:'нет прав'}); return;
    }
    if (o.c === 'staff') {
      if (o.op === 'del' ) { rejected.push({c:o.c, id:o.id, reason:'сотрудников не удаляют, а отключают'}); return; }
      delete o.v.pass; delete o.v._pw;
      if (cur && cur.role === OWNER) o.v.role = OWNER;
      else if (o.v.role === OWNER) { rejected.push({c:o.c, id:o.id, reason:'владелец один'}); return; }
      const lg = String(o.v.login || '').toLowerCase();
      if (lg && db.state.staff.some(m => m.id !== o.id && String(m.login || '').toLowerCase() === lg)) { rejected.push({c:o.c, id:o.id, reason:'логин занят'}); return; }
    }
    const i = arr.findIndex(r => r.id === o.id);
    if (o.op === 'del') { if (i >= 0) arr.splice(i, 1); }
    else if (i >= 0) arr[i] = o.v; else arr.unshift(o.v);
    bump(o); changed = true;
  });
  if (S.m.ovUsed) { S.m.ovUntil = 0; S.m.ovUsed = false; }
  return {rejected, changed};
}

/* ---------- HTTP ---------- */
const SEC = {'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY'};
function json(res, obj, code) {
  res.writeHead(code || 200, Object.assign({'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store'}, SEC));
  res.end(JSON.stringify(obj));
}
function readBody(req, cb) {
  let n = 0; const chunks = [];
  req.on('data', c => { n += c.length; if (n > 30e6) req.destroy(); else chunks.push(c); });
  req.on('end', () => { try { cb(null, JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { cb(e); } });
  req.on('error', cb);
}
let verCache = {m:0, v:''};
function appVer() {
  for (const f of ['index.html', 'repair-crm-v2.html']) {
    try {
      const p = path.join(DIR, f), st = fs.statSync(p);
      if (st.mtimeMs !== verCache.m || !verCache.v) verCache = {m:st.mtimeMs, v:crypto.createHash('sha1').update(fs.readFileSync(p)).digest('hex').slice(0, 10)};
      return verCache.v;
    } catch (e) {}
  }
  return '';
}
const STATIC = {'/manifest.webmanifest':'application/manifest+json', '/sw.js':'text/javascript; charset=utf-8', '/icon-192.png':'image/png', '/icon-512.png':'image/png', '/icon-maskable-512.png':'image/png'};
function sendApp(res) {
  for (const f of ['index.html', 'repair-crm-v2.html']) {
    const p = path.join(DIR, f);
    if (fs.existsSync(p)) {
      res.writeHead(200, Object.assign({'Content-Type':'text/html; charset=utf-8', 'Cache-Control':'no-cache'}, SEC));
      return res.end(fs.readFileSync(p));
    }
  }
  res.writeHead(404); res.end('Файл программы (repair-crm-v2.html) не найден рядом с server.js');
}
const okPw = p => typeof p === 'string' && p.length >= 4 && p.length <= 200;

function handle(req, url, body, res) {
  const ip = ipOf(req);
  if (url === '/api/setup') {                             // первый запуск: создание владельца
    if (db.state) return json(res, {error:'already'}, 409);
    const ow = body.owner || {}, name = String(ow.name || '').trim(), login = String(ow.login || '').trim();
    if (!name || login.length < 3 || !okPw(ow.password) || ow.password.length < 6) return json(res, {error:'Имя, логин (от 3 знаков) и пароль (от 6 знаков) обязательны'}, 400);
    const st = body.state && typeof body.state === 'object' ? body.state : {};
    ARR.forEach(k => { if (!Array.isArray(st[k])) st[k] = []; });
    let oid = (st.staff.find(m => m.role === OWNER) || {}).id;
    if (oid == null) { oid = 1; st.staff.unshift({id:1, role:OWNER, perms:{}}); }
    st.staff.forEach(m => {
      if (m.id === oid) { m.name = name; m.login = login; m.role = OWNER; db.users[m.id] = makeHash(ow.password); }
      else if (m.pass) db.users[m.id] = makeHash(m.pass);
      delete m.pass; delete m._pw;
    });
    delete st.pin; delete st.pinSet;
    db.state = st;
    const c = db.counters, bc = body.counters || {};
    ['nextId','nextCash','nextStaff'].forEach(k => { if (+bc[k] > c[k]) c[k] = +bc[k]; });
    ARR.forEach(k => st[k].forEach(r => bump({op:'set', c:k, id:r.id})));
    db.rev = 1; db.schema = SCHEMA;
    const token = newSession(oid), u = st.staff.find(m => m.id === oid);
    save();
    return json(res, {token, uid:oid, rev:db.rev, state:view(u)});
  }
  if (url === '/api/login') {
    if (!db.state) return json(res, {error:'setup'}, 409);
    const l = String(body.login || '').trim().toLowerCase(), pw = String(body.password || '');
    const w = Math.max(locked('ip:' + ip), locked('u:' + l));
    if (w) return json(res, {error:'locked', wait:w}, 429);
    const m = db.state.staff.find(x => x.login && String(x.login).toLowerCase() === l && !x.off);
    if (m && checkHash(db.users[m.id], pw)) {
      fails.delete('u:' + l);
      return json(res, {token:newSession(m.id), uid:m.id});
    }
    addFail('ip:' + ip, 20, 600e3); addFail('u:' + l, 6, 600e3);
    serverLog('Неудачный вход: логин «' + String(body.login || '').slice(0, 40) + '»', 'warn', 'Не вошёл', 0);
    return json(res, {error:'login'}, 401);
  }
  const S = session(req);
  if (!S) return json(res, {error:'auth'}, 401);
  const u = S.user;
  switch (url) {
    case '/api/me': return json(res, {uid:u.id, role:u.role, name:u.name});
    case '/api/logout': delete db.sessions[S.h]; delete mem[S.h]; save(); return json(res, {ok:true});
    case '/api/state': return json(res, {rev:db.rev, state:view(u)});
    case '/api/sync': {
      const ops = Array.isArray(body.ops) ? body.ops : [];
      let changed = false, rejected = [];
      if (ops.length) { const r = applyOps(u, S, ops); rejected = r.rejected; changed = changed || r.changed; }
      if (body.pw && typeof body.pw === 'object' && u.role === OWNER) {      // пароли — после записей, чтобы новый сотрудник уже существовал
        Object.keys(body.pw).forEach(id => {
          if (okPw(body.pw[id]) && db.state.staff.some(m => String(m.id) === String(id))) { db.users[id] = makeHash(body.pw[id]); changed = true; }
        });
      }
      if (rejected.length) serverLog('Сервер не принял изменения (' + rejected.length + '): ' + rejected.slice(0, 3).map(x => x.c + ' ' + x.reason).join('; '), 'warn', u.name, u.id);
      if (changed) { db.rev++; save(); }
      if (!changed && !rejected.length && body.rev === db.rev) return json(res, {rev:db.rev, same:true, ver:appVer()});
      return json(res, {rev:db.rev, state:view(u), rejected, ver:appVer()});
    }
    case '/api/pin/verify': {
      const w = S.m.pinLock > Date.now() ? Math.ceil((S.m.pinLock - Date.now()) / 60000) : 0;
      if (w) return json(res, {ok:false, locked:true, wait:w});
      if (db.pin && checkHash(db.pin, String(body.pin || ''))) { S.m.pinFails = 0; S.m.ovUntil = Date.now() + OV_MS; return json(res, {ok:true}); }
      S.m.pinFails = (S.m.pinFails || 0) + 1;
      if (S.m.pinFails >= 5) { S.m.pinFails = 0; S.m.pinLock = Date.now() + 300e3; serverLog('Код доступа введён неверно 5 раз, ввод заблокирован на 5 минут', 'warn', u.name, u.id); }
      return json(res, {ok:false});
    }
    case '/api/pin/set': {
      if (u.role !== OWNER) return json(res, {error:'forbidden'}, 403);
      if (!/^\d{4,8}$/.test(String(body.new || ''))) return json(res, {error:'Код: от 4 до 8 цифр'}, 400);
      if (db.pin && !checkHash(db.pin, String(body.old || ''))) return json(res, {ok:false});
      db.pin = makeHash(String(body.new)); db.rev++; save();
      return json(res, {ok:true});
    }
    case '/api/password/verify': {
      const w = S.m.pwLock > Date.now() ? Math.ceil((S.m.pwLock - Date.now()) / 60000) : 0;
      if (w) return json(res, {ok:false, locked:true, wait:w});
      if (checkHash(db.users[u.id], String(body.password || ''))) { S.m.pwFails = 0; return json(res, {ok:true}); }
      S.m.pwFails = (S.m.pwFails || 0) + 1;
      if (S.m.pwFails >= 5) { S.m.pwFails = 0; S.m.pwLock = Date.now() + 300e3; }
      return json(res, {ok:false});
    }
    case '/api/export': {
      if (u.role !== OWNER) return json(res, {error:'forbidden'}, 403);
      return json(res, {exported:Date.now(), state:view(u)});
    }
    case '/api/block': {
      const k = String(body.counter), size = Math.max(1, Math.min(10000, +body.size || 100));
      if (!(k in db.counters)) return json(res, {error:'counter'}, 400);
      const start = db.counters[k]; db.counters[k] += size; save();
      return json(res, {start});
    }
  }
  json(res, {error:'not found'}, 404);
}

(function migrate() {
  const from = db.schema || 0;
  if (from > SCHEMA) { console.error('Файл данных создан более новой версией программы. Обновите server.js. Сервер не запущен.'); process.exit(1); }
  if (!db.state) { db.schema = SCHEMA; return; }
  if (from < SCHEMA) {
    try { fs.copyFileSync(DATA, DATA.replace(/\.json$/, '') + '.before-schema' + SCHEMA + '-' + Date.now() + '.json'); } catch (e) {}
    for (let v = from; v < SCHEMA; v++) MIGRATIONS[v](db.state, db);
    db.schema = SCHEMA; saveNow();
    console.log('Данные обновлены до версии структуры ' + SCHEMA + ' (копия сохранена рядом с data.json).');
  }
})();
const srv = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (req.method === 'GET') {
    if (url === '/api/ping') return json(res, {app:'ultrapro', setup:!db.state, ver:appVer()});
    if (url === '/' || url === '/index.html' || url === '/repair-crm-v2.html') return sendApp(res);
    const st = STATIC[url];
    if (st) {
      const f = path.join(DIR, url.slice(1));
      if (fs.existsSync(f)) {
        res.writeHead(200, Object.assign({'Content-Type':st, 'Cache-Control':'no-cache'}, SEC));
        return res.end(fs.readFileSync(f));
      }
    }
    res.writeHead(404); return res.end('Not found');
  }
  if (req.method === 'POST' && url.startsWith('/api/')) {
    return readBody(req, (err, body) => {
      if (err) return json(res, {error:'bad request'}, 400);
      try { handle(req, url, body, res); } catch (e) { console.error(e); json(res, {error:'server'}, 500); }
    });
  }
  res.writeHead(404); res.end('Not found');
});
srv.listen(PORT, process.env.HOST || '0.0.0.0', () => {
  console.log('\n=== Сервер запущен ===');
  console.log(db.state ? 'Данные найдены, можно входить.' : 'Первый запуск: откройте адрес и создайте владельца.');
  console.log('Адреса (в одной сети Wi-Fi):');
  Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal)
    .forEach(i => console.log('   http://' + i.address + ':' + PORT));
  console.log('   http://localhost:' + PORT + '  (на этом же компьютере)');
  console.log('Файл данных: ' + DATA + '\nНе закрывайте это окно, пока работаете.\n');
});
['SIGINT','SIGTERM'].forEach(s => process.on(s, () => { saveNow(); process.exit(0); }));
