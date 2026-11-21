// מתכונים — Cloudflare Worker + מסד נתונים SQLite (Durable Object)
// קבצי האתר נמצאים ב-/public. כל מה שמתחת ל-/api/* מטופל כאן ונשמר במסד הנתונים.

import { DurableObject } from 'cloudflare:workers';
import SEED from './seed.json';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // אבטחה: רק חיבור מוצפן (https)
    if (url.protocol === 'http:' && url.hostname !== 'localhost') {
      url.protocol = 'https:';
      return Response.redirect(url.toString(), 301);
    }
    if (url.pathname.startsWith('/api/')) {
      const stub = env.DB.get(env.DB.idFromName('main'));
      return withSecurityHeaders(await stub.fetch(request));
    }
    const res = await env.ASSETS.fetch(request);
    const type = res.headers.get('content-type') || '';
    const out = withSecurityHeaders(res);
    if (type.includes('text/html')) {
      out.headers.set('cache-control', 'no-cache, no-store, must-revalidate');
      out.headers.set('content-security-policy', CSP);
    }
    return out;
  }
};

// ---------- אבטחה ----------
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data: blob: https:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'"
].join('; ');
function withSecurityHeaders(res) {
  const out = new Response(res.body, res);
  out.headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  out.headers.set('x-content-type-options', 'nosniff');
  out.headers.set('x-frame-options', 'DENY');
  out.headers.set('referrer-policy', 'strict-origin-when-cross-origin');
  out.headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  return out;
}

const SESSION_DAYS = 90;
const MIN_PASS = 6;
const CATS = ['chicken', 'meat', 'fish', 'soup', 'salad', 'side', 'bake'];
const COLORS = ['#c4633f', '#6f8a4a', '#d49a3a', '#8a5a7a', '#4f7f8a', '#b5523b', '#7a6a4a'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const PASS_ABC = 'abcdefghjkmnpqrstuvwxyz23456789';
const FAMILY = 'family'; // הספר של קבוצת הוואטסאפ: ספר פרטי של נמרוד
const FAMILY_OWNER = 'nimrodyaroker@gmail.com';
const MAX_BOOKS = 20, MAX_MEMBERS = 200;

class Limiter {
  constructor() { this.hits = new Map(); }
  count(key, windowMs) {
    const now = Date.now(), arr = (this.hits.get(key) || []).filter(t => t > now - windowMs);
    this.hits.set(key, arr); return arr;
  }
  over(key, max, windowMs) { return this.count(key, windowMs).length >= max; }
  add(key, windowMs) { const arr = this.count(key, windowMs); arr.push(Date.now()); }
  clear(key) { this.hits.delete(key); }
  sweep() { if (this.hits.size > 5000) this.hits.clear(); }
}

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg) => { throw new HttpError(400, msg); };
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});
const norm = (s, max = 80) => String(s ?? '').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim().replace(/[ \t]+/g, ' ').slice(0, max);
const lines = (arr, maxLines, maxLen) => (Array.isArray(arr) ? arr : String(arr || '').split('\n'))
  .map(x => norm(x, maxLen)).filter(Boolean).slice(0, maxLines);
const safeUrl = (u) => {
  u = norm(u, 600);
  if (!u) return '';
  try { const p = new URL(u); return (p.protocol === 'https:' || p.protocol === 'http:') ? p.toString() : ''; } catch (e) { return ''; }
};

function randomId(bytes = 9) {
  const a = new Uint8Array(bytes); crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function toHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function hashPassword(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return toHex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export class RecipesDB extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.limiter = new Limiter();
    this.migrate();
  }
  q(query, ...binds) { return this.sql.exec(query, ...binds).toArray(); }
  one(query, ...binds) { return this.q(query, ...binds)[0] || null; }

  migrate() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        pass_hash TEXT NOT NULL, salt TEXT NOT NULL,
        color TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS recipes (
        id TEXT PRIMARY KEY, cat TEXT NOT NULL, title TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', img TEXT NOT NULL DEFAULT '',
        photo TEXT, photo_v INTEGER NOT NULL DEFAULT 0,
        servings TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
        ing TEXT NOT NULL DEFAULT '[]', steps TEXT NOT NULL DEFAULT '[]',
        video INTEGER NOT NULL DEFAULT 0, by_user INTEGER, edited_by INTEGER,
        sort INTEGER NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seed_removed (id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS security_log (t INTEGER NOT NULL, kind TEXT NOT NULL, who TEXT, ip TEXT);
      CREATE TABLE IF NOT EXISTS books (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, owner INTEGER,
        private INTEGER NOT NULL DEFAULT 0, invite TEXT NOT NULL UNIQUE, created INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS members (book_id TEXT NOT NULL, user_id INTEGER NOT NULL, joined INTEGER NOT NULL, PRIMARY KEY (book_id, user_id));
    `);
    // ספרים: כל מתכון שייך לספר. מה שהיה עד עכשיו נכנס לספר של המשפחה
    try { this.sql.exec("ALTER TABLE recipes ADD COLUMN book_id TEXT NOT NULL DEFAULT 'family'"); } catch (e) { /* העמודה כבר קיימת */ }
    // שיתוף מתכון: קישור אישי לכל מתכון, שפותח רק את המתכון הזה גם מספר פרטי
    try { this.sql.exec('ALTER TABLE recipes ADD COLUMN share TEXT'); } catch (e) { /* העמודה כבר קיימת */ }
    this.sql.exec('CREATE UNIQUE INDEX IF NOT EXISTS recipes_share ON recipes (share)');
    this.sql.exec('CREATE INDEX IF NOT EXISTS recipes_book ON recipes (book_id, sort)');
    this.sql.exec('CREATE INDEX IF NOT EXISTS members_user ON members (user_id)');
    if (!this.one('SELECT 1 AS x FROM books WHERE id = ?', FAMILY)) {
      this.sql.exec('INSERT INTO books (id, name, owner, private, invite, created) VALUES (?, ?, NULL, 0, ?, ?)',
        FAMILY, 'ספר המתכונים של המשפחה', randomId(12), Date.now());
    }
    // פעם אחת בלבד: הספר של המשפחה הופך לציבורי (ברירת המחדל לכל הספרים). אחר כך הבעלים יכול לשנות כרצונו
    this.sql.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)');
    if (!this.one("SELECT 1 AS x FROM meta WHERE k = 'family-public'")) {
      this.sql.exec('UPDATE books SET private = 0 WHERE id = ?', FAMILY);
      this.sql.exec("INSERT INTO meta (k, v) VALUES ('family-public', '1')");
    }
    this.claimFamily();
    // פעם אחת: נמרוד ביקש שנורית תהיה מי שפתחה את ספר המשפחה. נמרוד נשאר חבר בספר
    if (!this.one("SELECT 1 AS x FROM meta WHERE k = 'family-owner-nurit'")) {
      const n = this.q("SELECT u.id FROM users u JOIN members m ON m.user_id = u.id AND m.book_id = ? WHERE u.name LIKE '%נורית%'", FAMILY);
      if (n.length === 1) {
        this.sql.exec('UPDATE books SET owner = ? WHERE id = ?', n[0].id, FAMILY);
        this.sql.exec("INSERT INTO meta (k, v) VALUES ('family-owner-nurit', ?)", String(n[0].id));
      }
    }
    this.sql.exec('DELETE FROM sessions WHERE created < ?', Date.now() - SESSION_DAYS * 864e5);
    // מתכונים מקבוצת הוואטסאפ: נכנסים פעם אחת. מתכון שנערך נשאר ערוך, מתכון שנמחק לא חוזר
    const now = Date.now();
    // קטגוריות: קינוחים ומאפים אוחדו. מתכון מהקבוצה שאף אחד לא ערך מקבל את הקטגוריה מהקובץ
    this.sql.exec("UPDATE recipes SET cat = 'bake' WHERE cat = 'sweet'");
    for (const r of SEED) {
      const ex = this.one('SELECT cat, by_user, edited_by FROM recipes WHERE id = ?', r.id);
      if (ex) { if (ex.by_user === null && ex.edited_by === null && ex.cat !== r.cat) this.sql.exec('UPDATE recipes SET cat = ? WHERE id = ?', r.cat, r.id); continue; }
      if (this.one('SELECT 1 AS x FROM seed_removed WHERE id = ?', r.id)) continue;
      const sort = r.date ? Date.parse(r.date + 'T12:00:00Z') : now - 400 * 864e5;
      this.sql.exec(`INSERT INTO recipes (id, book_id, cat, title, source, url, img, servings, note, ing, steps, video, by_user, sort, created, updated)
        VALUES (?, '${FAMILY}', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
        r.id, r.cat, r.title, r.source || '', r.url || '', r.img || '', r.servings || '', r.note || '',
        JSON.stringify(r.ing || []), JSON.stringify(r.steps || []), r.video ? 1 : 0, sort, now, now);
    }
  }
  secLog(kind, who, ip) {
    this.sql.exec('INSERT INTO security_log (t, kind, who, ip) VALUES (?, ?, ?, ?)', Date.now(), kind, who || '', ip || '');
    this.sql.exec('DELETE FROM security_log WHERE t < ?', Date.now() - 30 * 864e5);
    console.warn('[security]', kind, who || '', ip || '');
  }

  async fetch(request) {
    try { return await this.handle(request); }
    catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: 'משהו נכשל בשרת. נסו שוב' }, 500);
    }
  }

  // ---------- עזרים ----------
  meUser(u) { return { id: u.id, name: u.name, email: u.email, color: u.color, admin: !!u.admin }; }
  auth(request, optional) {
    const h = request.headers.get('authorization') || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    const row = token && this.one('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.created > ?', token, Date.now() - SESSION_DAYS * 864e5);
    if (!row && !optional) throw new HttpError(401, 'צריך להתחבר');
    return row || null;
  }
  newSession(userId) {
    const token = randomId(24);
    this.sql.exec('INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)', token, userId, Date.now());
    return token;
  }
  // ----- ספרים -----
  // הספר של קבוצת הוואטסאפ שייך למשתמש של נמרוד (גם אם הוא נרשם רק אחרי שהספר נוצר)
  claimFamily() {
    const u = this.one('SELECT id FROM users WHERE email = ?', FAMILY_OWNER);
    if (!u) return;
    this.sql.exec('UPDATE books SET owner = ? WHERE id = ? AND owner IS NULL', u.id, FAMILY);
      this.sql.exec('INSERT OR IGNORE INTO members (book_id, user_id, joined) VALUES (?, ?, ?)', FAMILY, u.id, Date.now());
  }
  newBook(name, ownerId) {
    const id = 'b' + randomId(6), now = Date.now();
    this.sql.exec('INSERT INTO books (id, name, owner, private, invite, created) VALUES (?, ?, ?, 0, ?, ?)', id, name, ownerId, randomId(12), now);
    this.sql.exec('INSERT OR IGNORE INTO members (book_id, user_id, joined) VALUES (?, ?, ?)', id, ownerId, now);
    return id;
  }
  book(id) { return this.one('SELECT * FROM books WHERE id = ?', String(id || '')); }
  isMember(me, b) { return !!me && !!b && !!this.one('SELECT 1 AS x FROM members WHERE book_id = ? AND user_id = ?', b.id, me.id); }
  canView(me, b) { return !b.private || this.isMember(me, b); }
  defaultBook(me) {
    // ספר ראשון של המשתמש. אין לו ספרים (או לא מחובר)? אין ספר פתוח והאתר מראה את רשימת הספרים
    if (!me) return null;
    return this.one('SELECT b.* FROM members m JOIN books b ON b.id = m.book_id WHERE m.user_id = ? ORDER BY m.joined LIMIT 1', me.id);
  }
  ownerName(b) { const u = b.owner ? this.one('SELECT name FROM users WHERE id = ?', b.owner) : null; return u ? u.name : ''; }
  bookPub(b, me, member) {
    const view = member || !b.private;
    return {
      id: b.id, name: b.name, private: !!b.private, family: b.id === FAMILY,
      mine: !!me && b.owner === me.id, member, locked: !view, owner: this.ownerName(b),
      count: this.one('SELECT COUNT(*) AS c FROM recipes WHERE book_id = ?', b.id).c,
      covers: view ? this.covers(b.id) : [],
      invite: member ? b.invite : undefined
    };
  }
  myBooks(me) {
    return this.q(`SELECT b.*, (SELECT COUNT(*) FROM recipes r WHERE r.book_id = b.id) AS c, (SELECT name FROM users u WHERE u.id = b.owner) AS oname
      FROM members m JOIN books b ON b.id = m.book_id WHERE m.user_id = ? ORDER BY m.joined`, me.id)
      .map(b => ({ id: b.id, name: b.name, private: !!b.private, mine: b.owner === me.id, owner: b.oname || '', count: b.c, covers: this.covers(b.id) }));
  }
  // עד 3 תמונות אחרונות מהספר, לשער של הספר במסך "הספרים שלי"
  covers(bookId) {
    return this.q("SELECT id, img, photo_v FROM recipes WHERE book_id = ? AND (photo_v > 0 OR img LIKE 'http%' OR img LIKE '/%') ORDER BY sort DESC LIMIT 3", bookId)
      .map(r => r.photo_v ? `/api/photo/${r.id}?v=${r.photo_v}` : r.img);
  }
  view(me, b, extra) {
    if (!b) return { me: me ? this.meUser(me) : null, book: null, recipes: [], books: me ? this.myBooks(me) : [], ...(extra || {}) };
    const member = this.isMember(me, b);
    const pb = this.bookPub(b, me, member);
    return { me: me ? this.meUser(me) : null, book: pb, recipes: pb.locked ? [] : this.all(me, b, member), books: me ? this.myBooks(me) : [], ...(extra || {}) };
  }
  ownBook(me, id, ip) {
    const b = this.book(id);
    if (!b) throw new HttpError(404, 'הספר לא נמצא');
    if (b.owner !== me.id) { this.secLog('book-denied', me.email, ip); throw new HttpError(403, 'רק מי שפתח את הספר יכול לעשות את זה'); }
    return b;
  }
  memberBook(me, id, ip) {
    const b = this.book(id);
    if (!b) throw new HttpError(404, 'הספר לא נמצא');
    if (!this.isMember(me, b)) { this.secLog('book-denied', me.email, ip); throw new HttpError(403, 'רק מי שהוזמן לספר יכול לעשות את זה'); }
    return b;
  }

  canEdit(me, r, member) { return !!me && member; }
  canDelete(me, r, b, member) { return !!me && member && (b.owner === me.id || (r.by_user !== null && r.by_user === me.id)); }
  pub(r, me, names, b, member) {
    return {
      id: r.id, cat: r.cat, title: r.title, source: r.source, url: r.url,
      img: r.photo_v ? `/api/photo/${r.id}?v=${r.photo_v}` : r.img,
      servings: r.servings, note: r.note, ing: JSON.parse(r.ing), steps: JSON.parse(r.steps),
      video: !!r.video, by: r.by_user ? (names.get(r.by_user) || '') : '', sort: r.sort,
      edit: this.canEdit(me, r, member), del: this.canDelete(me, r, b, member)
    };
  }
  all(me, b, member) {
    const names = new Map(this.q('SELECT id, name FROM users').map(u => [u.id, u.name]));
    return this.q('SELECT id, cat, title, source, url, img, photo_v, servings, note, ing, steps, video, by_user, sort FROM recipes WHERE book_id = ? ORDER BY sort DESC', b.id)
      .map(r => this.pub(r, me, names, b, member));
  }
  readRecipe(body, existing) {
    const title = norm(body.title, 80);
    if (title.length < 2) bad('צריך לתת למתכון שם');
    const cat = CATS.includes(body.cat) ? body.cat : bad('צריך לבחור סוג מנה');
    const ing = lines(body.ing, 80, 200), steps = lines(body.steps, 40, 1000);
    const url = safeUrl(body.url);
    if (norm(body.url) && !url) bad('הקישור לא נראה תקין');
    if (!ing.length && !steps.length && !url) bad('צריך מצרכים, הוראות הכנה או לפחות קישור');
    return {
      title, cat, ing, steps, url,
      source: norm(body.source, 80), servings: norm(body.servings, 40), note: norm(body.note, 600),
      video: (!ing.length && !steps.length) ? 1 : 0
    };
  }
  savePhoto(id, photo) {
    if (photo === null) { this.sql.exec('UPDATE recipes SET photo = NULL, photo_v = 0, img = ? WHERE id = ?', '', id); return; }
    if (typeof photo !== 'string' || !photo) return;
    if (!photo.startsWith('data:image/jpeg;base64,')) bad('אפשר להעלות רק תמונה');
    const b64 = photo.slice(23);
    if (b64.length > 450000) bad('התמונה גדולה מדי');
    if (!/^[A-Za-z0-9+/=]+$/.test(b64) || !b64.startsWith('/9j/')) bad('אפשר להעלות רק תמונה');
    this.sql.exec('UPDATE recipes SET photo = ?, photo_v = photo_v + 1 WHERE id = ?', b64, id);
  }

  async handle(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '');
    const method = request.method;
    let body = {};
    if (method === 'POST') {
      const len = +(request.headers.get('content-length') || 0);
      if (len > 700000) bad('הבקשה גדולה מדי');
      try { body = await request.json(); } catch (e) { body = {}; }
      if (!body || typeof body !== 'object') body = {};
    }
    let m;
    const ip = request.headers.get('cf-connecting-ip') || 'local';
    const L = this.limiter; L.sweep();
    if (L.over('req:' + ip, 300, 60e3)) throw new HttpError(429, 'יותר מדי בקשות. חכו דקה ונסו שוב');
    L.add('req:' + ip, 60e3);

    // ----- ציבורי: צפייה במתכונים -----
    if (path === '/api/recipes' && method === 'GET') {
      const me = this.auth(request, true);
      const rid = url.searchParams.get('recipe'), bid = url.searchParams.get('book');
      let b = null;
      if (rid) { const r = this.one('SELECT book_id FROM recipes WHERE id = ?', rid); if (r) b = this.book(r.book_id); }
      else if (bid) b = this.book(bid);
      let denied = false;
      if (b && !this.canView(me, b)) { b = null; denied = true; }
      if (!b) b = this.defaultBook(me);
      return json(this.view(me, b, { denied }));
    }
    if ((m = path.match(/^\/api\/invite\/([\w-]+)$/)) && method === 'GET') {
      if (L.over('inv:' + ip, 30, 600e3)) throw new HttpError(429, 'יותר מדי ניסיונות. חכו כמה דקות');
      L.add('inv:' + ip, 600e3);
      const b = this.one('SELECT * FROM books WHERE invite = ?', m[1]);
      if (!b) throw new HttpError(404, 'קישור ההזמנה לא תקף. בקשו קישור חדש');
      const me = this.auth(request, true);
      return json({ book: { id: b.id, name: b.name, owner: this.ownerName(b) }, member: this.isMember(me, b) });
    }
    // ----- שיתוף מתכון -----
    if ((m = path.match(/^\/api\/recipes\/([\w-]+)\/share$/)) && method === 'POST') {
      if (L.over('shr:' + ip, 60, 600e3)) throw new HttpError(429, 'יותר מדי שיתופים. חכו כמה דקות');
      L.add('shr:' + ip, 600e3);
      const me = this.auth(request, true);
      const r = this.one('SELECT id, book_id, share FROM recipes WHERE id = ?', m[1]);
      const b = r ? this.book(r.book_id) : null;
      if (!r || !b) throw new HttpError(404, 'המתכון לא נמצא');
      if (!this.canView(me, b)) { this.secLog('share-denied', me ? me.email : '', ip); throw new HttpError(403, 'אין הרשאה לשתף את המתכון הזה'); }
      let token = r.share;
      if (!token) { token = randomId(12); this.sql.exec('UPDATE recipes SET share = ? WHERE id = ?', token, r.id); }
      return json({ token });
    }
    if ((m = path.match(/^\/api\/shared\/([\w-]+)$/)) && method === 'GET') {
      if (L.over('shg:' + ip, 60, 600e3)) throw new HttpError(429, 'יותר מדי בקשות. חכו כמה דקות');
      L.add('shg:' + ip, 600e3);
      const r = this.one('SELECT * FROM recipes WHERE share = ?', m[1]);
      if (!r) throw new HttpError(404, 'הקישור למתכון לא תקף, אולי המתכון נמחק');
      const b = this.book(r.book_id);
      const u = r.by_user ? this.one('SELECT name FROM users WHERE id = ?', r.by_user) : null;
      const names = new Map(u ? [[r.by_user, u.name]] : []);
      return json({ recipe: { ...this.pub(r, null, names, b, false), share: r.share }, book: b ? b.name : '' });
    }
    if ((m = path.match(/^\/api\/photo\/([\w-]+)$/)) && method === 'GET') {
      const r = this.one('SELECT photo FROM recipes WHERE id = ?', m[1]);
      if (!r || !r.photo) throw new HttpError(404, 'אין תמונה');
      const bin = Uint8Array.from(atob(r.photo), c => c.charCodeAt(0));
      return new Response(bin, { headers: { 'content-type': 'image/jpeg', 'cache-control': 'public, max-age=31536000, immutable' } });
    }

    // ----- חשבונות -----
    if (path === '/api/signup' && method === 'POST') {
      if (L.over('signup:' + ip, 5, 3600e3)) { this.secLog('signup-limit', '', ip); throw new HttpError(429, 'נפתחו יותר מדי משתמשים מהמכשיר הזה. נסו שוב בעוד שעה'); }
      const name = norm(body.name, 24), password = String(body.password || '');
      const email = String(body.email || '').trim().toLowerCase();
      if (name.length < 2) bad('צריך שם (לפחות 2 אותיות)');
      if (!EMAIL_RE.test(email) || email.length > 120) bad('כתובת המייל לא נראית תקינה');
      if (password.length < MIN_PASS || password.length > 200) bad(`הסיסמה צריכה להיות לפחות ${MIN_PASS} תווים`);
      if (this.one('SELECT id FROM users WHERE email = ?', email)) bad('כבר יש משתמש עם המייל הזה. נסו להתחבר');
      const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
      const count = this.one('SELECT COUNT(*) AS c FROM users').c;
      // המשתמש הראשון שנרשם הוא המנהל של האתר
      this.sql.exec('INSERT INTO users (name, email, pass_hash, salt, color, admin, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
        name, email, await hashPassword(password, salt), salt, COLORS[count % COLORS.length], count === 0 ? 1 : 0, Date.now());
      const u = this.one('SELECT * FROM users WHERE email = ?', email);
      if (email === FAMILY_OWNER) this.claimFamily();
      L.add('signup:' + ip, 3600e3);
      return json({ token: this.newSession(u.id) });
    }
    if (path === '/api/login' && method === 'POST') {
      const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
      const acc = 'fail:' + email, ipk = 'failip:' + ip, WIN = 15 * 60e3;
      if (L.over(acc, 5, WIN) || L.over(ipk, 20, WIN)) throw new HttpError(429, 'יותר מדי ניסיונות כניסה. חכו 15 דקות ונסו שוב');
      const u = this.one('SELECT * FROM users WHERE email = ?', email);
      const pass = String(body.password || '').slice(0, 200);
      if (!u || !safeEqual(await hashPassword(pass, u.salt), u.pass_hash)) {
        L.add(acc, WIN); L.add(ipk, WIN);
        this.secLog(L.over(acc, 5, WIN) ? 'login-locked' : 'login-failed', email, ip);
        bad('המייל או הסיסמה לא נכונים');
      }
      L.clear(acc);
      return json({ token: this.newSession(u.id) });
    }

    const me = this.auth(request);
    const token = (request.headers.get('authorization') || '').slice(7);
    if (path === '/api/logout' && method === 'POST') {
      this.sql.exec('DELETE FROM sessions WHERE token = ?', token);
      return json({ ok: true });
    }
    if (path === '/api/password' && method === 'POST') {
      if (!safeEqual(await hashPassword(String(body.oldPass || '').slice(0, 200), me.salt), me.pass_hash)) bad('הסיסמה הנוכחית לא נכונה');
      const np = String(body.newPass || '');
      if (np.length < MIN_PASS || np.length > 200) bad(`הסיסמה החדשה צריכה להיות לפחות ${MIN_PASS} תווים`);
      const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
      this.sql.exec('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?', await hashPassword(np, salt), salt, me.id);
      this.sql.exec('DELETE FROM sessions WHERE user_id = ? AND token != ?', me.id, token);
      return json({ ok: true });
    }

    // ----- מנהל: רשימת בני המשפחה ואיפוס סיסמה למי ששכח -----
    if (path.startsWith('/api/admin/')) {
      if (!me.admin) { this.secLog('admin-denied', me.email, ip); throw new HttpError(403, 'רק למנהל האתר'); }
      if (path === '/api/admin/users' && method === 'GET') {
        return json({ users: this.q('SELECT id, name, email, created FROM users ORDER BY created'),
          alerts: this.q("SELECT t, kind, who FROM security_log WHERE kind IN ('login-locked','signup-limit','admin-denied','book-denied') ORDER BY t DESC LIMIT 20") });
      }
      if ((m = path.match(/^\/api\/admin\/users\/(\d+)\/reset$/)) && method === 'POST') {
        const u = this.one('SELECT * FROM users WHERE id = ?', +m[1]);
        if (!u) bad('המשתמש לא נמצא');
        const a = new Uint8Array(10); crypto.getRandomValues(a);
        const temp = [...a].map(x => PASS_ABC[x % PASS_ABC.length]).join('');
        const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
        this.sql.exec('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?', await hashPassword(temp, salt), salt, u.id);
        this.sql.exec('DELETE FROM sessions WHERE user_id = ?', u.id);
        this.secLog('admin-reset', u.email, ip);
        return json({ temp });
      }
    }

    // ----- ספרים -----
    if (path === '/api/books' && method === 'POST') {
      const name = norm(body.name, 40);
      if (name.length < 2) bad('צריך לתת לספר שם');
      if (this.one('SELECT COUNT(*) AS c FROM books WHERE owner = ?', me.id).c >= MAX_BOOKS) bad(`אפשר לפתוח עד ${MAX_BOOKS} ספרים`);
      const id = this.newBook(name, me.id);
      return json(this.view(me, this.book(id)));
    }
    if (path === '/api/join' && method === 'POST') {
      if (L.over('inv:' + ip, 30, 600e3)) throw new HttpError(429, 'יותר מדי ניסיונות. חכו כמה דקות');
      L.add('inv:' + ip, 600e3);
      const b = this.one('SELECT * FROM books WHERE invite = ?', String(body.token || '').slice(0, 40));
      if (!b) bad('קישור ההזמנה לא תקף. בקשו קישור חדש');
      if (!this.isMember(me, b)) {
        if (this.one('SELECT COUNT(*) AS c FROM members WHERE book_id = ?', b.id).c >= MAX_MEMBERS) bad('הספר מלא');
        this.sql.exec('INSERT INTO members (book_id, user_id, joined) VALUES (?, ?, ?)', b.id, me.id, Date.now());
      }
      return json({ book: b.id });
    }
    if ((m = path.match(/^\/api\/books\/([\w-]+)\/members$/)) && method === 'GET') {
      const b = this.memberBook(me, m[1], ip);
      return json({ members: this.q('SELECT u.id, u.name, u.color FROM members m JOIN users u ON u.id = m.user_id WHERE m.book_id = ? ORDER BY m.joined', b.id)
        .map(u => ({ ...u, owner: u.id === b.owner })) });
    }
    if ((m = path.match(/^\/api\/books\/([\w-]+)(?:\/(invite|remove|leave|delete))?$/)) && method === 'POST') {
      const act = m[2] || 'update';
      if (act === 'leave') {
        const b = this.memberBook(me, m[1], ip);
        if (b.owner === me.id) bad('אי אפשר לצאת מספר שפתחתם');
        this.sql.exec('DELETE FROM members WHERE book_id = ? AND user_id = ?', b.id, me.id);
        return json({ ok: true });
      }
      const b = this.ownBook(me, m[1], ip);
      if (act === 'update') {
        if (body.name !== undefined) {
          const name = norm(body.name, 40);
          if (name.length < 2) bad('צריך לתת לספר שם');
          this.sql.exec('UPDATE books SET name = ? WHERE id = ?', name, b.id);
        }
        if (body.private !== undefined) this.sql.exec('UPDATE books SET private = ? WHERE id = ?', body.private ? 1 : 0, b.id);
      } else if (act === 'invite') {
        this.sql.exec('UPDATE books SET invite = ? WHERE id = ?', randomId(12), b.id);
      } else if (act === 'remove') {
        const uid = +body.user;
        if (!uid || uid === me.id) bad('אי אפשר להוציא את עצמכם');
        this.sql.exec('DELETE FROM members WHERE book_id = ? AND user_id = ?', b.id, uid);
        return json({ ok: true });
      } else if (act === 'delete') {
        if (b.id === FAMILY) bad('את הספר של המשפחה אי אפשר למחוק');
        this.sql.exec('DELETE FROM recipes WHERE book_id = ?', b.id);
        this.sql.exec('DELETE FROM members WHERE book_id = ?', b.id);
        this.sql.exec('DELETE FROM books WHERE id = ?', b.id);
        return json({ ok: true });
      }
      return json(this.view(me, this.book(b.id)));
    }

    // ----- מתכונים -----
    if (path === '/api/recipes' && method === 'POST') {
      if (L.over('add:' + me.id, 40, 3600e3)) throw new HttpError(429, 'הוספתם הרבה מתכונים בשעה האחרונה. נסו שוב מאוחר יותר');
      if (this.one('SELECT COUNT(*) AS c FROM recipes').c >= 20000) bad('אין מקום למתכונים נוספים');
      const b = this.memberBook(me, body.book, ip);
      const r = this.readRecipe(body);
      const id = 'u' + randomId(8), now = Date.now();
      this.sql.exec(`INSERT INTO recipes (id, book_id, cat, title, source, url, servings, note, ing, steps, video, by_user, edited_by, sort, created, updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        id, b.id, r.cat, r.title, r.source, r.url, r.servings, r.note, JSON.stringify(r.ing), JSON.stringify(r.steps), r.video, me.id, me.id, now, now, now);
      this.savePhoto(id, body.photo);
      L.add('add:' + me.id, 3600e3);
      return json({ id, ...this.view(me, b) });
    }
    if ((m = path.match(/^\/api\/recipes\/([\w-]+)(?:\/(delete))?$/)) && method === 'POST') {
      const ex = this.one('SELECT * FROM recipes WHERE id = ?', m[1]);
      if (!ex) throw new HttpError(404, 'המתכון לא נמצא');
      const b = this.memberBook(me, ex.book_id, ip);
      if (m[2] === 'delete') {
        if (!this.canDelete(me, ex, b, true)) throw new HttpError(403, 'אפשר למחוק רק מתכון שהוספתם');
        this.sql.exec('DELETE FROM recipes WHERE id = ?', ex.id);
        if (ex.by_user === null) this.sql.exec('INSERT OR IGNORE INTO seed_removed (id) VALUES (?)', ex.id);
        return json(this.view(me, b));
      }
      const r = this.readRecipe(body);
      this.sql.exec(`UPDATE recipes SET cat = ?, title = ?, source = ?, url = ?, servings = ?, note = ?, ing = ?, steps = ?, video = ?, edited_by = ?, updated = ? WHERE id = ?`,
        r.cat, r.title, r.source, r.url, r.servings, r.note, JSON.stringify(r.ing), JSON.stringify(r.steps), r.video, me.id, Date.now(), ex.id);
      this.savePhoto(ex.id, body.photo);
      return json({ id: ex.id, ...this.view(me, b) });
    }
    throw new HttpError(404, 'לא נמצא');
  }
}
