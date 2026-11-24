// BirrLow server, phase 1 (TEST payments only). One file, many routes: /api?r=<route>
const crypto = require('crypto');
const mysql = require('mysql2/promise');

let pool;
const db = () => pool || (pool = mysql.createPool({
  host: process.env.DB_HOST, port: +process.env.DB_PORT || 4000,
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
  connectionLimit: 3, timezone: 'Z', decimalNumbers: true,
}));

let ready;
const setup = () => ready || (ready = db().query(`CREATE TABLE IF NOT EXISTS orders (
  token VARCHAR(48) PRIMARY KEY, user_id INT NOT NULL, auction_id INT NOT NULL,
  amounts VARCHAR(500) NOT NULL, total DECIMAL(10,2) NOT NULL,
  status ENUM('pending','paid','expired') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`));

const TOKEN = () => (process.env.BOT_TOKEN || '').trim();

// Check that the Telegram data is genuine (signed with the bot token)
function tgUser(init) {
  if (!init) return null;
  const p = new URLSearchParams(init), hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const dcs = [...p.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => k + '=' + v).join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(TOKEN()).digest();
  const calc = crypto.createHmac('sha256', secret).update(dcs).digest('hex');
  const a = Buffer.from(calc), b = Buffer.from(hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Date.now() / 1000 - (+p.get('auth_date') || 0) > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch (e) { return null; }
}

async function upsertUser(u) {
  const c = db();
  await c.query(`INSERT INTO users (telegram_id,first_name,last_name,username) VALUES (?,?,?,?)
    ON DUPLICATE KEY UPDATE first_name=VALUES(first_name),last_name=VALUES(last_name),username=VALUES(username)`,
    [String(u.id), u.first_name || '', u.last_name || null, u.username || null]);
  const [r] = await c.query('SELECT id FROM users WHERE telegram_id=?', [String(u.id)]);
  return r[0].id;
}

let ready2;
const setup2 = () => ready2 || (ready2 = db().query(`CREATE TABLE IF NOT EXISTS audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY, kind VARCHAR(40) NOT NULL, auction_id INT NULL,
  detail VARCHAR(500) NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`));
// Audit record: every payment, closing and extension is written here
const log = (c, kind, aid, detail) => c.query('INSERT INTO audit_log (kind,auction_id,detail) VALUES (?,?,?)',
  [kind, aid, String(detail).slice(0, 500)]).catch(() => {});
// Send Telegram messages (people who never started the bot are skipped quietly)
const tell = (ids, text) => Promise.allSettled(ids.map((id) => fetch('https://api.telegram.org/bot' + TOKEN() + '/sendMessage', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: id, text }) })));

// Close finished auctions: lowest amount chosen by exactly one person wins.
// If nobody is unique, the auction is extended by 24 hours and all bids stay.
async function closeExpired() {
  const c = db();
  const [ex] = await c.query(`SELECT id FROM auctions WHERE status='active' AND end_time<=UTC_TIMESTAMP()`);
  for (const { id } of ex) {
    const [w] = await c.query(`SELECT bid_amount FROM bids WHERE auction_id=? GROUP BY bid_amount HAVING COUNT(*)=1 ORDER BY bid_amount ASC LIMIT 1`, [id]);
    if (w.length) {
      const [b] = await c.query(`SELECT id FROM bids WHERE auction_id=? AND bid_amount=?`, [id, w[0].bid_amount]);
      await c.query(`UPDATE auctions SET status='completed', winning_bid_id=? WHERE id=?`, [b[0].id, id]);
      await log(c, 'closed', id, `winner bid ${b[0].id} at ${w[0].bid_amount}`);
    } else {
      await c.query(`UPDATE auctions SET end_time=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 24 HOUR) WHERE id=?`, [id]);
      await log(c, 'extended', id, 'no unique bid, extended 24 hours');
    }
  }
}

const fixStatus = (c, aid) => c.query(`UPDATE bids b JOIN
  (SELECT bid_amount a, COUNT(*) n FROM bids WHERE auction_id=? GROUP BY bid_amount) x ON x.a=b.bid_amount
  SET b.status=IF(x.n=1,'unique','repeated') WHERE b.auction_id=?`, [aid, aid]);

// All the rules for a set of bids. The server never trusts the browser.
async function check(c, uid, aid, raw) {
  const [rows] = await c.query(`SELECT * FROM auctions WHERE id=? AND status='active'
    AND start_time<=UTC_TIMESTAMP() AND end_time>UTC_TIMESTAMP()`, [aid]);
  const a = rows[0];
  if (!a) return { error: 'closed' };
  const am = (Array.isArray(raw) ? raw : []).map(Number);
  if (!am.length || am.length > 20 || am.some((x) => !Number.isFinite(x))) return { error: 'bad' };
  if (am.some((x) => x < a.min_bid)) return { error: 'min' };
  if (am.some((x) => Math.round(x * 100) / 100 !== x)) return { error: 'dec' };
  if (new Set(am).size < am.length) return { error: 'dup' };
  const [mine] = await c.query(`SELECT bid_amount FROM bids WHERE auction_id=? AND user_id=?`, [aid, uid]);
  if (mine.some((m) => am.includes(+m.bid_amount))) return { error: 'dup' };
  if (mine.length + am.length > a.max_bids_per_user) return { error: 'cap' };
  return { a, am };
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  const q = req.query || {}, r = q.r, post = req.method === 'POST';
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const out = (o, s) => { res.statusCode = s || 200; res.end(JSON.stringify(o)); };
  try {
    if (r === 'health') {
      const t = TOKEN();
      return out({ ok: true, token_set: !!t, token_format_ok: /^\d+:[A-Za-z0-9_-]{30,}$/.test(t), db_host_set: !!process.env.DB_HOST });
    }
    await setup();
    await setup2();
    const c = db();

    if (r === 'auctions') {
      await closeExpired();
      const [rows] = await c.query(`SELECT a.id, a.product_name name, a.product_name_am name_am, a.emoji, a.description,
        a.participation_fee fee, a.min_bid, a.retail_price retail, a.end_time end_at,
        (SELECT COUNT(DISTINCT b2.user_id) FROM bids b2 WHERE b2.auction_id=a.id) people,
        (SELECT COUNT(*) FROM bids b WHERE b.auction_id=a.id) bids
        FROM auctions a WHERE a.status='active' ORDER BY a.end_time`);
      return out({ ok: true, auctions: rows });
    }

    // Step 1 (Telegram): check the person and the bids, create an order
    if (r === 'order' && post) {
      const u = tgUser(body.initData);
      if (!u) return out({ ok: false, error: body.initData ? 'sig' : 'auth' }, 401);
      const uid = await upsertUser(u);
      const v = await check(c, uid, +body.auction_id, body.amounts);
      if (v.error) return out({ ok: false, error: v.error });
      const token = crypto.randomBytes(18).toString('hex');
      const total = +(v.a.participation_fee * v.am.length).toFixed(2);
      await c.query(`INSERT INTO orders (token,user_id,auction_id,amounts,total) VALUES (?,?,?,?,?)`,
        [token, uid, v.a.id, JSON.stringify(v.am), total]);
      return out({ ok: true, token, total });
    }

    // Step 2 (website payment page): show the order. Only the secret order number is needed.
    if (r === 'order') {
      const [rows] = await c.query(`SELECT o.*, a.product_name name, a.emoji FROM orders o
        JOIN auctions a ON a.id=o.auction_id WHERE o.token=?`, [String(q.o || '')]);
      const o = rows[0];
      if (!o) return out({ ok: false, error: 'closed' }, 404);
      return out({ ok: true, order: { name: o.name, emoji: o.emoji, auction_id: o.auction_id,
        amounts: JSON.parse(o.amounts), total: o.total, status: o.status } });
    }

    // Step 3: pay. TEST MODE: no money moves. When Chapa is added, bids are saved
    // only after Chapa confirms the payment, and this shortcut must be removed.
    if (r === 'pay' && post) {
      const [rows] = await c.query(`SELECT * FROM orders WHERE token=?`, [String(body.o || '')]);
      const o = rows[0];
      if (!o) return out({ ok: false, error: 'closed' });
      if (o.status === 'paid') return out({ ok: true, already: true });
      const v = await check(c, o.user_id, o.auction_id, JSON.parse(o.amounts));
      if (v.error) return out({ ok: false, error: v.error });
      const [u] = await c.query(`UPDATE orders SET status='paid' WHERE token=? AND status='pending'`, [o.token]);
      if (!u.affectedRows) return out({ ok: true, already: true });
      for (const x of v.am) {
        await c.query(`INSERT INTO bids (id,auction_id,user_id,bid_amount) VALUES (?,?,?,?)`,
          ['BD-' + crypto.randomBytes(5).toString('hex'), o.auction_id, o.user_id, x]);
      }
      await fixStatus(c, o.auction_id);
      await log(c, 'paid', o.auction_id, `order ${o.token.slice(0, 8)} user ${o.user_id} amounts ${v.am.join(',')}`);
      // Tell everyone holding a number that is now repeated
      try {
        for (const x of v.am) {
          const [h] = await c.query(`SELECT DISTINCT u.telegram_id tg FROM bids b JOIN users u ON u.id=b.user_id
            WHERE b.auction_id=? AND b.bid_amount=?`, [o.auction_id, x]);
          if (h.length > 1) {
            const n = v.a.product_name;
            await tell(h.map((r) => r.tg), `BirrLow: your number ${x} in ${n} is now chosen by ${h.length} people, so it is no longer unique.\n${x} ብር በ${n} አሁን በ${h.length} ሰዎች ተመርጧል፤ ብቸኛ አይደለም።`);
          }
        }
      } catch (e) { console.error(e); }
      return out({ ok: true });
    }

    if (r === 'results') {
      await closeExpired();
      const [rows] = await c.query(`SELECT a.id, a.product_name name, a.product_name_am name_am, a.emoji, a.end_time end_at,
        (SELECT COUNT(*) FROM bids b WHERE b.auction_id=a.id) bids, w.bid_amount win_amount,
        TRIM(CONCAT(IFNULL(u.first_name,''),' ',LEFT(IFNULL(u.last_name,''),1))) winner
        FROM auctions a LEFT JOIN bids w ON w.id=a.winning_bid_id LEFT JOIN users u ON u.id=w.user_id
        WHERE a.status='completed' ORDER BY a.end_time DESC LIMIT 30`);
      return out({ ok: true, results: rows });
    }

    // Ranked bids are public only after the auction has closed
    if (r === 'ranked') {
      const [ar] = await c.query(`SELECT a.id, a.product_name name, a.emoji, a.status, w.bid_amount win_amount
        FROM auctions a LEFT JOIN bids w ON w.id=a.winning_bid_id WHERE a.id=?`, [+q.id]);
      if (!ar[0] || ar[0].status !== 'completed') return out({ ok: false, error: 'closed' }, 404);
      const [rows] = await c.query(`SELECT bid_amount amount, COUNT(*) n FROM bids WHERE auction_id=?
        GROUP BY bid_amount ORDER BY bid_amount ASC`, [+q.id]);
      return out({ ok: true, auction: ar[0], rows });
    }

    if (r === 'mybids' && post) {
      const u = tgUser(body.initData);
      if (!u) return out({ ok: false, error: body.initData ? 'sig' : 'auth' }, 401);
      const uid = await upsertUser(u);
      const [rows] = await c.query(`SELECT b.id, b.auction_id, b.bid_amount amount, b.status, a.product_name name,
        a.status astatus, (a.winning_bid_id=b.id) won,
        (SELECT COUNT(*) FROM bids x WHERE x.auction_id=b.auction_id AND x.bid_amount=b.bid_amount) reps
        FROM bids b JOIN auctions a ON a.id=b.auction_id WHERE b.user_id=? ORDER BY b.created_at DESC`, [uid]);
      return out({ ok: true, bids: rows });
    }

    return out({ ok: false, error: 'bad' }, 404);
  } catch (e) {
    console.error(e);
    return out({ ok: false, error: 'server' }, 500);
  }
};
module.exports._tgUser = tgUser;
