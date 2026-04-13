// ============================================================
// HermitStash PQC Gateway Worker — Fully Hardened
// ============================================================

// --- Rate Limiter (in-memory, per isolate) ---
var rateLimitMap = {};
var RATE_LIMIT_WINDOW = 60000;
var RATE_LIMIT_MAX = 30;

function isRateLimited(ip) {
  var now = Date.now();
  if (Math.random() < 0.01) {
    for (var k in rateLimitMap) {
      if (now - rateLimitMap[k].start > RATE_LIMIT_WINDOW * 2) delete rateLimitMap[k];
    }
  }
  var entry = rateLimitMap[ip];
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimitMap[ip] = { start: now, count: 1 };
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

// --- Bot UA blocklist ---
var BOT_PATTERNS = [
  'curl', 'wget', 'python', 'httpie', 'scrapy', 'httpclient',
  'go-http', 'java/', 'libwww', 'lwp-', 'php/', 'ruby',
  'perl', 'nikto', 'sqlmap', 'nmap', 'masscan', 'zgrab',
  'semrush', 'ahref', 'mj12bot', 'dotbot', 'petalbot',
  'bytespider', 'gptbot', 'ccbot', 'claudebot', 'anthropic',
  'dataforseo', 'headlesschrome', 'phantomjs', 'selenium',
  'puppeteer', 'playwright', 'applebot', 'yandexbot', 'baiduspider',
  'aiohttp'
];

function isBot(ua) {
  if (!ua) return true;
  var lower = ua.toLowerCase();
  for (var i = 0; i < BOT_PATTERNS.length; i++) {
    if (lower.indexOf(BOT_PATTERNS[i]) !== -1) return true;
  }
  return false;
}

// --- Blocked ASNs (TOR exits, open proxies, abusive hosting, scanners) ---
var BLOCKED_ASNS = [
  209, 396507, 212238, 63949,
  211590,  // FBW NETWORKS SAS (stripe/env scanner)
  213737,  // AYOSOFT LTD (vuln scanner)
  213412,  // ONYPHE (internet scanner)
  9009     // UAB code200 (proxy/scanner)
];

function isBlockedASN(asn) {
  if (!asn) return false;
  for (var i = 0; i < BLOCKED_ASNS.length; i++) {
    if (asn === BLOCKED_ASNS[i]) return true;
  }
  return false;
}

// --- Browser fingerprint check ---
function looksLikeBrowser(request) {
  var acceptLang = request.headers.get('accept-language');
  if (!acceptLang) return false;

  var accept = request.headers.get('accept');
  if (!accept || accept.indexOf('text/html') === -1) return false;

  var secDest = request.headers.get('sec-fetch-dest');
  var upgrade = request.headers.get('upgrade-insecure-requests');
  if (!secDest && !upgrade) return false;

  return true;
}

// --- Nonce generator ---
function generateNonce() {
  var array = new Uint8Array(16);
  crypto.getRandomValues(array);
  var nonce = '';
  for (var i = 0; i < array.length; i++) {
    nonce += array[i].toString(16).padStart(2, '0');
  }
  return nonce;
}

// --- Generic block response ---
function blocked() {
  return new Response('Access Denied', {
    status: 403,
    headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }
  });
}

// --- Main handler ---
export default {
  async fetch(request, env) {
    var url = new URL(request.url);

    // Method check
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Path normalization — only serve root
    if (url.pathname !== '/' && url.pathname !== '') {
      return Response.redirect(url.origin + '/', 301);
    }

    // Rate limiting
    var ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (isRateLimited(ip)) {
      return new Response('Too Many Requests', {
        status: 429,
        headers: { 'Retry-After': '60', 'Content-Type': 'text/plain' }
      });
    }

    // Bot detection
    var ua = request.headers.get('user-agent') || '';
    if (isBot(ua)) return blocked();

    // ASN check
    var cf = request.cf || {};
    if (isBlockedASN(cf.asn)) return blocked();

    // Browser fingerprint
    if (!looksLikeBrowser(request)) return blocked();

    // Generate nonce
    var nonce = generateNonce();

    // Asset version (commit SHA injected at deploy time; 'dev' when running wrangler dev)
    var version = (env && env.ASSET_VERSION) || 'dev';

    // Security headers
    var headers = {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, must-revalidate',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '0',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=()',
      'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src https://app.hermitstash.com; img-src 'self' https://assets.hermitstash.com; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'credentialless',
    };

    var html = [
'<!DOCTYPE html>',
'<html lang="en">',
'<head>',
'<meta charset="UTF-8">',
'<meta name="viewport" content="width=device-width, initial-scale=1.0">',
'<title>HermitStash \u2014 Quantum-Safe Entry</title>',
'<style>',
"  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Outfit:wght@300;400;600;800&display=swap');",
'  :root {',
'    --bg: #0a0a0f; --bg-card: #12121a; --border: #1e1e2e;',
'    --accent: #22d3a7; --accent-dim: #22d3a740; --accent-glow: #22d3a718;',
'    --red: #f24e6a; --red-dim: #f24e6a30;',
'    --text: #e2e2e8; --text-dim: #6b6b80; --text-mid: #9898aa;',
'  }',
'  * { margin: 0; padding: 0; box-sizing: border-box; }',
"  body { background: var(--bg); color: var(--text); font-family: 'Outfit', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; overflow: hidden; }",
"  body::before { content: ''; position: fixed; inset: 0; background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px); background-size: 60px 60px; opacity: 0.3; animation: gridShift 20s linear infinite; }",
'  @keyframes gridShift { 0% { transform: translate(0, 0); } 100% { transform: translate(60px, 60px); } }',
"  body::after { content: ''; position: fixed; width: 500px; height: 500px; border-radius: 50%; top: 50%; left: 50%; transform: translate(-50%, -50%); background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%); pointer-events: none; transition: background 1.5s ease; }",
'  body.failed::after { background: radial-gradient(circle, var(--red-dim) 0%, transparent 70%); }',
'  .container { position: relative; z-index: 1; width: 90%; max-width: 520px; text-align: center; }',
"  .logo { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-weight: 700; font-size: 1.6rem; letter-spacing: -0.03em; color: var(--accent); margin-bottom: 2.5rem; display: flex; align-items: center; justify-content: center; gap: 0.5rem; }",
'  .logo .icon { width: 36px; height: 36px; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; }',
'  .logo .icon svg { width: 100%; height: 100%; }',
'  .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 2.5rem 2rem; backdrop-filter: blur(20px); }',
'  #state-checking { animation: fadeIn 0.4s ease; }',
'  .spinner-wrap { margin-bottom: 1.5rem; }',
'  .spinner { width: 48px; height: 48px; margin: 0 auto; position: relative; }',
'  .spinner .ring { position: absolute; inset: 0; border: 2px solid transparent; border-top-color: var(--accent); border-radius: 50%; animation: spin 1s linear infinite; }',
'  .spinner .ring:nth-child(2) { inset: 6px; border-top-color: var(--accent-dim); animation-duration: 1.5s; animation-direction: reverse; }',
'  @keyframes spin { to { transform: rotate(360deg); } }',
"  .status-label { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent); letter-spacing: 0.1em; text-transform: uppercase; }",
'  .status-sub { font-size: 0.85rem; color: var(--text-dim); margin-top: 0.5rem; font-weight: 300; }',
"  .log { margin-top: 1.5rem; text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--text-dim); line-height: 1.8; border-top: 1px solid var(--border); padding-top: 1rem; }",
'  .log .line { opacity: 0; animation: logIn 0.3s ease forwards; }',
'  .log .line .prefix { color: var(--text-mid); user-select: none; }',
'  .log .line.ok .val { color: var(--accent); }',
'  .log .line.fail .val { color: var(--red); }',
'  @keyframes logIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }',
'  #state-fail { display: none; animation: fadeIn 0.5s ease; }',
'  .fail-icon { width: 56px; height: 56px; margin: 0 auto 1.2rem; border: 2px solid var(--red); border-radius: 50%; display: grid; place-items: center; font-size: 1.5rem; color: var(--red); animation: pulse 2s ease-in-out infinite; }',
'  @keyframes pulse { 0%, 100% { box-shadow: 0 0 0 0 var(--red-dim); } 50% { box-shadow: 0 0 0 12px transparent; } }',
'  .fail-title { font-size: 1.3rem; font-weight: 600; margin-bottom: 0.6rem; color: var(--text); }',
'  .fail-desc { font-size: 0.9rem; color: var(--text-mid); line-height: 1.6; margin-bottom: 1.5rem; font-weight: 300; }',
'  .fail-desc strong { color: var(--text); font-weight: 500; }',
'  .browsers { display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; margin-bottom: 1.5rem; }',
"  .browser-pill { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 0.8rem; font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--text-mid); display: flex; align-items: center; gap: 0.5rem; transition: border-color 0.2s; }",
'  .browser-pill:hover { border-color: var(--accent-dim); }',
'  .browser-pill .ver { color: var(--accent); font-weight: 500; }',
'  .why-section { border-top: 1px solid var(--border); padding-top: 1rem; text-align: left; }',
"  .why-title { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; }",
'  .why-text { font-size: 0.8rem; color: var(--text-dim); line-height: 1.6; font-weight: 300; }',
'  .why-text a { color: var(--accent); text-decoration: none; border-bottom: 1px solid var(--accent-dim); transition: border-color 0.2s; }',
'  .why-text a:hover { border-color: var(--accent); }',
'  #state-success { display: none; animation: fadeIn 0.4s ease; }',
'  .success-icon { width: 56px; height: 56px; margin: 0 auto 1.2rem; border: 2px solid var(--accent); border-radius: 50%; display: grid; place-items: center; font-size: 1.5rem; color: var(--accent); }',
'  .success-title { font-size: 1.1rem; font-weight: 500; color: var(--accent); margin-bottom: 0.4rem; }',
'  .success-sub { font-size: 0.85rem; color: var(--text-dim); font-weight: 300; }',
'  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }',
"  .footer { margin-top: 1.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: var(--text-dim); letter-spacing: 0.05em; opacity: 0.6; }",
'  @media (max-width: 480px) { .card { padding: 2rem 1.2rem; } .browsers { grid-template-columns: 1fr; } .logo { font-size: 1.1rem; } }',
'</style>',
'</head>',
'<body>',
'<div class="container">',
'  <div class="logo">',
'    <span class="icon"><img src="https://assets.hermitstash.com/pqc.svg?v=' + version + '" alt="HermitStash" width="36" height="36"></span>',
'    HermitStash',
'  </div>',
'',
'  <div class="card">',
'    <div id="state-checking">',
'      <div class="spinner-wrap">',
'        <div class="spinner">',
'          <div class="ring"></div>',
'          <div class="ring"></div>',
'        </div>',
'      </div>',
'      <div class="status-label">Negotiating Handshake</div>',
'      <div class="status-sub">Verifying post-quantum key exchange support\u2026</div>',
'      <div class="log" id="log"></div>',
'    </div>',
'',
'    <div id="state-fail">',
'      <div class="fail-icon">\u2715</div>',
'      <div class="fail-title">PQC Handshake Failed</div>',
'      <div class="fail-desc">',
"        Your browser doesn't support <strong>post-quantum cryptography</strong>.",
'        HermitStash requires <strong>X25519MLKEM768</strong> hybrid key exchange',
'        to protect your data against harvest-now-decrypt-later attacks.',
'      </div>',
'      <div class="browsers">',
'        <div class="browser-pill">Chrome <span class="ver">\u2265 131</span></div>',
'        <div class="browser-pill">Firefox <span class="ver">\u2265 135</span></div>',
'        <div class="browser-pill">Edge <span class="ver">\u2265 131</span></div>',
'        <div class="browser-pill">Safari <span class="ver">TBD</span></div>',
'      </div>',
'      <div class="why-section">',
'        <div class="why-title">Why enforce this?</div>',
'        <div class="why-text">',
'          Quantum computers capable of breaking classical encryption are approaching',
'          faster than expected. Your encrypted traffic can be intercepted today and',
'          decrypted later. PQC stops that.',
'          <br><br>',
'          <a href="https://pq.cloudflareresearch.com" target="_blank" rel="noopener">',
"            Test your browser's PQC support \u2192",
'          </a>',
'        </div>',
'      </div>',
'    </div>',
'',
'    <div id="state-success">',
'      <div class="success-icon">\u2713</div>',
'      <div class="success-title">PQC Verified</div>',
'      <div class="success-sub">Redirecting to quantum-safe connection\u2026</div>',
'    </div>',
'  </div>',
'',
'  <div class="footer">quantum-safe since 2026</div>',
'</div>',
'',
'<script nonce="' + nonce + '">',
'(function() {',
"  var logEl = document.getElementById('log');",
"  var stateChecking = document.getElementById('state-checking');",
"  var stateFail = document.getElementById('state-fail');",
"  var stateSuccess = document.getElementById('state-success');",
'  var lineDelay = 0;',
'',
'  function addLog(prefix, text, cls, delay) {',
'    lineDelay += delay;',
'    setTimeout(function() {',
"      var div = document.createElement('div');",
"      div.className = 'line ' + (cls || '');",
"      div.innerHTML = '<span class=\"prefix\">' + prefix + '</span> <span class=\"val\">' + text + '</span>';",
'      logEl.appendChild(div);',
'    }, lineDelay);',
'  }',
'',
'  function showFail(reason) {',
"    addLog('\\u2715', 'pqc handshake failed: ' + reason, 'fail', 400);",
"    addLog('\\u2139', 'browser does not support ML-KEM key exchange', 'fail', 300);",
'    setTimeout(function() {',
"      stateChecking.style.display = 'none';",
"      stateFail.style.display = 'block';",
"      document.body.classList.add('failed');",
'    }, lineDelay + 800);',
'  }',
'',
'  function showSuccess() {',
"    addLog('\\u2713', 'pqc handshake succeeded', 'ok', 400);",
"    addLog('\\u2713', 'health check: status ok', 'ok', 300);",
'    setTimeout(function() {',
"      stateChecking.style.display = 'none';",
"      stateSuccess.style.display = 'block';",
'    }, lineDelay + 600);',
'    setTimeout(function() {',
'      window.location.href = PQC_ORIGIN;',
'    }, lineDelay + 2000);',
'  }',
'',
"  var PQC_ORIGIN = 'https://app.hermitstash.com';",
"  var HEALTH_ENDPOINT = PQC_ORIGIN + '/health';",
'',
"  addLog('\\u2192', 'initiating tls 1.3 probe\\u2026', '', 300);",
"  addLog('\\u2192', 'target: ' + PQC_ORIGIN, '', 600);",
"  addLog('\\u2192', 'required: X25519MLKEM768', '', 400);",
'',
'  var controller = new AbortController();',
'  var timeout = setTimeout(function() { controller.abort(); }, 8000);',
'',
"  addLog('\\u22ef', 'awaiting handshake\\u2026', '', 500);",
'',
'  fetch(HEALTH_ENDPOINT, {',
"    mode: 'cors',",
'    signal: controller.signal,',
"    cache: 'no-store'",
'  })',
'  .then(function(res) {',
'    clearTimeout(timeout);',
'    if (!res.ok) throw new Error("http " + res.status);',
'    return res.json();',
'  })',
'  .then(function(data) {',
"    if (data && data.status === 'ok') {",
'      showSuccess();',
'    } else {',
"      throw new Error('bad status');",
'    }',
'  })',
'  .catch(function(err) {',
'    clearTimeout(timeout);',
"    var reason = err.name === 'AbortError' ? 'connection timed out' : 'handshake rejected';",
'    showFail(reason);',
'  });',
'})();',
'</script>',
'</body>',
'</html>'
    ].join('\n');

    return new Response(html, { headers: headers });
  },
};
