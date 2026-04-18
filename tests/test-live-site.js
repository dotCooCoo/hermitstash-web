#!/usr/bin/env node
// HermitStash PQC Gateway — live site e2e tests
//
// Usage:
//   node tests/test-live-site.js                    # test production
//   node tests/test-live-site.js http://localhost:8787  # test local dev
//
// Zero dependencies — uses Node.js built-in fetch (Node 18+).

var BASE = process.argv[2] || "https://hermitstash.com";
var passed = 0, failed = 0, skipped = 0;

function ok(name) { passed++; console.log("  \x1b[32mPASS\x1b[0m " + name); }
function fail(name, detail) { failed++; console.log("  \x1b[31mFAIL\x1b[0m " + name + (detail ? " — " + detail : "")); }
function skip(name, reason) { skipped++; console.log("  \x1b[33mSKIP\x1b[0m " + name + " — " + reason); }

// Browser-like headers that pass the fingerprint check
var BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.9",
  "Sec-Fetch-Dest": "document",
  "Upgrade-Insecure-Requests": "1",
};

async function GET(path, headers) {
  return fetch(BASE + path, { headers: headers || BROWSER_HEADERS, redirect: "manual" });
}

// ==================== Security Headers ====================

async function testSecurityHeaders() {
  console.log("\n--- Security Headers ---");
  var res = await GET("/");
  var h = res.headers;

  var required = {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "credentialless",
    "cache-control": "no-cache, must-revalidate",
  };

  for (var [name, expected] of Object.entries(required)) {
    var actual = h.get(name);
    if (!actual) fail("Header: " + name, "missing");
    else if (actual !== expected) fail("Header: " + name, "expected '" + expected + "' got '" + actual + "'");
    else ok("Header: " + name);
  }

  // Permissions-Policy (partial match — long value)
  var pp = h.get("permissions-policy");
  if (!pp) fail("Header: permissions-policy", "missing");
  else if (pp.includes("camera=()") && pp.includes("microphone=()") && pp.includes("geolocation=()")) ok("Header: permissions-policy");
  else fail("Header: permissions-policy", "missing required directives");

  // CSP must exist and contain nonce
  var csp = h.get("content-security-policy");
  if (!csp) fail("CSP: present", "missing");
  else {
    ok("CSP: present");
    if (csp.includes("default-src 'none'")) ok("CSP: default-src 'none'");
    else fail("CSP: default-src 'none'", "not found in CSP");

    var nonceMatch = csp.match(/nonce-([A-Za-z0-9+/=]+)/);
    if (nonceMatch) ok("CSP: has nonce (" + nonceMatch[1].substring(0, 8) + "...)");
    else fail("CSP: has nonce", "no nonce found in CSP");

    if (csp.includes("'unsafe-eval'")) fail("CSP: no unsafe-eval", "unsafe-eval found");
    else ok("CSP: no unsafe-eval");

    if (csp.match(/script-src[^;]*'unsafe-inline'/)) fail("CSP: no unsafe-inline on scripts", "unsafe-inline found in script-src");
    else ok("CSP: no unsafe-inline on scripts");
  }
}

// ==================== CSP Nonce Uniqueness ====================

async function testNonceUniqueness() {
  console.log("\n--- Nonce Uniqueness ---");
  var res1 = await GET("/");
  var res2 = await GET("/");
  var csp1 = res1.headers.get("content-security-policy") || "";
  var csp2 = res2.headers.get("content-security-policy") || "";
  var n1 = (csp1.match(/nonce-([A-Za-z0-9+/=]+)/) || [])[1];
  var n2 = (csp2.match(/nonce-([A-Za-z0-9+/=]+)/) || [])[1];
  if (!n1 || !n2) fail("Nonce uniqueness", "could not extract nonces");
  else if (n1 === n2) fail("Nonce uniqueness", "same nonce across requests");
  else ok("Nonce uniqueness — two requests got different nonces");
}

// ==================== HTML Content ====================

async function testHTMLContent() {
  console.log("\n--- HTML Content ---");
  var res = await GET("/");
  var body = await res.text();

  // Nonce in HTML matches CSP
  var csp = res.headers.get("content-security-policy") || "";
  var cspNonce = (csp.match(/nonce-([A-Za-z0-9+/=]+)/) || [])[1];
  if (cspNonce && body.includes('nonce="' + cspNonce + '"')) ok("Script nonce matches CSP header");
  else fail("Script nonce matches CSP header", "nonce mismatch or not found in HTML");

  // OG tags
  var ogTags = ["og:title", "og:description", "og:url", "og:image", "og:type", "og:site_name"];
  for (var tag of ogTags) {
    if (body.includes('property="' + tag + '"')) ok("OG tag: " + tag);
    else fail("OG tag: " + tag, "not found in HTML");
  }

  // Twitter card
  var twitterTags = ["twitter:card", "twitter:title", "twitter:description", "twitter:image"];
  for (var tag of twitterTags) {
    if (body.includes('name="' + tag + '"')) ok("Twitter tag: " + tag);
    else fail("Twitter tag: " + tag, "not found in HTML");
  }

  // JSON-LD
  if (body.includes("application/ld+json")) ok("JSON-LD schema present");
  else fail("JSON-LD schema present", "not found");

  // Title
  if (body.includes("<title>HermitStash")) ok("Page title contains HermitStash");
  else fail("Page title", "not found");

  // Meta description
  if (body.includes('name="description"')) ok("Meta description present");
  else fail("Meta description", "not found");
}

// ==================== Method Filtering ====================

async function testMethodFiltering() {
  console.log("\n--- Method Filtering ---");

  // GET should work
  var get = await GET("/");
  if (get.status === 200) ok("GET / → 200");
  else fail("GET / → 200", "got " + get.status);

  // HEAD should work
  var head = await fetch(BASE + "/", { method: "HEAD", headers: BROWSER_HEADERS, redirect: "manual" });
  if (head.status === 200) ok("HEAD / → 200");
  else fail("HEAD / → 200", "got " + head.status);

  // POST should be blocked
  var post = await fetch(BASE + "/", { method: "POST", headers: BROWSER_HEADERS, redirect: "manual" });
  if (post.status === 405) ok("POST / → 405");
  else fail("POST / → 405", "got " + post.status);
}

// ==================== Path Handling ====================

async function testPathHandling() {
  console.log("\n--- Path Handling ---");

  // Non-root paths should 301 to /
  var paths = ["/admin", "/login", "/foo/bar", "/wp-admin"];
  for (var p of paths) {
    var res = await GET(p);
    if (res.status === 301) {
      var loc = res.headers.get("location") || "";
      if (loc === "/" || loc === BASE + "/") ok(p + " → 301 to /");
      else fail(p + " → 301", "redirects to " + loc + " instead of /");
    } else {
      fail(p + " → 301", "got " + res.status);
    }
  }

  // /.well-known/security.txt
  var sectxt = await fetch(BASE + "/.well-known/security.txt", { headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] }, redirect: "manual" });
  if (sectxt.status === 200) {
    ok("/.well-known/security.txt → 200");
    var stbody = await sectxt.text();
    if (stbody.includes("Contact:")) ok("security.txt has Contact");
    else fail("security.txt Contact", "missing");
    if (stbody.includes("Expires:")) ok("security.txt has Expires (RFC 9116)");
    else fail("security.txt Expires", "missing — required by RFC 9116");
    if (stbody.includes("Canonical:")) ok("security.txt has Canonical");
    else fail("security.txt Canonical", "missing");
  } else {
    fail("/.well-known/security.txt → 200", "got " + sectxt.status);
  }

  // /robots.txt should return 200 with text/plain
  var robots = await fetch(BASE + "/robots.txt", { headers: { "User-Agent": BROWSER_HEADERS["User-Agent"] }, redirect: "manual" });
  if (robots.status === 200) {
    ok("/robots.txt → 200");
    var ct = robots.headers.get("content-type") || "";
    if (ct.includes("text/plain")) ok("/robots.txt content-type is text/plain");
    else fail("/robots.txt content-type", "got " + ct);
    var rbody = await robots.text();
    if (rbody.includes("User-agent:") && rbody.includes("Sitemap:")) ok("/robots.txt has User-agent and Sitemap");
    else fail("/robots.txt content", "missing expected directives");
  } else {
    fail("/robots.txt → 200", "got " + robots.status);
  }
}

// ==================== Bot Filtering ====================

async function testBotFiltering() {
  console.log("\n--- Bot Filtering ---");

  // Blocked bots should get 403
  var blockedUAs = [
    ["curl/8.0", "curl"],
    ["python-requests/2.31.0", "python"],
    ["Wget/1.21", "wget"],
    ["", "empty UA"],
  ];
  for (var [ua, label] of blockedUAs) {
    var res = await fetch(BASE + "/", { headers: { "User-Agent": ua }, redirect: "manual" });
    if (res.status === 403) ok("Blocked bot: " + label + " → 403");
    else fail("Blocked bot: " + label + " → 403", "got " + res.status);
  }

  // Allowed bots should get 200 (bypass fingerprint check)
  var allowedBots = [
    ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"],
    ["facebookexternalhit/1.1", "Facebook"],
    ["LinkedInBot/1.0", "LinkedIn"],
    ["Slackbot-LinkExpanding 1.0", "Slackbot"],
    ["Twitterbot/1.0", "Twitterbot"],
  ];
  for (var [ua, label] of allowedBots) {
    var res = await fetch(BASE + "/", { headers: { "User-Agent": ua }, redirect: "manual" });
    if (res.status === 200) ok("Allowed bot: " + label + " → 200");
    else fail("Allowed bot: " + label + " → 200", "got " + res.status);
  }
}

// ==================== Browser Fingerprint ====================

async function testBrowserFingerprint() {
  console.log("\n--- Browser Fingerprint ---");

  // Valid browser headers should pass
  var valid = await GET("/");
  if (valid.status === 200) ok("Full browser headers → 200");
  else fail("Full browser headers → 200", "got " + valid.status);

  // Missing accept-language should fail (may pass on Cloudflare edge which injects headers)
  var noLang = await fetch(BASE + "/", {
    headers: {
      "User-Agent": BROWSER_HEADERS["User-Agent"],
      "Accept": BROWSER_HEADERS["Accept"],
      "Sec-Fetch-Dest": "document",
    },
    redirect: "manual",
  });
  if (noLang.status === 403) ok("Missing accept-language → 403");
  else if (BASE.includes("localhost")) fail("Missing accept-language → 403", "got " + noLang.status);
  else skip("Missing accept-language → 403", "Cloudflare edge may inject accept-language");

  // Missing accept header should fail
  var noAccept = await fetch(BASE + "/", {
    headers: {
      "User-Agent": BROWSER_HEADERS["User-Agent"],
      "Accept-Language": "en-US",
      "Sec-Fetch-Dest": "document",
    },
    redirect: "manual",
  });
  if (noAccept.status === 403) ok("Missing accept → 403");
  else fail("Missing accept → 403", "got " + noAccept.status);
}

// ==================== Response Codes ====================

async function testResponseCodes() {
  console.log("\n--- Response Codes ---");

  var res = await GET("/");
  if (res.status === 200) ok("GET / status 200");
  else fail("GET / status 200", "got " + res.status);

  var ct = res.headers.get("content-type") || "";
  if (ct.includes("text/html")) ok("Content-Type is text/html");
  else fail("Content-Type is text/html", "got " + ct);
}

// ==================== Run All ====================

async function main() {
  console.log("Testing: " + BASE);

  await testResponseCodes();
  await testSecurityHeaders();
  await testNonceUniqueness();
  await testHTMLContent();
  await testMethodFiltering();
  await testPathHandling();
  await testBotFiltering();
  await testBrowserFingerprint();

  console.log("\n========================================");
  console.log("  " + passed + " passed, " + failed + " failed, " + skipped + " skipped");
  console.log("========================================\n");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(function (err) { console.error(err); process.exit(1); });
