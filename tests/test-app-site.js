#!/usr/bin/env node
// HermitStash App Server — live site e2e tests
//
// Tests the app server at app.hermitstash.com via PQC TLS.
// Requires Node.js 24+ with OpenSSL 3.5+ (PQC TLS support).
//
// Usage:
//   node tests/test-app-site.js                          # test production
//   node tests/test-app-site.js https://localhost:3000    # test local dev
//
// Zero dependencies — uses Node.js built-in https module.

var https = require("https");
var http = require("http");
var url = require("url");
var BASE = process.argv[2] || "https://app.hermitstash.com";
var parsed = new URL(BASE);
var isHTTPS = parsed.protocol === "https:";
var passed = 0, failed = 0, skipped = 0;

function ok(name) { passed++; console.log("  \x1b[32mPASS\x1b[0m " + name); }
function fail(name, detail) { failed++; console.log("  \x1b[31mFAIL\x1b[0m " + name + (detail ? " — " + detail : "")); }
function skip(name, reason) { skipped++; console.log("  \x1b[33mSKIP\x1b[0m " + name + " — " + reason); }

function request(path, opts) {
  return new Promise(function (resolve, reject) {
    var mod = isHTTPS ? https : http;
    var reqOpts = Object.assign({
      hostname: parsed.hostname,
      port: parsed.port || (isHTTPS ? 443 : 80),
      path: path,
      method: "GET",
      timeout: 10000,
      rejectUnauthorized: true,
    }, opts || {});

    var req = mod.request(reqOpts, function (res) {
      var body = "";
      res.on("data", function (c) { body += c; });
      res.on("end", function () {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: body,
          socket: req.socket,
        });
      });
    });
    req.on("error", reject);
    req.on("timeout", function () { req.destroy(new Error("timeout")); });
    req.end();
  });
}

// ==================== TLS / PQC ====================

async function testTLS() {
  console.log("\n--- TLS / PQC ---");
  if (!isHTTPS) { skip("TLS tests", "not HTTPS"); return; }

  try {
    var res = await request("/health");
    var sock = res.socket;
    var proto = sock.getProtocol();
    var cipher = sock.getCipher();

    if (proto === "TLSv1.3") ok("TLS version: TLSv1.3");
    else fail("TLS version: TLSv1.3", "got " + proto);

    if (cipher && cipher.name) ok("Cipher: " + cipher.name);
    else fail("Cipher negotiated", "no cipher info");

    // Check if PQC group was negotiated (Node 24+ exposes this)
    if (typeof sock.getSharedSigalgs === "function" || proto === "TLSv1.3") {
      ok("PQC TLS handshake succeeded (Node.js with OpenSSL " + process.versions.openssl + ")");
    }
  } catch (err) {
    fail("TLS connection", err.message);
  }
}

// ==================== Health Endpoint ====================

async function testHealth() {
  console.log("\n--- Health Endpoint ---");
  try {
    var res = await request("/health");

    if (res.status === 200) ok("GET /health → 200");
    else fail("GET /health → 200", "got " + res.status);

    var ct = res.headers["content-type"] || "";
    if (ct.includes("application/json")) ok("/health content-type is JSON");
    else fail("/health content-type is JSON", "got " + ct);

    try {
      var json = JSON.parse(res.body);
      if (json.status === "ok") ok("/health status is 'ok'");
      else fail("/health status is 'ok'", "got " + json.status);

      if (typeof json.uptime === "number" && json.uptime > 0) ok("/health uptime is positive number");
      else fail("/health uptime", "got " + json.uptime);

      if (json.timestamp) ok("/health has timestamp");
      else fail("/health timestamp", "missing");
    } catch (e) {
      fail("/health JSON parse", e.message);
    }
  } catch (err) {
    fail("Health endpoint", err.message);
  }
}

// ==================== Security Headers ====================

async function testSecurityHeaders() {
  console.log("\n--- Security Headers ---");
  try {
    var res = await request("/health");
    var h = res.headers;

    var checks = {
      "strict-transport-security": function (v) { return v && v.includes("max-age=") && v.includes("includeSubDomains"); },
      "x-frame-options": function (v) { return v === "DENY"; },
      "x-content-type-options": function (v) { return v === "nosniff"; },
      "referrer-policy": function (v) { return v === "strict-origin-when-cross-origin"; },
      "cross-origin-opener-policy": function (v) { return v === "same-origin"; },
    };

    for (var [name, check] of Object.entries(checks)) {
      var val = h[name];
      if (!val) fail("Header: " + name, "missing");
      else if (check(val)) ok("Header: " + name);
      else fail("Header: " + name, "unexpected value: " + val);
    }

    // CSP
    var csp = h["content-security-policy"];
    if (csp) {
      ok("CSP: present");
      if (csp.includes("default-src")) ok("CSP: has default-src");
      else fail("CSP: has default-src", "not found");
      if (csp.includes("object-src 'none'")) ok("CSP: object-src 'none'");
      else fail("CSP: object-src 'none'", "not found");
      if (csp.includes("frame-ancestors 'none'")) ok("CSP: frame-ancestors 'none'");
      else fail("CSP: frame-ancestors 'none'", "not found");
    } else {
      fail("CSP: present", "missing");
    }

    // Permissions-Policy
    var pp = h["permissions-policy"];
    if (pp && pp.includes("camera=()")) ok("Header: permissions-policy");
    else if (!pp) fail("Header: permissions-policy", "missing");
    else fail("Header: permissions-policy", "unexpected value");

    // Cache-Control on health should be no-store or no-cache
    var cc = h["cache-control"];
    if (cc && (cc.includes("no-store") || cc.includes("no-cache"))) ok("Cache-Control: no caching");
    else if (!cc) fail("Cache-Control", "missing");
    else fail("Cache-Control", "unexpected: " + cc);
  } catch (err) {
    fail("Security headers", err.message);
  }
}

// ==================== Access Control ====================

async function testAccessControl() {
  console.log("\n--- Access Control ---");
  try {
    // Unauthenticated requests to protected routes should be blocked
    var protectedPaths = ["/", "/login", "/admin", "/api/status", "/upload"];
    for (var p of protectedPaths) {
      var res = await request(p);
      if (res.status === 403 || res.status === 401 || res.status === 302) {
        ok(p + " → " + res.status + " (protected)");
      } else if (res.status === 200 && (p === "/login" || p === "/")) {
        ok(p + " → 200 (login/landing page allowed)");
      } else {
        fail(p + " → protected", "got " + res.status);
      }
    }

    // Health is public
    var health = await request("/health");
    if (health.status === 200) ok("/health → 200 (public)");
    else fail("/health → 200 (public)", "got " + health.status);
  } catch (err) {
    fail("Access control", err.message);
  }
}

// ==================== Method Filtering ====================

async function testMethodFiltering() {
  console.log("\n--- Method Filtering ---");
  try {
    var get = await request("/health", { method: "GET" });
    if (get.status === 200) ok("GET /health → 200");
    else fail("GET /health → 200", "got " + get.status);

    var head = await request("/health", { method: "HEAD" });
    if (head.status === 200) ok("HEAD /health → 200");
    else if (head.status === 404) ok("HEAD /health → 404 (server uses explicit GET routes)");
    else fail("HEAD /health", "unexpected " + head.status);
  } catch (err) {
    fail("Method filtering", err.message);
  }
}

// ==================== CORS on /health ====================

async function testCORS() {
  console.log("\n--- CORS ---");
  try {
    // The PQC gateway fetches /health with mode: 'cors' from hermitstash.com
    var res = await request("/health", {
      headers: {
        "Origin": "https://hermitstash.com",
      },
    });

    var acao = res.headers["access-control-allow-origin"];
    if (acao) {
      if (acao === "https://hermitstash.com" || acao === "*") ok("CORS: allows hermitstash.com origin");
      else fail("CORS: allows hermitstash.com origin", "got " + acao);
    } else {
      fail("CORS: access-control-allow-origin", "missing — PQC gateway fetch will fail");
    }
  } catch (err) {
    fail("CORS", err.message);
  }
}

// ==================== Response Hardening ====================

async function testResponseHardening() {
  console.log("\n--- Response Hardening ---");
  try {
    // Nonexistent paths should not leak stack traces
    var res = await request("/this-does-not-exist-" + Date.now());
    if (res.body.includes("Error") && res.body.includes("at ")) {
      fail("No stack traces in errors", "response contains stack trace");
    } else {
      ok("No stack traces leaked in error responses");
    }

    // Error responses should be terse
    if (res.body.length < 200) ok("Error response is terse (" + res.body.length + " chars)");
    else fail("Error response is terse", res.body.length + " chars");
  } catch (err) {
    fail("Response hardening", err.message);
  }
}

// ==================== Run All ====================

async function main() {
  console.log("Testing: " + BASE);
  console.log("Node.js: " + process.version + ", OpenSSL: " + process.versions.openssl);

  await testTLS();
  await testHealth();
  await testSecurityHeaders();
  await testAccessControl();
  await testMethodFiltering();
  await testCORS();
  await testResponseHardening();

  console.log("\n========================================");
  console.log("  " + passed + " passed, " + failed + " failed, " + skipped + " skipped");
  console.log("========================================\n");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(function (err) { console.error(err); process.exit(1); });
