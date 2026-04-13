# HermitStash Web — PQC Gateway

A Cloudflare Worker that serves the landing page at [`hermitstash.com`](https://hermitstash.com) and gates access to the app at [`app.hermitstash.com`](https://app.hermitstash.com) on post-quantum TLS support.

The visitor's browser must negotiate a hybrid post-quantum key exchange (`X25519MLKEM768`) with the app origin; if it can't, the gateway blocks the redirect and shows a browser-upgrade screen instead. This is a defense against "harvest now, decrypt later" attacks — everyone routed through HermitStash is already on PQC the moment they arrive.

## How it works

1. Browser hits `https://hermitstash.com/`
2. Worker runs the request filter chain (method → path → rate limit → bot UA → ASN → browser fingerprint); anything that fails is blocked
3. Worker serves a single static HTML page with a strict CSP, a per-request nonce, and an embedded handshake UI
4. Client-side JS issues a CORS `fetch()` to `https://app.hermitstash.com/health`
5. If the fetch succeeds, the browser negotiated PQC TLS with the app — redirect to the app
6. If the fetch fails (for any reason — no PQC, TLS error, aborted, etc.) — show the PQC requirements screen with a link to [pq.cloudflareresearch.com](https://pq.cloudflareresearch.com) so the visitor can verify their browser

The PQC check is end-to-end between the visitor's browser and the app origin. The gateway never proxies the health check — if it did, the whole point would collapse.

## Browser requirements

| Browser  | Minimum version  |
| -------- | ---------------- |
| Chrome   | 131              |
| Edge     | 131              |
| Firefox  | 135              |
| Safari   | TBD              |

## Request filter chain

Order is load-bearing. Do not reorder.

1. **Method** — only `GET` and `HEAD`; anything else → `405 Method Not Allowed`
2. **Path** — only `/`; any other path → `301` redirect to root
3. **Rate limit** — 30 requests / 60 seconds per `cf-connecting-ip`, in-memory per isolate (best-effort; not a global counter). Probabilistic cleanup (~1% chance per request) keeps the map bounded.
4. **Bot UA blocklist** — 37 substring patterns matched case-insensitively against the `User-Agent` header. Empty UAs are treated as bots. Covers: `curl`, `wget`, `python`, `httpie`, `scrapy`, `go-http`, `java/`, `libwww`, `php/`, `ruby`, `perl`, `nikto`, `sqlmap`, `nmap`, `masscan`, `zgrab`, `semrush`, `ahref`, `mj12bot`, `bytespider`, `gptbot`, `ccbot`, `claudebot`, `anthropic`, `dataforseo`, `headlesschrome`, `phantomjs`, `selenium`, `puppeteer`, `playwright`, `applebot`, `yandexbot`, `baiduspider`, `aiohttp`, and friends.
5. **Blocked ASNs** — TOR exits, known open proxies, and internet scanners. Currently blocks AS209 (TOR), AS396507, AS212238, AS63949, AS211590 (FBW Networks — stripe/env scanner), AS213737 (AYOSOFT — vuln scanner), AS213412 (ONYPHE — internet scanner), AS9009 (UAB code200 — proxy/scanner).
6. **Browser fingerprint** — requires `Accept-Language`, an `Accept` header containing `text/html`, and at least one of `Sec-Fetch-Dest` or `Upgrade-Insecure-Requests`. Headless tools that forget these get dropped.

Anything that fails after step 2 gets a terse `403 Access Denied` with no body leaking why.

## Security

Every successful HTML response sets the following headers:

- **Content-Security-Policy** — `default-src 'none'`, nonce-based `script-src` (no `unsafe-inline`, no `unsafe-eval`), `style-src 'unsafe-inline' https://fonts.googleapis.com`, `font-src https://fonts.gstatic.com`, `connect-src https://app.hermitstash.com`, `img-src 'self' https://assets.hermitstash.com`, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`
- **Strict-Transport-Security** — `max-age=31536000; includeSubDomains; preload`
- **X-Frame-Options** — `DENY`
- **X-Content-Type-Options** — `nosniff`
- **Referrer-Policy** — `strict-origin-when-cross-origin`
- **Permissions-Policy** — camera, microphone, geolocation, payment, USB, bluetooth, serial all disabled
- **Cross-Origin-Opener-Policy** — `same-origin`
- **Cross-Origin-Embedder-Policy** — `require-corp`
- **Cross-Origin-Resource-Policy** — `same-origin`

The script nonce is generated per-request from `crypto.getRandomValues(Uint8Array(16))` and templated only into the single `<script nonce="...">` tag and the CSP header. Inline event handlers (`onclick=`, `onload=`, etc.) are not used and would be blocked if added.

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting policy.

## Project conventions

- **Zero dependencies.** The worker is a single file using only the Cloudflare Workers runtime. No npm packages are bundled into the deploy; `wrangler` is the only devDep.
- **Single entry point.** Everything — rate limiter, bot filter, ASN blocklist, security headers, HTML template, client JS — lives in `src/worker.js` for auditability.
- **No build step.** ES modules, plain functions, inline HTML as a JS string array. No TypeScript, no bundler, no asset pipeline.
- **Stateless per-request.** No KV, no Durable Objects, no R2 in the critical path. Runs cold on any edge isolate with no warm-up penalty.

## File structure

```
src/worker.js                  The entire worker — filters, headers, HTML, client JS
wrangler.toml                  Cloudflare deploy config
package.json                   npm scripts for wrangler dev/deploy
.github/workflows/deploy.yml   Auto-deploy on push to main
.github/ISSUE_TEMPLATE/        Bug / feature / question templates
SECURITY.md                    Vulnerability reporting policy
LICENSE                        MIT
```

Static assets (the favicon/logo SVG) are hosted separately at `assets.hermitstash.com` — the worker only references them via `<img src>` and CSP `img-src`.

## Development

```bash
npm install
npm run dev       # wrangler dev — local at http://localhost:8787
node --check src/worker.js   # syntax check
```

There is no test suite. Verification is done by hitting `localhost:8787` in a real browser (Chrome/Firefox with recent versions), inspecting headers with `curl -I` from an allowlisted UA, and confirming the PQC gate behaves correctly in both an old browser (block screen) and a new browser (success + redirect).

If adding test coverage ever becomes worthwhile, prefer [Miniflare](https://miniflare.dev) over mocking — the filter logic depends on `request.cf` and real headers.

## Deployment

Auto-deploy runs via GitHub Actions on every push to `main`. See [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml).

- **Push to `main`** → `wrangler deploy` (live)
- **Pull request to `main`** → `wrangler deploy --dry-run` (validates without deploying)
- **Manual dispatch** → available via the Actions tab

The workflow uses [`cloudflare/wrangler-action@v3`](https://github.com/cloudflare/wrangler-action) and needs two repository secrets:

- `CLOUDFLARE_API_TOKEN` — scoped API token with `Workers Scripts:Edit` on the target account
- `CLOUDFLARE_ACCOUNT_ID` — the target Cloudflare account ID

To deploy manually from a local checkout:

```bash
npm install
npx wrangler deploy
```

## Configuration

Runtime behavior is hardcoded in `src/worker.js`. There are no user-facing runtime flags:

- Rate limit constants live at the top of the file (`RATE_LIMIT_WINDOW`, `RATE_LIMIT_MAX`)
- Bot patterns and blocked ASNs are plain arrays — add to them with a source comment
- The app origin (`https://app.hermitstash.com`) is hardcoded in both the CSP `connect-src` directive and the client-side `PQC_ORIGIN` constant. The `PQC_ORIGIN` env var in `wrangler.toml` exists for documentation only; changing it does not change runtime behavior. If you fork this and point it at a different origin, update the worker source in both places together.

## Related repositories

HermitStash is split across three repos, each with its own release cadence:

- [`dotCooCoo/hermitstash`](https://github.com/dotCooCoo/hermitstash) — the main server (the app at `app.hermitstash.com`)
- [`dotCooCoo/hermitstash-sync`](https://github.com/dotCooCoo/hermitstash-sync) — desktop sync client
- [`dotCooCoo/hermitstash-web`](https://github.com/dotCooCoo/hermitstash-web) — **this repo** (landing page + PQC gateway)

## Contributing

This project is not currently accepting external code contributions — the security surface is small and deliberately kept under single-author review. Bug reports and feature requests via the issue tracker are welcome; see the templates in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/).

If you find a security issue, please follow the coordinated disclosure process in [`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE) — Copyright © 2026 dotCooCoo
