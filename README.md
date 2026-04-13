# HermitStash Web — PQC Gateway

Cloudflare Worker that serves the landing page at `hermitstash.com` and verifies the visitor's browser supports post-quantum TLS before redirecting to the app at `app.hermitstash.com`.

## How it works

1. Visitor hits `hermitstash.com`
2. Worker serves a single-page PQC handshake UI
3. Browser `fetch()` to `app.hermitstash.com/health` (CORS mode)
4. If the fetch succeeds (browser negotiated PQC TLS with the server) — redirect to app
5. If it fails (browser can't do PQC) — show browser requirements

## Security

- Rate limiting (30 req/min per IP)
- Bot UA blocklist (30+ patterns)
- ASN blocking (TOR exits, known scanners)
- Browser fingerprint check (accept-language, sec-fetch-dest)
- Strict CSP with nonces
- HSTS with preload

## Deploy

```bash
wrangler deploy
```

## Configuration

Set `PQC_ORIGIN` in `wrangler.toml` to your app's URL:

```toml
[vars]
PQC_ORIGIN = "https://app.hermitstash.com"
```

## Local development

```bash
wrangler dev
```

## License

MIT
