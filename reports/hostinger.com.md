# Security Audit Report — hostinger.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hostinger.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hostinger.com |
| Test date | 2026-09-26 16:42 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | CT1 | 117 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.19.150.80:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.19.150.80:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] 117 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.hostinger.com, cdn.hostinger.com, docs.hostinger.com, help.hostinger.com, mail.hostinger.com, mg.store.hostinger.com, sso.hostinger.com, status.hostinger.com, support.hostinger.com, webmail.hostinger.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "hostinger.com",
  "dns": {
    "a": [
      "104.19.150.80",
      "104.19.149.80"
    ],
    "aaaa": [
      "2606:4700::6813:9550",
      "2606:4700::6813:9650"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "dns2.hostinger.com.",
      "dns1.hostinger.com."
    ],
    "spf": [
      "_sslnkubllu80rt3klnta5jj78ohfe31",
      "9dz88hzqmv6f9qp6h6n81ccknqt5qsj5",
      "docusign=2992f799-e2b5-4a59-9478-d87ff226e65b",
      "atlassian-domain-verification=XJK8F7iNQk3gsKAzIMisoRaKR1K3wU11K0QCw662ENGLiGUAYNDUNHX/Ol5F4yyK",
      "anthropic-domain-verification-sbpz2r=8X9I3m1TfwoIB68L9whmSnNoc",
      "MS=ms37476243",
      "nordpass-domain-verification=6b627232b00e4e9ea70693c7994f2d50",
      "figma-domain-verification=bb2a3852187101c21a8a019813cb47acd28c3d9b84f1747c8cbdb7244c36bfda-1737460010",
      "atlassian-sending-domain-verification=42cc4d24-81df-49d0-9693-a168df8fc223",
      "apple-domain-verification=IyFbOUpTx9DUOFwL",
      "google-site-verification=MOjKs17dYrFXyEPndU4bK505my3D0dyC63-c5mvaNGU",
      "openai-domain-verification=dv-9okZFix3JJIj9RBphlsAvfbi",
      "google-site-verification=RLEBWxPy5k2j9nDF2u1A6hcvktrjchIs_6--G1DmgEQ",
      "miro-verification=5d62135ad61fab8158906087fb92a56d0c945430",
      "notion-domain-verification=BtpwrYPzJa32VMexOuoqItloklD9vb0uNmMu357qaif",
      "yahoo-verification-key=YU6422jppAaWZKxEmokKU9sZrUatIZbu69iKw6p2zsI=",
      "cwj6bz8hbrb0362ql3rp9pqlt1wryp6y",
      "cursor-domain-verification-ed8vgx=HaftGMosCA7Suow43DgMeAz0z",
      "mailru-verification: a8a9886e0072b036",
      "google-site-verification=OVQopdHgqSSImLDPT0sUNZZRdXpLVBwDaSqloVGyK6Q",
      "v=spf1 include:_spf.google.com include:amazonses.com include:_spf.hostedemail.com include:_spf.psm.knowbe4.com include:_spf.atlassian.net -all",
      "google-site-verification=4EfGmYRIEIPWA_ACJsA5zFGUzzY1pa8Du2tiHb8EKuI",
      "h1-domain-verification=47Qxwxj28Ps2M1vAa5opS7wHmEMswKJq2rDjd5tem6ZuN7PB"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:1dfdc22fb72e416c8609bbda0450f278@dmarc-reports.cloudflare.net;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.hostinger.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV R36",
    "notBefore": "Feb  2 00:00:00 2026 GMT",
    "notAfter": "Mar  4 23:59:59 2027 GMT",
    "san": [
      "*.hostinger.com",
      "hostinger.com"
    ],
    "days_left": 159,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.19.150.80",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "hostinger.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.hostinger.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.hostinger.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 117,
    "notable": [
      "api.hostinger.com",
      "cdn.hostinger.com",
      "docs.hostinger.com",
      "help.hostinger.com",
      "mail.hostinger.com",
      "mg.store.hostinger.com",
      "sso.hostinger.com",
      "status.hostinger.com",
      "support.hostinger.com",
      "webmail.hostinger.com"
    ],
    "sample": [
      "academy.hostinger.com",
      "affiliates.hostinger.com",
      "affs-stats.hostinger.com",
      "aktivalas.hostinger.com",
      "ambassador.hostinger.com",
      "api.hostinger.com",
      "apstiprina.hostinger.com",
      "autenticacion.hostinger.com",
      "autenticar.hostinger.com",
      "autentificacion.hostinger.com",
      "autentificar.hostinger.com",
      "bekraeft.hostinger.com",
      "builder.hostinger.com",
      "cdn.hostinger.com",
      "clicks.hostinger.com",
      "confirmar.hostinger.com",
      "connect.hostinger.com",
      "convalida.hostinger.com",
      "cpanel.hostinger.com",
      "d.account.hostinger.com"
    ]
  },
  "elapsed_s": 19.3,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
