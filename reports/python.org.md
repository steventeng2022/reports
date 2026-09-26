# Security Audit Report — python.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://python.org/ |
| Bug bounty program | PSF |
| Listed scope domain | python.org |
| Test date | 2026-09-26 14:55 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | CT1 | 48 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] 48 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.wiki.python.org, blog.python.org, jobs.python.org, mail.python.org, status.python.org, wiki.python.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "python.org",
  "dns": {
    "a": [
      "151.101.64.223",
      "151.101.0.223",
      "151.101.192.223",
      "151.101.128.223"
    ],
    "aaaa": [
      "2a04:4e42:200::223",
      "2a04:4e42:600::223",
      "2a04:4e42:400::223",
      "2a04:4e42::223"
    ],
    "cname": null,
    "mx": [
      "mail.python.org (pref 50)"
    ],
    "ns": [
      "ns-981.awsdns-58.net.",
      "ns-1134.awsdns-13.org.",
      "ns-484.awsdns-60.com.",
      "ns-2046.awsdns-63.co.uk."
    ],
    "spf": [
      "anthropic-domain-verification-x3xt87=cFLP3aL71pAYPZLQR7JKvRhcF",
      "libera-1298aas",
      "google-site-verification=dqhMiMzpbkSyEhgjGKyEOMlEg2tF0MSHD7UN-MYfD-M",
      "google-site-verification=9852CbTRhQ51-9gCUayPbGYqJeBle_MXLb6E4AL_qQk",
      "888acb5757da46ad83b7e341ec544c64",
      "MS=73147F1EC0843C399CF17F586EC6B8EAF8C57961",
      "twilio-domain-verification=1c295667813cc0aaae819ed7657818f8",
      "openai-domain-verification=dv-VgeNijVDgW7g56UZyGIVyKNr",
      "google-site-verification=QALZObrGl2OVG8lWUE40uVSMCAka316yADn9ZfCU5OA",
      "_globalsign-domain-verification=B57sRQpmte4G4w-gavZbVNmmNsMxGp5kcL19UP2599",
      "status-page-domain-verification=9y2klhzbxsgk",
      "v=spf1 mx ip4:188.166.95.178/32 ip6:2a03:b0c0:2:d0::71:1 include:stspg-customer.com include:_spf.google.com include:mailgun.org ~all",
      "google-site-verification=w3b8mU3wU6cZ8uSrj3E_5f1frPejJskDpSp_nMWJ99o"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:re+shb8ybr70a3@dmarc.postmarkapp.com; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=www.python.org",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2025 Q4",
    "notBefore": "Jan 13 13:03:46 2026 GMT",
    "notAfter": "Feb 14 13:03:45 2027 GMT",
    "san": [
      "www.python.org",
      "*.python.org",
      "python.org"
    ],
    "days_left": 140,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.64.223",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.python.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.python.org/"
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
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 48,
    "notable": [
      "api.wiki.python.org",
      "blog.python.org",
      "jobs.python.org",
      "mail.python.org",
      "status.python.org",
      "wiki.python.org"
    ],
    "sample": [
      "africa.python.org",
      "analytics.python.org",
      "api.wiki.python.org",
      "blog.python.org",
      "bugs.python.org",
      "buildbot.python.org",
      "calendario.es.python.org",
      "cheeseshop.python.org",
      "cla.python.org",
      "community.uk.python.org",
      "comunidad.es.python.org",
      "comunidades.es.python.org",
      "console.python.org",
      "devguide.python.org",
      "discuss.python.org",
      "diversity.python.org",
      "documentos-asociacion.es.python.org",
      "donate.python.org",
      "education.python.org",
      "es.python.org"
    ]
  },
  "elapsed_s": 30.1,
  "rechecked": "2026-09-26 16:29 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
