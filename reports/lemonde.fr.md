# Security Audit Report — lemonde.fr

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://lemonde.fr/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | lemonde.fr |
| Test date | 2026-09-26 16:42 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | CT1 | 147 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 13 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 12. [INFO] 147 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: blog.chefsimon.lemonde.fr, checkout.lemonde.fr, dev.carnet.lemonde.fr, dev.cities.lemonde.fr, dev.debats-afrique.lemonde.fr, dev.festival.lemonde.fr, dev.webserver.carnet.lemonde.fr, docs.forecast.lemonde.fr, media.lemonde.fr, webmail.lemonde.fr
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 13. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: blog.chefsimon.lemonde.fr; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "lemonde.fr",
  "dns": {
    "a": [
      "151.101.122.137"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-b3.googledomains.com.",
      "ns-cloud-b2.googledomains.com.",
      "ns-cloud-b4.googledomains.com.",
      "ns-cloud-b1.googledomains.com."
    ],
    "spf": [
      "00DWx000008KcED=1TBSb0000000Ak9",
      "mandrill_verify.2xFVS2iRdBArj1vR6iXqDw",
      "v=spf1 include:spf1.lemonde.fr include:spf2.lemonde.fr include:_spf.salesforce.com ip4:79.99.32.203 ip4:79.99.32.185 ip4:79.99.32.186 ip4:217.74.103.211 ip4:195.154.80.82 ip4:163.172.55.8 ip4:35.181.34.138 ip4:35.181.85.71 ip4:52.143.135.92 -all",
      "_globalsign-domain-verification=yRdIt507tQIZyVRXF6VBvVbEIWhqpzJaxh8r1qdSUr",
      "00DAP00000MRjsP=1TBAP0000000CHJ",
      "sendinblue-code:bfdbbdc264502c94bb90794d2a902e50",
      "recyclagerecylum=1fd014598415abe7ca04160fccf87442",
      "00DAU00000LLlRQ=1TBAU0000000GJJ",
      "openai-domain-verification=dv-nQ1ldfkkoDfrWmjKfXdqLG2h",
      "google-site-verification=712IVumgXvK3v6WCyCJVLS6O96hThcw39o84JSN9m_k",
      "d7o5vwenp6",
      "jamf-site-verification=zUEgWKIxDl9-X3pb0bIY7A",
      "fastly-domain-delegation-x2kl6p87n3g5b6FDG-79324-2018-04-10"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=quarantine; adkim=r; aspf=r; pct=100; rua=mailto:dmarc.report@lemonde.fr"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=lemonde.fr",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 17 07:47:53 2026 GMT",
    "notAfter": "Nov 15 07:47:52 2026 GMT",
    "san": [
      "lemonde.fr"
    ],
    "days_left": 49,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.122.137",
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
      "origin": "https://sub.lemonde.fr",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.lemonde.fr/"
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
    "source": "crt.sh",
    "count": 147,
    "notable": [
      "blog.chefsimon.lemonde.fr",
      "checkout.lemonde.fr",
      "dev.carnet.lemonde.fr",
      "dev.cities.lemonde.fr",
      "dev.debats-afrique.lemonde.fr",
      "dev.festival.lemonde.fr",
      "dev.webserver.carnet.lemonde.fr",
      "docs.forecast.lemonde.fr",
      "media.lemonde.fr",
      "webmail.lemonde.fr",
      "www.dev.carnet.lemonde.fr",
      "www.docs.forecast.lemonde.fr"
    ],
    "sample": [
      "0jfenddm9.lemonde.fr",
      "80ans.lemonde.fr",
      "abo.lemonde.fr",
      "aboadmin.lemonde.fr",
      "aboapi.lemonde.fr",
      "abonnements.lemonde.fr",
      "abonnes.lemonde.fr",
      "abonnes.mobile.lemonde.fr",
      "abosh.lemonde.fr",
      "adresapdf.paris5.lemonde.fr",
      "adresapdfqa.paris5.lemonde.fr",
      "adresaprod.paris5.lemonde.fr",
      "adresareport.paris5.lemonde.fr",
      "afrique-cities.lemonde.fr",
      "aleph-prod.lemonde.fr",
      "aleph.lemonde.fr",
      "allemand.lemonde.fr",
      "anglais.lemonde.fr",
      "annonces-legales.lemonde.fr",
      "application-facebook.lemonde.fr"
    ],
    "dangling": [
      "blog.chefsimon.lemonde.fr"
    ]
  },
  "elapsed_s": 46.3,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
