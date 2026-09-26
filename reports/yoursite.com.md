# Security Audit Report — yoursite.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yoursite.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | yoursite.com |
| Test date | 2026-09-26 02:48 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 5, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | CT1 | 2 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] 2 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "yoursite.com",
  "dns": {
    "a": [
      "103.224.182.238"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "park-mx.above.com (pref 10)"
    ],
    "ns": [
      "ns2.abovedomains.com.",
      "ns1.abovedomains.com."
    ],
    "spf": [
      "v=spf1 ip6:fdcf:abda:4154::/48 -all"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=yoursite.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Sep  9 18:28:37 2026 GMT",
    "notAfter": "Dec  8 18:28:36 2026 GMT",
    "san": [
      "*.38.yoursite.com",
      "*.app.yoursite.com",
      "*.baiji.yoursite.com",
      "*.baz.yoursite.com",
      "*.blog.yoursite.com",
      "*.booking.yoursite.com",
      "*.brainstormwith.me",
      "*.cariget.com",
      "*.ccc73572.top",
      "*.ccc73586.top",
      "*.chat.yoursite.com",
      "*.cn.yoursite.com",
      "*.com.yoursite.com",
      "*.community.yoursite.com",
      "*.comwww.yoursite.com",
      "*.contact.yoursite.com",
      "*.cureacne.yoursite.com",
      "*.d0a.yoursite.com",
      "*.dev.yoursite.com",
      "*.discourse.yoursite.com",
      "*.dns-ta.yoursite.com",
      "*.eliteweddingvow.beauty",
      "*.email.yoursite.com",
      "*.flourishgardenspro.vip",
      "*.ftp.yoursite.com",
      "*.git.yoursite.com",
      "*.hzmyk.cc",
      "*.iherb.yoursite.com",
      "*.int.yoursite.com",
      "*.ipv6.yoursite.com",
      "*.jobs.yoursite.com",
      "*.john.yoursite.com",
      "*.joomla.yoursite.com",
      "*.js5133.top",
      "*.js9761.top",
      "*.kids-web.com",
      "*.kjsuperstar.com",
      "*.kr.yoursite.com",
      "*.lawspotmax.com",
      "*.listmonk.yoursite.com",
      "*.lng.yoursite.com",
      "*.m.yoursite.com",
      "*.mail.yoursite.com",
      "*.mydatascope.yoursite.com",
      "*.mysite.yoursite.com",
      "*.nvidiahrcollaborationandcommunicationsuite.com",
      "*.oribangsa.sbs",
      "*.pedidofacil.sbs",
      "*.phpmyadmin.yoursite.com",
      "*.rpl.yoursite.com",
      "*.shoppingcart.yoursite.com",
      "*.site.yoursite.com",
      "*.site1.yoursite.com",
      "*.square.yoursite.com",
      "*.staging.yoursite.com",
      "*.static.yoursite.com",
      "*.straight-poker.com",
      "*.sub-domain.yoursite.com",
      "*.test.yoursite.com",
      "*.thrivefitxperience.club",
      "*.vitalfocusfitness.club",
      "*.weblog.yoursite.com",
      "*.www.yoursite.com",
      "*.yourblog.yoursite.com",
      "*.yourhost.yoursite.com",
      "*.yoursite.com",
      "*.yxglqc.vip",
      "*.za.yoursite.com",
      "*.zm.yoursite.com",
      "brainstormwith.me",
      "cariget.com",
      "ccc73572.top",
      "ccc73586.top",
      "eliteweddingvow.beauty",
      "flourishgardenspro.vip",
      "hzmyk.cc",
      "js5133.top",
      "js9761.top",
      "kids-web.com",
      "kjsuperstar.com",
      "lawspotmax.com",
      "nvidiahrcollaborationandcommunicationsuite.com",
      "oribangsa.sbs",
      "pedidofacil.sbs",
      "straight-poker.com",
      "thrivefitxperience.club",
      "vitalfocusfitness.club",
      "yoursite.com",
      "yxglqc.vip"
    ],
    "days_left": 73,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "103.224.182.238",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.yoursite.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 0
  },
  "subdomains": {
    "source": "certspotter",
    "count": 2,
    "notable": [],
    "sample": [
      "ww38.yoursite.com",
      "yoursite.com"
    ]
  },
  "elapsed_s": 45.0,
  "rechecked": "2026-09-26 02:49 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
