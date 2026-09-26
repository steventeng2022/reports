# Security Audit Report — zalo.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zalo.me/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | zalo.me |
| Test date | 2026-09-26 16:42 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 6, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | CT1 | 414 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 15 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** Detected: Server: za-ngx-srv
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=86400 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Header reveals: za-ngx-srv
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'NEXT_LOCALE' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] 414 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: 3rdservice.oa.zalo.me, accounts.admin.channel.zalo.me, accounts.admin.taxi.booking.zalo.me, accounts.ads.zalo.me, accounts.beta.developers.zalo.me, accounts.booking.zalo.me, accounts.caiapp.zalo.me, accounts.careers.zalo.me, accounts.channel.zalo.me, accounts.chat.dev.zalo.me
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 15. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: 3rdservice.oa.zalo.me, accounts.admin.channel.zalo.me, accounts.admin.taxi.booking.zalo.me, accounts.ads.zalo.me, accounts.beta.developers.zalo.me; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "zalo.me",
  "dns": {
    "a": [
      "49.213.95.151",
      "49.213.95.189"
    ],
    "aaaa": [
      "2001:df0:13:1::99",
      "2001:df0:13:1::93"
    ],
    "cname": null,
    "mx": [
      "zalo-me.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "zans1.zadns.vn.",
      "zans2.zadns.vn.",
      "zans1.zadns.me.",
      "zans2.zadns.me."
    ],
    "spf": [
      "openai-domain-verification=dv-GDSrB72rpm75o4uQ86kZykcN",
      "v=spf1 a mx include:amazonses.com include:spf.protection.outlook.com include:zapps.me include:zapps.vn ~all",
      "google-site-verification=lpuA40S08EYD9BwfGINK96Y4LC0qkU7CBolRXlaYoT8",
      "google-site-verification=W6B6OX-CH4YVR2qoG-rApRzMLtlkKQeHOZfkOO4NX_U"
    ],
    "dmarc": [
      "v=DMARC1; p=none; sp=reject; ruf=mailto:hotro@zalo.me,mailto:no-reply@zalo.me; rua=mailto:hotro@zalo.me,mailto:no-reply@zalo.me"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "subject": "countryName=VN, stateOrProvinceName=Thành phố Hồ Chí Minh, localityName=Tân Thuận Đông, organizationName=VNG GROUP JSC, commonName=*.zalo.me",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Jul 10 00:00:00 2026 GMT",
    "notAfter": "Jan 24 23:59:59 2027 GMT",
    "san": [
      "*.zalo.me",
      "zalo.me"
    ],
    "days_left": 120,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "49.213.95.151",
    "open": []
  },
  "https": {
    "status": 307,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: za-ngx-srv"
  ],
  "cookies": [
    {
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.zalo.me",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://zalo.me/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 403,
    "/security.txt": 302,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 414,
    "notable": [
      "3rdservice.oa.zalo.me",
      "accounts.admin.channel.zalo.me",
      "accounts.admin.taxi.booking.zalo.me",
      "accounts.ads.zalo.me",
      "accounts.beta.developers.zalo.me",
      "accounts.booking.zalo.me",
      "accounts.caiapp.zalo.me",
      "accounts.careers.zalo.me",
      "accounts.channel.zalo.me",
      "accounts.chat.dev.zalo.me",
      "accounts.chat.stg.zalo.me",
      "accounts.chat.zalo.me",
      "accounts.dev-chat.zalo.me",
      "accounts.dev.chat.zalo.me",
      "accounts.dev.zalo.me"
    ],
    "sample": [
      "3rdservice.oa.zalo.me",
      "accounts.admin.channel.zalo.me",
      "accounts.admin.taxi.booking.zalo.me",
      "accounts.ads.zalo.me",
      "accounts.beta.developers.zalo.me",
      "accounts.booking.zalo.me",
      "accounts.caiapp.zalo.me",
      "accounts.careers.zalo.me",
      "accounts.channel.zalo.me",
      "accounts.chat.dev.zalo.me",
      "accounts.chat.stg.zalo.me",
      "accounts.chat.zalo.me",
      "accounts.dev-chat.zalo.me",
      "accounts.dev.chat.zalo.me",
      "accounts.dev.zalo.me",
      "accounts.developers.zalo.me",
      "accounts.dmp.zalo.me",
      "accounts.erp.zalo.me",
      "accounts.food.zalo.me",
      "accounts.live.zalo.me"
    ],
    "dangling": [
      "3rdservice.oa.zalo.me",
      "accounts.admin.channel.zalo.me",
      "accounts.admin.taxi.booking.zalo.me",
      "accounts.ads.zalo.me",
      "accounts.beta.developers.zalo.me"
    ]
  },
  "elapsed_s": 32.7,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
