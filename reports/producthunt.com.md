# Security Audit Report — producthunt.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://producthunt.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | producthunt.com |
| Test date | 2026-09-26 14:54 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 1, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | CT1 | 12 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.127.118:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.127.118:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=2592000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] 12 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: blog.producthunt.com, dev.producthunt.com, internal.producthunt.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "producthunt.com",
  "dns": {
    "a": [
      "104.18.127.118",
      "104.18.126.118"
    ],
    "aaaa": [
      "2606:4700::6812:7f76",
      "2606:4700::6812:7e76"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 1)",
      "mxa.mailgun.org (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "mxb.mailgun.org (pref 10)",
      "alt2.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "tia.ns.cloudflare.com.",
      "alexis.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=sWYBxCa1cFh0ExjFp-gWCOLtuIoy8VhLC9Ldg4TTv0M",
      "v=spf1 include:spf.mail.intercom.io include:spf.mailjet.com include:_spf.mailgun.org include:_spf.eu.mailgun.org include:_spf.google.com -all",
      "google-site-verification=GhCGOP8xrz1df0ncSvYMwPTTAEcpVTVeW4rNMziGCFg",
      "facebook-domain-verification=u33of40eu8wnfhryggfmshexmmsdjy",
      "google-site-verification=Q1HPJR75DAVMk3X5dr1XVya1RwEI69Avb0Z1VQkxaY4",
      "google-site-verification=3kl3Tg8FCPBz_5gLpKzus_04NMD_abDvp2KGxDfikYE",
      "google-site-verification=Ey6WtKaEnT1c-5wi8OI864IrUwiDUTH431l_ezI0Fco",
      "google-site-verification=8qbQNeyJeOoYCS4OjYfdMY7gu3QVQixsMdc6yq4AvUk",
      "google-site-verification=9K2kzf0i4TZ7L5C_IIr9P_79zceMMDHiCSfgA3gnDXc",
      "google-site-verification=97bcfxU6IL0_6xbiIIpTrd8vYkjPWmywjQXbt4X9UW4",
      "google-site-verification=2jKosM5Q7j1UdhkJdI30kEZcTGSdwba30ce6VK8GNyk"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarc-reports@migma.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=producthunt.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  6 18:17:05 2026 GMT",
    "notAfter": "Dec  5 19:16:43 2026 GMT",
    "san": [
      "producthunt.com",
      "internal.producthunt.com",
      "*.internal.producthunt.com"
    ],
    "days_left": 70,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.127.118",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
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
      "domain": "producthunt.com",
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
      "origin": "https://sub.producthunt.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://producthunt.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "source": "certspotter",
    "count": 12,
    "notable": [
      "blog.producthunt.com",
      "dev.producthunt.com",
      "internal.producthunt.com"
    ],
    "sample": [
      "api-v2-docs.producthunt.com",
      "blog.producthunt.com",
      "deeperlearning.producthunt.com",
      "dev-demo1.producthunt.com",
      "dev.producthunt.com",
      "internal.producthunt.com",
      "links-i.producthunt.com",
      "makerstacks.producthunt.com",
      "producthunt.com",
      "s-links.producthunt.com",
      "weirdwideweb.producthunt.com",
      "www.dev-demo1.producthunt.com"
    ]
  },
  "elapsed_s": 4.9,
  "rechecked": "2026-09-26 16:29 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
