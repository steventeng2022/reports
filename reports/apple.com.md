# Security Audit Report — apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | apple.com |
| Test date | 2026-09-25 08:37 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 4, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "apple.com",
  "dns": {
    "a": [
      "17.253.144.10"
    ],
    "aaaa": [
      "2620:149:af0::10"
    ],
    "cname": null,
    "mx": [
      "mx-in-vib.apple.com (pref 20)",
      "mx-in-sg.apple.com (pref 20)",
      "mx-in-ma.apple.com (pref 20)",
      "mx-in-hfd.apple.com (pref 20)",
      "mx-in.g.apple.com (pref 10)",
      "mx-in-rn.apple.com (pref 20)"
    ],
    "ns": [
      "b.ns.apple.com.",
      "d.ns.apple.com.",
      "a.ns.apple.com.",
      "c.ns.apple.com."
    ],
    "spf": [
      "google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c",
      "webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8",
      "_khcec23xgc5b2lb981hup1csjb4cdnz",
      "lucidlink-verification=SCDW9V44GJHAVXKFS6ZY6EZ2YR",
      "v=spf1 include:_spf.apple.com include:_spf-txn.apple.com ~all",
      "google-site-verification=8M6XjQCzydT62jk8HY3VXPAG-nKDllTRV-JpA3-Ktyw",
      "json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJpZW4wYWVHaGF0aG9oNmhhaHZpZWphaTNlYXkwYWh2YWhjaGFocXVhZWxlZTBZdWw0cGhpZXRoMHNvNXZpZXllZWNvaDRpZThzaGVlcGllVDNwYWVjaGVpVjZqb2h3aWVwaG82In0K",
      "cisco-ci-domain-verification=6f3bfb849796a518061f8e8c4356f687a138502d86db742791685059176547dd",
      "facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v",
      "yahoo-verification-key=Ay+djyw0qWQgXKWGA/jstjYryTMrKb+PBXI5l8u5/jw=",
      "apple-domain-verification=X5Jt76bn3Dnmgzjj",
      "Dynatrace-site-verification=7d881a7c-c13f-4146-9d27-2731459e2509__iqls0105tagglcsaul0m16ibrf",
      "ValidationTokenValue=77a4a6de-da14-449c-83c4-85366e0f55f9",
      "_eht2v8yfz1agpq7o4zdkkz3k0k86fyr",
      "atlassian-domain-verification=qZD4TfnCAoAjCFQgafhoKQpOs9tviekNK4wYE4a5eK3XoRP06hXAvEp8SLU0v7fI",
      "adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c",
      "google-site-verification=zBSq1mG5ssu2If-C17UAz_MzSZDcx03MVxmeDwMNc5w",
      "json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJxdWFoMGVpamFhNGVlajh0aWVkYWlnaG9jZWljaGFlOGVUb3ppZTVmdTVhaFRoMldlaU00aWsyaHVxdThpZXBoaWVxdW9oc2hlaXBhZWdoOUthZWw3b2NoaWVuZ2llem9lc2g1In0K",
      "miro-verification=2494d255c4c50b1e521650a0659cbf3fa08b0072",
      "atlassian-domain-verification=mLabq99iaT8kquJechF6l31FAYoNUe3WB7tLpLFUiUYVJCse9SKq83hOJzFkwqrh",
      "77a4a6de-da14-449c-83c4-85366e0f55f9",
      "cerner-client-id=22dd1d8a-5e8b-4e1e-80ef-39bcdfd42798",
      "cerner-client-id=ce3abf18-ee87-43b9-9927-9eb24b4bac4a"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "businessCategory=Private Organization, jurisdictionCountryName=US, jurisdictionStateOrProvinceName=California, serialNumber=C0806592, countryName=US, stateOrProvinceName=California, localityName=Cupertino, organizationName=Apple Inc., commonName=apple.com",
    "issuer": "countryName=US, organizationName=Apple Inc., commonName=Apple Public EV Server ECC CA 1 - G1",
    "notBefore": "Aug 13 16:20:01 2026 GMT",
    "notAfter": "Nov  5 20:55:13 2026 GMT",
    "san": [
      "apple.com"
    ],
    "days_left": 41,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "17.253.144.10",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.apple.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.apple.com/"
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 77.1,
  "rechecked": "2026-09-25 13:59 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
