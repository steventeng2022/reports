# Security Audit Report — fb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fb.com/ |
| Bug bounty program | Facebook |
| Listed scope domain | fb.com |
| Test date | 2026-09-25 09:44 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 2, Info: 5)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 7 days (notAfter Oct  2 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15552000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "fb.com",
  "dns": {
    "a": [
      "57.144.92.1"
    ],
    "aaaa": [
      "2a03:2880:f325:1:face:b00c:0:25de"
    ],
    "cname": null,
    "mx": [
      "mxb-00082601.gslb.pphosted.com (pref 10)",
      "mx0a-00082601.pphosted.com (pref 20)",
      "mx0b-00082601.pphosted.com (pref 20)",
      "mxa-00082601.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "c.ns.facebook.com.",
      "b.ns.facebook.com.",
      "d.ns.facebook.com.",
      "a.ns.facebook.com."
    ],
    "spf": [
      "v=spf1 redirect=_spf.fb.com",
      "586957ce-d11e-4efa-9fe5-a887498bf838",
      "parkable-domain-verification=N89SxXel0S4pUXDFVpckFmXIO9MUvN4Or0bO_Lcb8Os=",
      "mentimeter-8599dcd1-e0da-4326-882e-7570e7c942fb",
      "slack-domain-verification=98evShJrgCmABvEiYjXPwVbRybZlSnQPoWY0n7WO",
      "MS=ms56927146",
      "mentimeter-16bdc82d-93be-47de-a6d4-fd6adb17c403",
      "I2B7AuxY6G1G_NeiaHF-9A0zn-3NDBnlOBi4zItNCU8",
      "docusign=ad7f789d-eff1-4283-9d90-fdc9484527e1",
      "google-site-verification=Dsycvk_Ky3uQjdvuPrI_Z6A98lWghNTntdS4LuATOj8",
      "G3X1k1XGYGra1nUpTv7Rdk2wAEFHfkKIr9/4/6+Nu67Ks9cR8xaiqAZPPhis9lGD6mb/+9vygIr4QKXIpxIc7w==",
      "atlassian-domain-verification=I7HLjLnlhJiDT58wzrru2Pd/2cRWa3AKlgCjDPOO43GMP7H0QuafH6eBts3D1GaP",
      "smartsheet-site-validation=sB5xgx-1nsnQCgORYUhnyDG3Jr739OxJ",
      "smartsheet-site-validation=r-TtxwzdAh2KN_Zi6mTLGu02fz-9vQU4"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:a@dmarc.facebookmail.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_CHACHA20_POLY1305_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Menlo Park, organizationName=Meta Platforms, Inc., commonName=*.fb.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul  4 00:00:00 2026 GMT",
    "notAfter": "Oct  2 23:59:59 2026 GMT",
    "san": [
      "*.fb.com",
      "fb.com"
    ],
    "days_left": 7,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "57.144.92.1",
    "open": []
  },
  "https": {
    "status": 400,
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
      "origin": "https://sub.fb.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://fb.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 400,
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 27.3,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
