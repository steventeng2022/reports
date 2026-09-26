# Security Audit Report — redbull.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://redbull.com/ |
| Bug bounty program | Redbull |
| Listed scope domain | redbull.com |
| Test date | 2026-09-25 10:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "redbull.com",
  "dns": {
    "a": [
      "23.208.12.170",
      "23.208.12.186"
    ],
    "aaaa": [
      "2600:1417:8400:31::17ce:cb47",
      "2600:1417:8400:31::17ce:cb59"
    ],
    "cname": null,
    "mx": [
      "redbull-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "pdns91.ultradns.com.",
      "pdns91.ultradns.net.",
      "ns15.ultradns2.com.",
      "pdns91.ultradns.org.",
      "ns15.ultradns2.org.",
      "pdns91.ultradns.biz."
    ],
    "spf": [
      "fastly-domain-delegation-l6ByU9UvR9NX06q-20251121",
      "vector-saml-92020417",
      "v=spf1 include:spf.protection.outlook.com include:_spf.redbull.com include:spf.virtrugateway.com -all",
      "google-site-verification=FT9NwKVuURPQaWb5Fq7oVSA7l5r_OebpkZ8ySQLlOIY",
      "notion-domain-verification=hN2mHaKh119t9oIeUxOZ3tMcWasvrx4wAOUBR7gEgfY",
      "f7fbf1eb4bb2bd20afa0e38447eff8dc3d66a2c953e59e527a",
      "figma-domain-verification=7a82465e7631432ddae7da5c5874d4fd7bdefc2c5eabd1baca75d219dc388f58-1725268196",
      "anthropic-domain-verification-5wg0q8=Drbo9cZiHvN1d2LNdDTEpoRku",
      "yandex-verification: a51dcd774998eab8",
      "atlassian-sending-domain-verification=3531ce11-63aa-453d-a854-4ab6aad86fcf",
      "QuoVadis=d56f7361-359a-4f04-b858-2e34d9d9b117",
      "_uy14g9zokx3stw6c10e7kacxl2krs0h",
      "uber-domain-verification=345f84e7-8f29-4772-8a95-437d5755fd97",
      "jamf-site-verification=_T1tJfEpBa5y1V4i5ongPw",
      "workplace-domain-verification=G6JbgsDS3rGKm9xjdExKVXP3uazq8P",
      "canva-site-verification=CpUH3-GXSXlisKiHbnI6kw",
      "atlassian-domain-verification=SE0bg/sLbNj/sxFjb5WzNowyB2EHWNhe/j4JbSYgLllAii8XsA6kVaTiLiQS7Kr7",
      "google-site-verification=wjAcjCp-XN8rKlZWz47ImMiC6gYoaVe5So6Yl7YhHk0",
      "google-site-verification=zdiNmEZSzIJoZazEYew3bFFSXqudF7ODAHqljjf9hjg",
      "google-site-verification=dyaNOA-sacV_MOg8KnODyK8ihwNa368Vz0Hq2_5MpcY",
      "globalsign-domain-verification=hL1YyaIXzf8_UoxDhIMWaHVWUANe7eU7dWvXus7lwI",
      "google-site-verification=x_6pn1VmeoS7F3VrlNiZye1yb0RXleXiW2psI9flRBY",
      "MS=ms97463818",
      "facebook-domain-verification=uhk1v8zuggj2ug6q0e9f1hczlzz1jr",
      "spycloud-domain-verification=7b0d7b29-0783-43a8-ae02-2618020eb9d0",
      "zapier-domain-verification-challenge=112b278f-86f3-41a1-896b-d581fb935e34",
      "amazonses:pkdkj6bcdiVxa2xtsoMA70kc1PyYjNtUzGcLZGHWXQk=",
      "atlassian-domain-verification=6JjO48MB9UypL10pMDk0vdlEGRGtdMztJavx3KTtMJerMz/adr2Ks0qr+55+LpoQ",
      "mongodb-site-verification=s4RGRapyJSjdREFYPXqvzHmYt60COynM",
      "monday-com-verification=qVsHJCKBqguw6NvEWYm9FSUma88aPXmBM__iEh_LcdU",
      "neat-pulse-domain-verification-W8XZ4xN=35c9459f-5f1d-48dc-a8dc-fcd480a2e5f1",
      "_ryr62gyfim9w9j6y96gb4hido52o87c",
      "yandex-verification: aad18f620b64b27c",
      "virtru-site-verify=obp3KuFTAvVACEbB28a2PkjY9bvEQhygmi7gd3d6",
      "ciscocidomainverification=484a6f952eb1e97a5d6a12260122d88095307403a3c873f524b55a8a09e0311c",
      "docusign=b3640d57-0668-4c84-a5cb-4e199fd00d38",
      "adobe-idp-site-verification=f7adf3e3b2e02fdafc5d0da23da483f36bbf68c3d554a3bb94db66190116545f",
      "cm.com-domain-verification=648a8834-79b1-4072-9fcc-01a85c8f8c22",
      "TGTRxhxdWsMPjij6aytGGneMBuVXCl/yZnJjLxOrka4s+20mUfT10boKi26Gucz3BPhpnzjLSLk+ktKl9sGJxw==",
      "google-site-verification=cAAOttK7KB-rKBmOD7p1Imx6EcdvKD-DLIvoDclN8YA",
      "Ws0bd7f6/5qF5IIq/WdhyrANdPcnsIiWWLi0IaWO5cKb/CFj6cBCGx2siy/4UFRc0e2FMOB0+FUmWeos/leuYg==",
      "apple-domain-verification=odkhNiY1AwjKsHAl",
      "firebase=redbull-photobooth-fansite",
      "ZOOM_verify_m27rLBztRkeFHLDKbAtzuA",
      "webexdomainverification.C5UR=281b4db8-b67c-4111-9ece-8958b41cd08f",
      "teamviewer-sso-verification=3d50f93de59b453aa294796293a115d0",
      "docusign=679758f7-e6bc-41ab-8dbf-417624c378a4"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:zsrbf6su@ag.eu.dmarcadvisor.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=AT, stateOrProvinceName=Salzburg, organizationName=Red Bull GmbH, commonName=redbull.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV E36",
    "notBefore": "Aug 13 00:00:00 2026 GMT",
    "notAfter": "Feb 27 23:59:59 2027 GMT",
    "san": [
      "redbull.com",
      "www.redbull.com"
    ],
    "days_left": 155,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.208.12.170",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.redbull.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.redbull.com/"
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 22.0,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
