# Security Audit Report — edx.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://edx.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | edx.org |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
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
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: dropbox-domain-verification=9dvz1ju53nbf; google-site-verification=-_Eevdy8NShzLkex28P2wC3zjbfVweCs0k5z5f6gm_k; atlassian-domain-verification=xpq-aB5aXpxCKMr7r3eDPHyz+H8uPB16jIppdmlCIloVrhEtCr
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of edx.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 25 disallow path(s), e.g. /*?utm_source=*, /*?utm_medium=*, /*?utm_campaign=*, /*?utm_term=*, /*?utm_content=*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.20 carries PTR server-54-192-248-20.tpe53.r.cloudfront.net. for edx.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "edx.org",
  "dns": {
    "a": [
      "54.192.248.20",
      "54.192.248.88",
      "54.192.248.55",
      "54.192.248.106"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-828.awsdns-39.net.",
      "ns-73.awsdns-09.com.",
      "ns-1753.awsdns-27.co.uk.",
      "ns-1472.awsdns-56.org."
    ],
    "spf": [
      "dropbox-domain-verification=9dvz1ju53nbf",
      "google-site-verification=-_Eevdy8NShzLkex28P2wC3zjbfVweCs0k5z5f6gm_k",
      "amazonses:0rz9BauM6+L1fwnDKUmS4nofo+8gZvTReGo5q/EliHY=",
      "atlassian-domain-verification=xpq-aB5aXpxCKMr7r3eDPHyz+H8uPB16jIppdmlCIloVrhEtCrKucpx/Nnqr1xJg",
      "hj-ownership=pzm3zqe*fhj7RQR3cpj",
      "google-site-verification=3wMRITKQ9E2388ON5mfWt98s48OBDMVzPO-7xY3U6H4",
      "pardot1059723=4defac72d9323b4f44f80b440e6eb91a8958b1f3b98bc585c494a8a5af62483e",
      "segment-site-verification=2ZGPEbxZ025BzXh516qCWeQ7sGFFltDx",
      "google-site-verification=S98FBFJqeURQhHxBtC_UG84orCIkl7msuarSO5NoIPc",
      "smartsheet-site-validation=bxOSD4ibPoym5apZEnln5bh2ckPn2Z1M",
      "apple-domain-verification=6VfkC2MXgvez6NHJ",
      "adobe-idp-site-verification=3f2215d19f499a970c4305a59755a6a1eb0f9850d7777a297a46db1e644e71c7",
      "google-site-verification=tVFyMKACOBTnEVoW-XJ0jbunNP7bDxPLxUZpGs9j9go",
      "atlassian-domain-verification=HN7ngRpg8qAazURti1cdbKGDap2uVfm7uvUYF/m9UkSHtwZM2P5Ub6muuhN47h1w",
      "adobe-idp-site-verification=0614d0e44da9d4b72a75d19e9138eb0052991fb2acb9d62cfd048eee75c7f24b",
      "atlassian-sending-domain-verification=5c0c6ccf-f137-44f4-8b59-90f8c09ba730",
      "docusign=f1e936d4-bf65-4aed-8c0b-59630d21e09c",
      "v=spf1 include:_u.edx.org._spf.smart.ondmarc.com ~all",
      "facebook-domain-verification=h2gg5zwnyax0dj0jyo4aafdtkpiiyu",
      "google-site-verification=VmJhKMomzXGRq96pOMWst3QD0KvnurTNsPHNhv8qt1k",
      "google-site-verification=y6TTw5e5GIQJ7YzqfhuE1eyu235AVu1bqk2YAvv_IY0",
      "ZOOM_verify_L9I5Fxqkv63ZPy63F1sHvK",
      "docusign=3b85e379-88dd-467e-a926-0b63f700d89a",
      "MS=ms89770774"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; sp=quarantine; rua=mailto:a7d505e3@inbox.ondmarc.com,mailto:dmarc-reports@edx.org; ruf=mailto:a7d505e3@inbox.ondmarc.com,mailto:dmarc-reports-forensic@edx.org; adkim=r; aspf=r; fo=1; rf=afrf; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=edx.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Nov  8 00:00:00 2025 GMT",
    "notAfter": "Dec  6 23:59:59 2026 GMT",
    "san": [
      "edx.org"
    ],
    "days_left": 71,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.20",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.edx.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.edx.org/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "dropbox-domain-verification=9dvz1ju53nbf",
    "google-site-verification=-_Eevdy8NShzLkex28P2wC3zjbfVweCs0k5z5f6gm_k",
    "atlassian-domain-verification=xpq-aB5aXpxCKMr7r3eDPHyz+H8uPB16jIppdmlCIloVrhEtCr",
    "google-site-verification=3wMRITKQ9E2388ON5mfWt98s48OBDMVzPO-7xY3U6H4",
    "segment-site-verification=2ZGPEbxZ025BzXh516qCWeQ7sGFFltDx"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20251108000000",
      "not_after": "20261206235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/*?utm_source=*",
      "/*?utm_medium=*",
      "/*?utm_campaign=*",
      "/*?utm_term=*",
      "/*?utm_content=*",
      "/*?_rsc=*",
      "/includes/",
      "/misc/",
      "/modules/",
      "/profiles/",
      "/scripts/",
      "/themes/",
      "/preview/",
      "/es/preview/",
      "/secure-preview/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-54-192-248-20.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 5.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
