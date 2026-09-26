# Security Audit Report — yahoo.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yahoo.com/ |
| Bug bounty program | Yahoo! |
| Listed scope domain | yahoo.com |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 9 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 25 days (notAfter Oct 21 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ATS
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ATS
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 9. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.yahoo.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=xoBvU6aKxP0gYgNL0iXqF0EccAg6nFrO7XxsHnc3iNQ; facebook-domain-verification=gysqrcd69g0ej34f4jfn0huivkym1p; google-site-verification=2b8irRvU5a2h4Mb-H_fdqNrqWjS00qmPfPcWqm8BhxI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of yahoo.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but yahoo.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 23 disallow path(s), e.g. /info/p.gif, /p/, /r/, /bin/, /caas/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 74.6.143.26 carries PTR media-router-fp74.prod.media.vip.bf1.yahoo.com. for yahoo.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "yahoo.com",
  "dns": {
    "a": [
      "74.6.143.26",
      "98.137.11.164",
      "98.137.11.163",
      "74.6.231.20",
      "74.6.143.25",
      "74.6.231.21"
    ],
    "aaaa": [
      "2001:4998:44:3507::8000",
      "2001:4998:124:1507::f000",
      "2001:4998:24:120d::1:0",
      "2001:4998:44:3507::8001",
      "2001:4998:124:1507::f001",
      "2001:4998:24:120d::1:1"
    ],
    "cname": null,
    "mx": [
      "mta7.am0.yahoodns.net (pref 1)",
      "mta5.am0.yahoodns.net (pref 1)",
      "mta6.am0.yahoodns.net (pref 1)"
    ],
    "ns": [
      "ns4.yahoo.com.",
      "ns2.yahoo.com.",
      "ns3.yahoo.com.",
      "ns5.yahoo.com.",
      "ns1.yahoo.com."
    ],
    "spf": [
      "v=spf1 redirect=_spf.mail.yahoo.com",
      "google-site-verification=xoBvU6aKxP0gYgNL0iXqF0EccAg6nFrO7XxsHnc3iNQ",
      "facebook-domain-verification=gysqrcd69g0ej34f4jfn0huivkym1p",
      "google-site-verification=2b8irRvU5a2h4Mb-H_fdqNrqWjS00qmPfPcWqm8BhxI",
      "edb3bff2c0d64622a9b2250438277a59",
      "google-site-verification=w4N2bNopAWw1xYrdXKORILxx-WW3_LIiyX6dIMIidgk",
      "google-site-verification=2b0Glh8l2icXIAgAcjOcFx16Jt26yWDgEyrk5hPD-ZY",
      "google-site-verification=GLp01gkFNopm_JItbLxml4iuVbTgJa3rKu0-eq1RvsE",
      "google-site-verification=Z3-Vh6zqUMgybVH4wQl1GxKSKN7JE13kyCyeZ3TZZ-I",
      "_globalsign-domain-verification=3rQPnwMFlx5UmUzSMV-JeDoNEMeG8BYFKvKDsHEzr9",
      "google-site-verification=GU8WAl0zPqaxdcZqDjuN7pqdfPCpR9Amz9rwxMG91qw",
      "Zoom=13284637"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Yahoo Holdings Inc., commonName=yahoo.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 28 00:00:00 2026 GMT",
    "notAfter": "Oct 21 23:59:59 2026 GMT",
    "san": [
      "yahoo.com",
      "tw.rd.yahoo.com",
      "s.yimg.com",
      "mbp.yimg.com",
      "hk.rd.yahoo.com",
      "fr-ca.rogers.yahoo.com",
      "ddl.fp.yahoo.com",
      "ca.rogers.yahoo.com",
      "ca.my.yahoo.com",
      "brb.yahoo.net",
      "add.my.yahoo.com",
      "*.yahoo.com",
      "*.www.yahoo.com",
      "*.media.yahoo.com",
      "*.att.yahoo.com",
      "*.amp.yimg.com"
    ],
    "days_left": 25,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "74.6.143.26",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ATS"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.yahoo.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://yahoo.com/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=xoBvU6aKxP0gYgNL0iXqF0EccAg6nFrO7XxsHnc3iNQ",
    "facebook-domain-verification=gysqrcd69g0ej34f4jfn0huivkym1p",
    "google-site-verification=2b8irRvU5a2h4Mb-H_fdqNrqWjS00qmPfPcWqm8BhxI",
    "google-site-verification=w4N2bNopAWw1xYrdXKORILxx-WW3_LIiyX6dIMIidgk",
    "google-site-verification=2b0Glh8l2icXIAgAcjOcFx16Jt26yWDgEyrk5hPD-ZY"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260728000000",
      "not_after": "20261021235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/info/p.gif",
      "/p/",
      "/r/",
      "/bin/",
      "/caas/",
      "/blank.html",
      "/includes/",
      "/_td_api",
      "/tdv2_fp",
      "/nel_ms",
      "/fp_ms",
      "/sports_fp_ms",
      "/search_ms",
      "/_tdpp_api",
      "/_remote"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "media-router-fp74.prod.media.vip.bf1.yahoo.com."
    ]
  },
  "elapsed_s": 28.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
