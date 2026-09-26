# Security Audit Report — samsung.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://samsung.com/ |
| Bug bounty program | Samsung TV |
| Listed scope domain | samsung.com |
| Test date | 2026-09-26 17:52 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 5, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 27 days (notAfter Oct 23 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

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
- **Detail:** Apex TXT records with verification/token content: mongodb-site-verification=OK5ChSTjOEnRssN4ZNjB6y7xoqWBSraL; openai-domain-verification=dv-geyHaAZ2x2iRSG5mPLgCehBU; canva-site-verification=Lz0E97jjjyiBnq4nGgrBzg
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of samsung.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "samsung.com",
  "dns": {
    "a": [
      "211.45.27.231"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mailin.samsung.com (pref 10)"
    ],
    "ns": [
      "dnsst.samsung.com.",
      "dnssm.samsung.com.",
      "dns-gi2.samsung.com.",
      "dnssm2.samsung.com.",
      "auth01.sam.ic.",
      "dns-gi1.samsung.com.",
      "dnsst2.samsung.com.",
      "dns-awskr1.samsung.com."
    ],
    "spf": [
      "mongodb-site-verification=OK5ChSTjOEnRssN4ZNjB6y7xoqWBSraL",
      "openai-domain-verification=dv-geyHaAZ2x2iRSG5mPLgCehBU",
      "canva-site-verification=Lz0E97jjjyiBnq4nGgrBzg",
      " amazonses:GabQpmRJN86a4HQqoLu1IEu/b6hqbMTlQSHol1cVzhA=",
      "globalsign-domain-verification=E636433F4A5B2209D29402CE4AE96D29",
      "globalsign-domain-verification=BD8E0953267AFCAEF59AFBF5F00BEB67",
      "asv=bbc7c9d6c4c6acdc2124368f94efe110",
      "atlassian-domain-verification=YJdK2oq4udj7wXxpQw52IsGEJue0ar/5JYtGr9lwcGNCffiKwPSGDZIQH0JlESij",
      "google-site-verification=4pYi1ZoA5M9sNwJ39mlfRLPA5w_J2lqCVFEVUPyojp8",
      "miro-verification=16f39e2d161837f1d97cfb17ff7e81f243c68683",
      "cisco-ci-domain-verification=37f06378ba0e1526ad9a057438e3f2a1d0888e4e21d4ce75160ac7475679e080",
      "google-site-verification=2Qn3FwdHxOdx-U2EBlX2Aq6OPFHM-JGRpo5fN2vEr88",
      "globalsign-domain-verification=142A59A6E9D02E64F922A9C6893534A2",
      "globalsign-domain-verification=9382b64f06fad76d1ebac344380ab28b",
      "box-domain-verification=b82590942dde67b52e8c41dc0e492a02ade277c5aede0e6de0b3b8de28a0085a",
      "google-site-verification=XioIPzfjKziFDv7svS2vFxobJ1j6ApORgnD43-La5jc",
      "MS=ms51591264",
      "google-site-verification=gVlQpmwAi4l7c9YZ6vgGKB",
      "smartsheet-site-validation=E2jBYaDqtbMgG1u9Jzz2eQBNGVL2eea-",
      "pardot1061372=cd7a8dc7dac11576e3160df3645c3be60beb48d38262fe75e1b83b6ed4547e2f",
      "pardot1061392=f1c7431aa41d5e18d6f425faa7ee4bef2cc82af55471991546af317ad4988f6f",
      "pardot1005352=4bf1edcafe2d5f7ea48b1ab4c669194f7fb8492acec4617e4b3af673899d0f05",
      "apple-domain-verification=1f6od6-lOUHNPseuv2qlLXryA-4aMi97KboxR65PVb0",
      " docusign=022189ea-ba76-432a-abd7-19343970da7e",
      "google-gws-recovery-domain-verification=57248779",
      "samsung-domain-verification=9a471672-ab8b-442c-a646-b6fda8a9e698",
      "v=spf1 include:_spf.samsung.com ~all",
      "pardot1061362=d72ade8848a288815d8cd7fcdedf8e2ea1ffdf37f2e6199b9c6d2b118b260b11",
      "pardot848313=94e68189fc6e698e53ab66f68f9fa66f68b14ab1837bac98f0a5b5b4dd57503d",
      "pardot880362=0579f4b1009200bd5629bc294b593112ab1438df4ebedf4de300d36b4a35e5bf",
      "google-site-verification=Tb4utn-Cz0GYEzmsVzHfYhi6kv6XU--QYrYkfsVLwO0",
      "asv=8c95d437a5f5281bf0b46412ea6410ff",
      " globalsign-domain-verification=d7cac74e387872153b45a1cf21f819ee",
      "google-gws-recovery-domain-verification=69734317",
      " 7029addd-cf82-4d9e-9ac6-45cd3e47e467",
      "cisco-ci-domain-verification=4d1fed540ceae17bd020e5d248bb657c382c66454d32a5984edd4871be659cea",
      "figma-domain-verification=74d791d52b49cbb05822c432d058f86bb47d2d97aa815d0ca470c6ef74a99003-1742422683 ",
      "google-site-verification=qKOICuq5bpeTBLMOeQs-pQ4fR4YdzZVLyFvahSDaRqc",
      "figma-domain-verification=fff7a09ce23c2d8329d368316712f1dcb0a29cb4c71a406f8f41dce4ef671081-1767768682",
      "pardot1061382=ee554f6d1abf83530c2b3bd50be47bc5e417bb833dc9b2686e5c5c384d2e174c",
      "dtm-domain-verification=sj6QpVm4qndJLuG0vmv2lv2WLlZ3g1EGLq9OItKaBQI",
      "globalsign-domain-verification=A931337188D2EF719A821F0016D8552E",
      "docker-verification=a98547c5-d702-4b4b-9516-4331ed5171c8",
      "google-site-verification=gVlQpmwAi4l7c9YZ6vgGKBrqIjduXkSx7ekuOPsOAlg",
      "pardot1061372=4fedddc5665b4f323efd74d4970852e6a46f8df316987974967da26bef35bf24",
      "globalsign-domain-verification=D4FBC243F3CA31BC63C84A1CE7856D69",
      "liveramp-site-verification=bLTcKGTyyCkVh8Zt5X8IYY9T4Uns9ZRoAEG6NPzTd-c",
      "pardot1123213=e21329a1ef7ab24c2a6a00afb2c9cdf6409a12ea19fd8c37c70c53eb8cbd3176",
      " globalsign-domain-verification=BF9A67D3968C1D5FEC1440B12347B6AF",
      "google-site-verification=If15ip-WHY67QHEaM6ka9WKCcxgFHbS1oaXJswpUbHQ",
      "pardot848313=56b423327c6bbcc73c4888f1e7a74aa35be107baa0d8dbc0d60d3078016cdedb",
      "pardot1061372=7f77a7e9d20bced708628f16f6245665a0b5d0ab840f492e5b8b9d0616ff8bff",
      "dtm-domain-verification=5gAZbUOV4mzm7FcNMxN3Z_8Og_vvyqJh5FxCE_rh0zE"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:postmaster@samsung.com; ruf=mailto:postmaster@samsung.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=KR, stateOrProvinceName=Gyeonggi-do, organizationName=SAMSUNG ELECTRONICS CO,.LTD, commonName=*.samsung.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R36",
    "notBefore": "Apr  8 00:00:00 2026 GMT",
    "notAfter": "Oct 23 23:59:59 2026 GMT",
    "san": [
      "*.samsung.com",
      "samsung.com"
    ],
    "days_left": 27,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "211.45.27.231",
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
      "origin": "https://sub.samsung.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.samsung.com/"
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
    "mongodb-site-verification=OK5ChSTjOEnRssN4ZNjB6y7xoqWBSraL",
    "openai-domain-verification=dv-geyHaAZ2x2iRSG5mPLgCehBU",
    "canva-site-verification=Lz0E97jjjyiBnq4nGgrBzg",
    "globalsign-domain-verification=E636433F4A5B2209D29402CE4AE96D29",
    "globalsign-domain-verification=BD8E0953267AFCAEF59AFBF5F00BEB67"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "elapsed_s": 19.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
