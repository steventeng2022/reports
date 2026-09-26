# Security Audit Report — nydailynews.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nydailynews.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | nydailynews.com |
| Test date | 2026-09-26 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P11 | WordPress login page exposed | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=hMnRAtdizhrC_XVmPTQN1cDWp-b--71NSTwSMExNeAI; knowbe4-site-verification=90309b4eacebd82470e924deb428c541; facebook-domain-verification=ois8caa2a84ewa28r3zx5ilvxs4g4r
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of nydailynews.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 70 disallow path(s), e.g. /wp-admin/, /cgi-bin/, /wp-includes/, /xmlrpc.php, /wp-content/plugins/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "nydailynews.com",
  "dns": {
    "a": [
      "192.0.66.144"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-1494.awsdns-58.org.",
      "ns-1929.awsdns-49.co.uk.",
      "ns-318.awsdns-39.com.",
      "ns-670.awsdns-19.net."
    ],
    "spf": [
      "google-site-verification=hMnRAtdizhrC_XVmPTQN1cDWp-b--71NSTwSMExNeAI",
      "knowbe4-site-verification=90309b4eacebd82470e924deb428c541",
      "fmtpohpupbmlg7ph5dgtpqhn1r",
      "amazonses:N8Ba1fh8HfMvT+t5J7vwXFgnXMVaK646lFnkrQkLoVc=",
      "bntlt7a869guderdu33t64dms5",
      "IPROTA_D59226-XXX",
      "mppmekcnmo3na10p5fqp793g9v",
      "8oqjg39e67s8ao65ndrgnd5ufv",
      "facebook-domain-verification=ois8caa2a84ewa28r3zx5ilvxs4g4r",
      "v=spf1 include:spf.protection.outlook.com include:_spf.google.com include:_spf.salesforce.com include:mail.zendesk.com ip4:198.21.3.53 ip4:159.183.220.8 exists:%{i}.spf.sitel.iphmx.com -all",
      "tollbit-domain-verification=ef1c9b50f5288be2ac950c259ca3f721ddf4d2161522e79044e2f7042a6d237c",
      "4b0695jv70h8g47zkdg16kzygm3ls02v",
      "google-site-verification=wJYLuUe209pKCTIs9tSdz5kaorlk7GqqWPHX9rOzH2M",
      "google-site-verification=8TDEqJ-arOBRammsLaJwjep-S63E7y7m-QsH9bhT6K4",
      "hucq9oebjdhnpo231ru64sqlu4",
      "google-site-verification=5JHSGMK_gK4xGs8DWfgnX4xwHqIAePxl4j18e5qkHv4",
      "google-site-verification=1RnCO3kOaGC8U0mJXV2sbY-6XM6VJscT8lSoWJOB7UY",
      "fbd8dhf0dupevcppakg92fireq",
      "13kvutnp8irg8ioiotkqq86i51",
      "7rdja10s86ikle4v2h82p6n642",
      "google-site-verification=1fTCAXxtHpJXkMkbrZjElBCAm6inCZ-7AkzpL2tLSaY",
      "MS=ms76891439",
      "google-site-verification=a40Yo5u46-Gpqee1PSKGDsuayXa3mn8A9wSFUJBnVDY",
      "fzkp52pbdwht5h6rsnhcfkh8hqs4d0z3",
      "amazonses:rUbohPMg18d7fvhiuygSmeQbkP+Y7JuMBpNoGODmKIM="
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=nydailynews.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep  4 00:38:01 2026 GMT",
    "notAfter": "Dec  3 00:38:00 2026 GMT",
    "san": [
      "nydailynews.com",
      "www.nydailynews.com"
    ],
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.144",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nydailynews.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://nydailynews.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=hMnRAtdizhrC_XVmPTQN1cDWp-b--71NSTwSMExNeAI",
    "knowbe4-site-verification=90309b4eacebd82470e924deb428c541",
    "facebook-domain-verification=ois8caa2a84ewa28r3zx5ilvxs4g4r",
    "tollbit-domain-verification=ef1c9b50f5288be2ac950c259ca3f721ddf4d2161522e79044e2",
    "google-site-verification=wJYLuUe209pKCTIs9tSdz5kaorlk7GqqWPHX9rOzH2M"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/cgi-bin/",
      "/wp-includes/",
      "/xmlrpc.php",
      "/wp-content/plugins/",
      "/wp-content/cache/",
      "/trackback/",
      "/comments/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "elapsed_s": 20.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
