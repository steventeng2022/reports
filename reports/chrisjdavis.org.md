# Security Audit Report — chrisjdavis.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://chrisjdavis.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | chrisjdavis.org |
| Test date | 2026-09-26 17:41 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 5, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL9 | DMARC enforces (p=quarantine) but has no reporting address (rua) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | CT1 | 5 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Vercel
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Vercel
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] DMARC enforces (p=quarantine) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (xudg95f9qjmo8t.chrisjdavis.org and 4pdsepii3by2yw.chrisjdavis.org) both resolve to distinct addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: brave-ledger-verification=2d3773df8ba0789c8e382dd8de095065e6cf0381f45eb2416d6004; protonmail-verification=d541f2d99ed79d5ef7eda87b958b02d732530823
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of chrisjdavis.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but chrisjdavis.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 45 disallow path(s), e.g. /admin/, /preview/, /login, /register, /reset-password/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] 5 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "chrisjdavis.org",
  "dns": {
    "a": [
      "216.150.1.1",
      "216.150.16.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mail.protonmail.ch (pref 10)",
      "mailsec.protonmail.ch (pref 20)"
    ],
    "ns": [
      "fattouche.ns.cloudflare.com.",
      "sonia.ns.cloudflare.com."
    ],
    "spf": [
      "brave-ledger-verification=2d3773df8ba0789c8e382dd8de095065e6cf0381f45eb2416d60048a88b6c34d",
      "protonmail-verification=d541f2d99ed79d5ef7eda87b958b02d732530823",
      "v=spf1 include:_spf.protonmail.ch ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=chrisjdavis.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug  6 13:26:09 2026 GMT",
    "notAfter": "Nov  4 13:26:08 2026 GMT",
    "san": [
      "chrisjdavis.org"
    ],
    "days_left": 38,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "216.150.1.1",
    "open": []
  },
  "https": {
    "status": 308,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Vercel"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.chrisjdavis.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 308,
    "location": "https://chrisjdavis.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 308,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "source": "certspotter",
    "count": 5,
    "notable": [],
    "sample": [
      "chrisjdavis.org",
      "genus.chrisjdavis.org",
      "photos.chrisjdavis.org",
      "plex.chrisjdavis.org",
      "www.chrisjdavis.org"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "brave-ledger-verification=2d3773df8ba0789c8e382dd8de095065e6cf0381f45eb2416d6004",
    "protonmail-verification=d541f2d99ed79d5ef7eda87b958b02d732530823"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/admin/",
      "/preview/",
      "/login",
      "/register",
      "/reset-password/",
      "/admin/",
      "/preview/",
      "/login",
      "/register",
      "/reset-password/",
      "/admin/",
      "/preview/",
      "/login",
      "/register",
      "/reset-password/"
    ]
  },
  "elapsed_s": 7.1,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
