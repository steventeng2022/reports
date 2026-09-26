# Security Audit Report — 1drv.ms

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://1drv.ms/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | 1drv.ms |
| Test date | 2026-09-26 18:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 13 | info | CT1 | 1 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=u-6C2yDFjGj4R_97zrQ9nbfgshLekyVcIozwHKk9Frw
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of 1drv.ms has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but 1drv.ms is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 13. [INFO] 1 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "1drv.ms",
  "dns": {
    "a": [
      "150.171.22.11"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [],
    "ns": [
      "ns4-35.azure-dns.info.",
      "ns3-35.azure-dns.org.",
      "ns2-35.azure-dns.net.",
      "ns1-35.azure-dns.com."
    ],
    "spf": [
      "google-site-verification=u-6C2yDFjGj4R_97zrQ9nbfgshLekyVcIozwHKk9Frw"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=storage.live.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 04",
    "notBefore": "Sep  2 06:06:01 2026 GMT",
    "notAfter": "Mar 19 06:06:01 2027 GMT",
    "san": [
      "l-df.live.net",
      "l.live.net",
      "api.live.com",
      "api.live.net",
      "docs.live.net",
      "skyapi.live.net",
      "api-df.live.com",
      "api-df.live.net",
      "docs-df.live.net",
      "skyapi-df.live.net",
      "*.ra.live.com",
      "*.cobalt.df.storage.msn.com",
      "*.cobalt.df.storage.live.com",
      "*.cobalt.storage.msn.com",
      "*.df.storage.live.com",
      "*.df.storage.msn.com",
      "*.docs-df.live.net",
      "*.storage.live.com",
      "*.storage.msn.com",
      "*.users.df.storage.live.com",
      "*.users.df.storage.msn.com",
      "*.users.storage.live.com",
      "*.users.storage.msn.com",
      "*.df.policies.live.net",
      "df.policies.live.net",
      "*.df.settings.live.net",
      "df.settings.live.net",
      "*.df.livefilestore.com",
      "apis.live.net",
      "*.apis.live.net",
      "*.bay.livefilestore.com",
      "*.livefilestore.com",
      "ssw.live-int.com",
      "ssw.live.com",
      "df.storage.live.com",
      "*.sn2.df.livefilestore.com",
      "storage.live.com",
      "*.blu.livefilestore.com",
      "*.bn1.livefilestore.com",
      "*.cobalt.storage.live.com",
      "*.dm1.livefilestore.com",
      "*.docs.live.net",
      "*.policies.live.net",
      "*.settings.live.net",
      "*.sn2.livefilestore.com",
      "*.tuk.livefilestore.com",
      "policies.live.net",
      "storage.msn.com",
      "dev.live.com",
      "oauth.live.com",
      "*.bn1301.livefilestore.com",
      "*.bn1302.livefilestore.com",
      "*.dm2301.livefilestore.com",
      "*.dm2302.livefilestore.com",
      "skyapi.skydrive.live.com",
      "settings.live.net",
      "*.bn1303.livefilestore.com",
      "*.bn1304.livefilestore.com",
      "*.dm2303.livefilestore.com",
      "*.dm2304.livefilestore.com",
      "*.by3301.livefilestore.com",
      "*.by3302.livefilestore.com",
      "*.snt002.df.livefilestore.com",
      "*.bn1303.df.livefilestore.com",
      "*.dm2303.df.livefilestore.com",
      "skyapi.newdrive.live.com",
      "skyapi.onedrive.live.com",
      "*.files.1drv.com",
      "*.bl3301.livefilestore.com",
      "*.bl3302.livefilestore.com",
      "*.bn1391soak2.livefilestore.com",
      "*.dm2391soak2.livefilestore.com",
      "*.bn1391soak3.livefilestore.com",
      "*.dm2391soak3.livefilestore.com",
      "*.files-df.1drv.com",
      "*.api.onedrive.com",
      "df.api.onedrive.com",
      "*.df.api.onedrive.com",
      "*.s2s-storage.live.com",
      "*.s2s-policies.live.net",
      "s2s-policies.live.net",
      "s2s-settings.live.net",
      "*.s2s-settings.live.net",
      "*.config.live.net",
      "config.live.net",
      "register.mesh.com",
      "*.df.s2s-storage.live.com",
      "*.df.s2s-settings.live.net",
      "df.s2s-settings.live.net",
      "s2s-storage.live.com",
      "df.s2s-storage.live.com",
      "*.s2s.livefilestore.com",
      "*.s2s.df.livefilestore.com",
      "*.s2s-files-df.1drv.com",
      "*.df.s2s-policies.live.net",
      "df.s2s-policies.live.net",
      "*.df-config.live.net",
      "df-config.live.net",
      "*.s2s-files.1drv.com",
      "device.ra.live.com",
      "*.keymaster.p001.1drv.com",
      "*.keymaster.i001.1drv.com",
      "s2s-skyapi.live.net",
      "s2s-api.onedrive.com",
      "*.s2s-api.onedrive.com",
      "s2s-skyapi-df.live.net",
      "df.s2s-api.onedrive.com",
      "*.df.s2s-api.onedrive.com",
      "df.people.onedrive.com",
      "*.slps.live.net",
      "*.ADMINSVC.P001.1drv.com",
      "*.ADMINSVC.I001.1drv.com",
      "*.CONFIG.I001.1drv.com",
      "*.DEPLOYMGR.P001.1drv.com",
      "*.JOB.P001.1drv.com",
      "*.CAMP.I001.1drv.com",
      "*.1drv.com",
      "1drv.ms",
      "*.LPS.I001.1drv.com",
      "*.WSTCRS.I001.1drv.com",
      "*.wstlm.1drv.com",
      "sdrv.ms",
      "*.am.files.1drv.com",
      "*.db.files.1drv.com",
      "*.bl.files.1drv.com",
      "*.bn.files.1drv.com",
      "*.by.files.1drv.com",
      "*.ch.files.1drv.com",
      "*.cy.files.1drv.com",
      "*.dm.files.1drv.com",
      "*.sn.files.1drv.com",
      "d.bl3301.docs.live.net",
      "d.bl3302.docs.live.net",
      "*.API.P001.1drv.com",
      "*.gls.i001.1drv.com",
      "*.ph.files.1drv.com",
      "devices.live.com",
      "favorites.live.com",
      "*.onedrive.com"
    ],
    "days_left": 173,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "150.171.22.11",
    "open": []
  },
  "https": {
    "status": 404,
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
      "origin": "https://sub.1drv.ms",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 404
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 1,
    "notable": [],
    "sample": [
      "1drv.ms"
    ]
  },
  "apex_txt": [
    "google-site-verification=u-6C2yDFjGj4R_97zrQ9nbfgshLekyVcIozwHKk9Frw"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.12",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260902060601",
      "not_after": "20270319060601"
    }
  },
  "http2": {
    "robots_disallow": [
      "/"
    ]
  },
  "x12": {
    "status": 404
  },
  "elapsed_s": 9.0,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
