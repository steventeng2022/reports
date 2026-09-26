# Security Audit Report — smashingmagazine.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://smashingmagazine.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | smashingmagazine.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CT1 | 5 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Netlify
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
- **Detail:** Header reveals: Netlify
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=0robA8kpiXkVEX1ts-_xCYWRkXleQJpwyN_BYQYOX54; google-site-verification=e2dLL9LD1Z_jpCFp6BTtGMlu42BGc8ugnf_midmUIlk; google-site-verification=X5sd8PEDJqYLSR98RKgSozn-0RNpknXFlGoA-UXe5K0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of smashingmagazine.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 190 disallow path(s), e.g. /wp-admin/, /wp-includes/, /wp-content/uploads/demos/BarGraph/index.html, /wp-content/uploads/demos/HoverPost/index.html, /wp-content/uploads/demos/ColorCategories/index.html
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] 5 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: store.smashingmagazine.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "smashingmagazine.com",
  "dns": {
    "a": [
      "15.197.167.90",
      "3.33.186.135"
    ],
    "aaaa": [
      "2406:da12:53f:c100::1f5"
    ],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "dns1.p06.nsone.net.",
      "dns4.p06.nsone.net.",
      "dns3.p06.nsone.net.",
      "dns2.p06.nsone.net."
    ],
    "spf": [
      "google-site-verification=0robA8kpiXkVEX1ts-_xCYWRkXleQJpwyN_BYQYOX54",
      "google-site-verification=e2dLL9LD1Z_jpCFp6BTtGMlu42BGc8ugnf_midmUIlk",
      "google-site-verification=X5sd8PEDJqYLSR98RKgSozn-0RNpknXFlGoA-UXe5K0",
      "v=spf1 include:_spf.google.com include:servers.mcsv.net include:spf.mandrillapp.com include:em4186.swell.store -all"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=reject;pct=100;rua=mailto:22c84bb25c@rua.easydmarc.eu;ruf=mailto:22c84bb25c@ruf.easydmarc.eu;ri=86400;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.smashingmagazine.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug 26 08:06:50 2026 GMT",
    "notAfter": "Nov 24 08:06:49 2026 GMT",
    "san": [
      "*.smashingmagazine.com",
      "smashingmagazine.com"
    ],
    "days_left": 58,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "15.197.167.90",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Netlify"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.smashingmagazine.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://smashingmagazine.com/"
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
    "source": "certspotter",
    "count": 5,
    "notable": [
      "store.smashingmagazine.com"
    ],
    "sample": [
      "podcast.smashingmagazine.com",
      "shopify.smashingmagazine.com",
      "smashingmagazine.com",
      "store.smashingmagazine.com",
      "testshop.smashingmagazine.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=0robA8kpiXkVEX1ts-_xCYWRkXleQJpwyN_BYQYOX54",
    "google-site-verification=e2dLL9LD1Z_jpCFp6BTtGMlu42BGc8ugnf_midmUIlk",
    "google-site-verification=X5sd8PEDJqYLSR98RKgSozn-0RNpknXFlGoA-UXe5K0"
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
    "hsts_preloaded": true,
    "robots_disallow": [
      "/wp-admin/",
      "/wp-includes/",
      "/wp-content/uploads/demos/BarGraph/index.html",
      "/wp-content/uploads/demos/HoverPost/index.html",
      "/wp-content/uploads/demos/ColorCategories/index.html",
      "/wp-content/uploads/demos/ImageCaptions/index.html",
      "/wp-content/uploads/2014/inaccessible.html",
      "/wp-content/uploads/2014/accessible.html",
      "/images/progressive-enhancement/navigation-1.html",
      "/images/progressive-enhancement/navigation-2.html",
      "/images/progressive-enhancement/navigation-3.html",
      "/wp-content/uploads/2011/07/email_template.html",
      "/wp-content/uploads/2015/05/splash-svg.html",
      "/wp-content/uploads/2015/05/extruded-svg.html",
      "/wp-content/uploads/2015/05/3dneon-svg.html"
    ]
  },
  "elapsed_s": 9.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
