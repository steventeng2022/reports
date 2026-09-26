# Security Audit Report — businessinsider.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://businessinsider.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | businessinsider.com |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

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
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 37 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 18 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=MeuJIyKOrXf6e1Foju5Tqkzoms8KH0IoP01G5KhB-m8; apple-domain-verification=G59n_HIhMNvtkyEDlx0g1LdxhRL8neVCOkZ-NcIa0cQ; google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of businessinsider.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but businessinsider.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 72 disallow path(s), e.g. /*?utm_campaign=Monitor&, /adframe, /afp$, /ajax/, /answers$
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 37 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: gcp.businessinsider.com, it.businessinsider.com, my.businessinsider.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 18. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: gcp.businessinsider.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "businessinsider.com",
  "dns": {
    "a": [
      "151.101.1.171",
      "151.101.65.171",
      "151.101.129.171",
      "151.101.193.171"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns21.constellix.com.",
      "ns11.constellix.com.",
      "dns3.p03.nsone.net.",
      "dns4.p03.nsone.net.",
      "ns61.constellix.net.",
      "dns1.p03.nsone.net.",
      "ns41.constellix.net.",
      "ns31.constellix.com.",
      "ns51.constellix.net.",
      "dns2.p03.nsone.net."
    ],
    "spf": [
      "google-site-verification=MeuJIyKOrXf6e1Foju5Tqkzoms8KH0IoP01G5KhB-m8",
      "MS=49384EFC2AA5C920CC726E72850EA7250E18356F",
      "apple-domain-verification=G59n_HIhMNvtkyEDlx0g1LdxhRL8neVCOkZ-NcIa0cQ",
      "google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXlTSpjtg1iNnMasAJ3GsD",
      "openai-domain-verification=dv-jTz4KfMtiA6SiWiVpka2QDFr",
      "google-site-verification=E4A9jU1go8SQoOYqjwybQIyUhIqPRDUF2Fu5nYC77oM",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:_spf.salesforce.com ~all",
      "globalsign-domain-verification=qhllLTVNbc63_k7N_0u2VjkgHnq48qKQ8gKVvHWkHI",
      "google-site-verification=dsTQoEYtkhKJUiHaf7NXBGBP5wRxmQ2ia56y9UnTeZc",
      "asv=4f7bed0ed9307319569dca0dc413d303",
      "lucidlink-verification=H13VJ94S9GRFM6ZX539Q5EB8MG",
      "google-site-verification=6siIDX8Eh0aPCTSxDF2-GFuuFff1H1aPGm3SfPvP7aI",
      "canva-site-verification=yOD8mjIYFWLM6qJQW-rwgg",
      "slack-domain-verification=p1y98UQQ7JwUhAuHWXgLsJqM1VDqn56eErx227bu",
      "facebook-domain-verification=jz79wu26i92i5zpxpqra4s1p1ois9j",
      "openai-domain-verification=dv-gEVeLfZWhh8fDqhgX7be0VGh",
      "google-site-verification=hVwc4FIT_C_8DNSPQSBmv84brU443LMUlfiyDqrByVA",
      "google-site-verification=lhkw5_yE2VpatfjtNqFeTXshSdHOmye2FSHCz4_IZwE",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXITSpjtg1iNnMasAJ3GsD",
      "google-site-verification=5khzg7Aljjht1XobmkoQeX_2L4E5UJO9C1Z9_zfFTYs",
      "_globalsign-domain-verification=O81xyb7YxpdGeHWkniit_VBT4vTXz9__NFrNMoTwFg",
      "ZOOM_verify_BiuNcpuc03G4NjRCC8crLr",
      "00Dd0000000cyqM=1TBQK00000000rF",
      "zapier-domain-verification-challenge=e10fad84-5944-470d-ae77-5d7697d0af05"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@insider.com; ruf=mailto:dmarc-reports@insider.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=businessinsider.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q1",
    "notBefore": "Feb 11 19:00:25 2026 GMT",
    "notAfter": "Mar 15 19:00:24 2027 GMT",
    "san": [
      "businessinsider.com"
    ],
    "days_left": 170,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.1.171",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.businessinsider.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.businessinsider.com/"
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
    "count": 37,
    "notable": [
      "gcp.businessinsider.com",
      "it.businessinsider.com",
      "my.businessinsider.com"
    ],
    "sample": [
      "account-dev.businessinsider.com",
      "account.businessinsider.com",
      "advertising.businessinsider.com",
      "africa.businessinsider.com",
      "businessinsider.com",
      "comments.businessinsider.com",
      "consent.markets.businessinsider.com",
      "coupons.businessinsider.com",
      "e.businessinsider.com",
      "gcp.businessinsider.com",
      "i-dev-cf.businessinsider.com",
      "info.businessinsider.com",
      "ing-images.businessinsider.com",
      "it.businessinsider.com",
      "l.businessinsider.com",
      "live.businessinsider.com",
      "login-dev.businessinsider.com",
      "markets.businessinsider.com",
      "my-dev.businessinsider.com",
      "my.businessinsider.com"
    ],
    "dangling": [
      "gcp.businessinsider.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=MeuJIyKOrXf6e1Foju5Tqkzoms8KH0IoP01G5KhB-m8",
    "apple-domain-verification=G59n_HIhMNvtkyEDlx0g1LdxhRL8neVCOkZ-NcIa0cQ",
    "google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0",
    "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXlTSpjt",
    "openai-domain-verification=dv-jTz4KfMtiA6SiWiVpka2QDFr"
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
  "http2": {
    "robots_disallow": [
      "/*?utm_campaign=Monitor&",
      "/adframe",
      "/afp$",
      "/ajax/",
      "/answers$",
      "/archives",
      "/associated-press$",
      "/authentication$",
      "/author/*/date",
      "/author/*/mostread",
      "/categories",
      "/cms/",
      "/comments$",
      "/cross-domain$",
      "/document/"
    ]
  },
  "elapsed_s": 19.1,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
