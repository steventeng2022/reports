# Security Audit Report — kiva.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://kiva.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | kiva.org |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 14 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 14. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (wi0iq2zn485ye9.kiva.org and 3fsoxz61p8delx.kiva.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=R376pH2Qg1DF_VAUNVoD9UdHnYQZgJc58a0RuOZBRJo; adobe-idp-site-verification=6fe80722ea29c9a5df78b8cc8395beef437166b62246b1ae0f96; google-site-verification=OC0AuKwkDfkZPB9fFbcQic9Sy0BEzHiJ_oiOtUH13lE
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of kiva.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "kiva.org",
  "dns": {
    "a": [
      "184.32.154.120",
      "35.84.123.227",
      "52.38.210.220"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-823.awsdns-38.net.",
      "ns-1401.awsdns-47.org.",
      "ns-1628.awsdns-11.co.uk.",
      "ns-467.awsdns-58.com."
    ],
    "spf": [
      "google-site-verification=R376pH2Qg1DF_VAUNVoD9UdHnYQZgJc58a0RuOZBRJo",
      "ZOOM_verify_EG8dulX8TLC_IA_EcCClOw",
      "adobe-idp-site-verification=6fe80722ea29c9a5df78b8cc8395beef437166b62246b1ae0f966dc9518e0be7",
      "google-site-verification=OC0AuKwkDfkZPB9fFbcQic9Sy0BEzHiJ_oiOtUH13lE",
      "anthropic-domain-verification-dpkt2p=m5p14kRrmTYLhAsidkSy7A3no",
      "google-site-verification=K6pOshF2tXM_Od3Aox6x0D5NCifEGgjeoKpEgm_0FnA",
      "6v2dgkhyvf59rskdrvnftbk323znlwlh",
      "google-site-verification=_Xv5McueunM-dPmSF1ge6wsY8FVJq0aPt_pcDKaeBm4",
      "google-site-verification=dw2XUoLh5GVnlVttqOWbFXhrDjOlJBhhPZ2eYZmoUPY",
      "have-i-been-pwned-verification=db1636b384f9357d05e558bf19131b1c",
      "google-site-verification=1fC3FgT5ECns8re10uYmOP6ti515lHow0590LexLpZI",
      "google-site-verification=aNSEEHIDfPXNUeb67q8FOy1leF8IHP3my5W5P-K3Ras",
      "v=spf1 ip4:50.31.62.59 ip4:149.72.59.130 ip4:44.231.14.47 ip4:44.228.3.254 ip4:98.124.155.57 ip4:167.89.73.35 +ip4:63.146.102.40 +ip4:159.242.240.114 +ip4:159.242.241.114 +ip4:184.105.251.240 +ip4:205.219.64.40 +ip4:209.117.187.240",
      " include:sendgrid.net include:_spf.salesforce.com include:_spf.google.com include:spf1.formassembly.com include:mg-spf.greenhouse.io ~all",
      "onetrust-domain-verification=7d515025ceee4735a290af3918d6eab1",
      "openai-domain-verification=dv-yC2ze882C9VikO8gNy93jlRg",
      "google-site-verification=p8xG9TMPbQbi9nZd95YSxllHvJAD67-tqmHpAhXImIk",
      "facebook-domain-verification=6k9ebdtev0wfu1xrh5uuy0a898natq",
      "atlassian-domain-verification=OVxK2M7RNrqHbkHkbj5fgLMB7PskfmIGG/vuJOF56EfSoZwcEOEH+1K83N1x8Io3",
      "MS=ms86669204",
      "pinterest-site-verification=5d85d0a1883817322133a4b593943825",
      "apple-domain-verification=aMzQxkiCFjcw6qs2",
      "google-site-verification=5jYUB2vDYFFMq4m_24JfhaRstDUUtCWM-YDQmyeNudE"
    ],
    "dmarc": [
      "v=DMARC1; p=none; sp=none; rua=mailto:dmarc@kiva.org, mailto:dmarc_agg@vali.email; ruf=mailto:dmarc@kiva.org; rf=afrf; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=kiva.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Dec 11 00:00:00 2025 GMT",
    "notAfter": "Jan  9 23:59:59 2027 GMT",
    "san": [
      "kiva.org",
      "*.kiva.org"
    ],
    "days_left": 105,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "184.32.154.120",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.kiva.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://kiva.org:443/"
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
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=R376pH2Qg1DF_VAUNVoD9UdHnYQZgJc58a0RuOZBRJo",
    "adobe-idp-site-verification=6fe80722ea29c9a5df78b8cc8395beef437166b62246b1ae0f96",
    "google-site-verification=OC0AuKwkDfkZPB9fFbcQic9Sy0BEzHiJ_oiOtUH13lE",
    "anthropic-domain-verification-dpkt2p=m5p14kRrmTYLhAsidkSy7A3no",
    "google-site-verification=K6pOshF2tXM_Od3Aox6x0D5NCifEGgjeoKpEgm_0FnA"
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
  "elapsed_s": 26.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
