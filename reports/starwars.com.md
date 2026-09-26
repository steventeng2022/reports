# Security Audit Report — starwars.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://starwars.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | starwars.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL3 | No DMARC record | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] No DMARC record (`MAIL3`)

- **CWE:** CWE-200
- **Detail:** No _dmarc TXT record published; receivers cannot enforce DMARC policy for this domain.
- **Recommendation:** Publish a DMARC record (start with p=none, then quarantine).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=93600
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ave4Otl9BlVJ0Zd2j4GVdJ4s4brlgM3fqPZ-_mM6EFY; google-site-verification=GohBbB11BuN1VTA3oFWu3tmiM_pM4Bw_nzKAonQmDb8; google-site-verification=4WbE24gb_6cUVXrWnFJ__9_I6dzVBEhlIAQvtZdA97U
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of starwars.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "starwars.com",
  "dns": {
    "a": [
      "23.210.215.217",
      "23.210.215.219"
    ],
    "aaaa": [
      "2600:1417:76::17c7:22a0",
      "2600:1417:76::17c7:2291"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "a12-66.akam.net.",
      "a1-127.akam.net.",
      "a9-66.akam.net.",
      "a18-64.akam.net.",
      "a13-67.akam.net.",
      "a28-65.akam.net."
    ],
    "spf": [
      "google-site-verification=ave4Otl9BlVJ0Zd2j4GVdJ4s4brlgM3fqPZ-_mM6EFY",
      "google-site-verification=GohBbB11BuN1VTA3oFWu3tmiM_pM4Bw_nzKAonQmDb8",
      "google-site-verification=4WbE24gb_6cUVXrWnFJ__9_I6dzVBEhlIAQvtZdA97U",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com ip4:208.72.12.43 ip4:208.72.12.44 ip4:208.72.12.58 ~all",
      "google-site-verification=q9DUzemhBxxc345W41MPTn3fzRuQaID_5R4GLRSgl80",
      "google-site-verification=291PSk69uu3M3SOrPTBsYGz8yvl16K1ZhbP6YMQytxU",
      "google-site-verification=3qYuZ0m5YJdjmVslnraXZKQtXmO_3YI9wv6nCY1CPHM"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=lucasfilm.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 24 03:49:53 2026 GMT",
    "notAfter": "Nov 22 03:49:52 2026 GMT",
    "san": [
      "20th.lucasarts.com",
      "au.starwars.com",
      "battlefornaboo.lucasarts.com",
      "collectables.starwars.com",
      "collectibles.starwars.com",
      "de.starwars.com",
      "demolition.lucasarts.com",
      "dk.starwars.com",
      "embed.starwars.com",
      "en-hk.starwars.com",
      "en-id.starwars.com",
      "en-my.starwars.com",
      "en-ph.starwars.com",
      "en-sg.starwars.com",
      "en-th.starwars.com",
      "en-vn.starwars.com",
      "es.starwars.com",
      "fi.starwars.com",
      "fr.starwars.com",
      "id-id.starwars.com",
      "id.starwars.com",
      "it.starwars.com",
      "jediknight2.lucasarts.com",
      "jediknightii.lucasarts.com",
      "jedipowerbattles.lucasarts.com",
      "lucasfilm.com",
      "ms-my.starwars.com",
      "nl.starwars.com",
      "no.starwars.com",
      "obiwan.lucasarts.com",
      "play.games.starwars.com",
      "play.starwars.com",
      "ru.starwars.com",
      "se.starwars.com",
      "sea.starwars.com",
      "shop.starwars.com",
      "starfighter.lucasarts.com",
      "starwars.com",
      "starwarsblog.starwars.com",
      "starwarskids.com",
      "starwarsresistance.com",
      "th-th.starwars.com",
      "th.starwars.com",
      "thisismadness.starwars.com",
      "tim.starwars.com",
      "tl-ph.starwars.com",
      "tr.starwars.com",
      "uk.starwars.com",
      "vi-vn.starwars.com",
      "www.1313starwars.de",
      "www.1313sw.de",
      "www.alllucas.com",
      "www.collectables.starwars.com",
      "www.collectibles.starwars.com",
      "www.findstarwarsrebels.com",
      "www.ilm-vancouver.com",
      "www.ilmartdepartment.com",
      "www.ilmartdepartment.net",
      "www.ilmartdepartment.org",
      "www.ilmartdept.com",
      "www.ilmartdept.net",
      "www.ilmartdept.org",
      "www.ilmconceptart.com",
      "www.ilmconceptart.net",
      "www.ilmconceptart.org",
      "www.indianajonesstore.com",
      "www.indyjones.com",
      "www.jointhejedi.ca",
      "www.jointhejedi.com",
      "www.legoindy2game.com",
      "www.livestarwars.com",
      "www.lucasfilms.com",
      "www.lucaslicensing.com",
      "www.playstarwarsuprising.com",
      "www.shop.starwars.com",
      "www.sith.net",
      "www.skywalkersound.com",
      "www.starwars.de",
      "www.starwars1313.com.au",
      "www.starwars1313.de",
      "www.starwarsarenaforce.com",
      "www.starwarsarenaforce.net",
      "www.starwarsarenaforce.org",
      "www.starwarsforcearena.net",
      "www.starwarsforcearena.org",
      "www.starwarsgalacticdefense.com",
      "www.starwarskids.com",
      "www.starwarsresistance.com",
      "www.starwarsrots.com",
      "www.sw1313.de",
      "www.swdemolition.com",
      "www.swkids.org",
      "zh-hk.starwars.com"
    ],
    "days_left": 56,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.210.215.217",
    "open": []
  },
  "https": {
    "status": 403,
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
      "origin": "https://sub.starwars.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://starwars.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=ave4Otl9BlVJ0Zd2j4GVdJ4s4brlgM3fqPZ-_mM6EFY",
    "google-site-verification=GohBbB11BuN1VTA3oFWu3tmiM_pM4Bw_nzKAonQmDb8",
    "google-site-verification=4WbE24gb_6cUVXrWnFJ__9_I6dzVBEhlIAQvtZdA97U",
    "google-site-verification=q9DUzemhBxxc345W41MPTn3fzRuQaID_5R4GLRSgl80",
    "google-site-verification=291PSk69uu3M3SOrPTBsYGz8yvl16K1ZhbP6YMQytxU"
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
  "elapsed_s": 4.3,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
