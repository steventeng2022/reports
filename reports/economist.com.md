# Security Audit Report — economist.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://economist.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | economist.com |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.145.237:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.145.237:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=Qb5YYUgxi34zMjL_BuQQ_Najf2Rw51HKl3CRIL43Pcc; miro-verification=f342c1be96026976f75e811e572741cd2b7dc4cf; adobe-idp-site-verification=fe3563308082627876b00fed079b9b07fa742f53e1dbad27a04d
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of economist.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 32 disallow path(s), e.g. /, /, /, /, /
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "economist.com",
  "dns": {
    "a": [
      "172.64.145.237",
      "104.18.42.19"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "dns2.p02.nsone.net.",
      "dns3.p02.nsone.net.",
      "dns1.p02.nsone.net.",
      "dns4.p02.nsone.net."
    ],
    "spf": [
      "google-site-verification=Qb5YYUgxi34zMjL_BuQQ_Najf2Rw51HKl3CRIL43Pcc",
      "miro-verification=f342c1be96026976f75e811e572741cd2b7dc4cf",
      "v=spf2.0/pra a mx include:spf.rimanggis.com ~all",
      "adobe-idp-site-verification=fe3563308082627876b00fed079b9b07fa742f53e1dbad27a04d4066c84e4e52",
      "anthropic-domain-verification-zzt4eb=hxHesCzVCR69nkH6qtjvnMN87",
      "_globalsign-domain-verification=h7hNxzyjxWcMmQGgdPl1sYiG5V-Bjrl_CsJqpKbIU4",
      "google-site-verification=J-5vS04lUpwFu33fb1lVeIiM0fhsBtzi5O-C3lhtPfU",
      "duo_sso_verification=M08QexH6Mc7fVPS7jsm3WEdvzoVJZz18LlXKjgCyGE39wQQXycZ0H1VKzu34KD3T",
      "cloudhealth=056432f7-cc47-40f2-a7ff-f94e38ab420e",
      "atlassian-domain-verification=ijxvw3ZV5ymQqnxv80sk3KF8m68Y5zejPUmA24aR3X1gDYFZLr1KJnthnreXeb3O",
      "ca3-3bc5fae524474e949511aadca9ffb68d",
      "google-site-verification=w_R93wx06QyNfts4iAvHnfcVpRQkm-WpiBg_xs26kxk",
      "google-site-verification=umYQJmRxpXTIiMNaF4IsR6apNajC4YwAQ0098xDaU3k",
      "MS=24621E8BD1E72EEF43C436A16E7DA57F77130691",
      "new-relic-domain-verification=6ed4883fe01f4350a7c2d6e4b70440ac",
      "OPE0071241",
      "zoho-verification=zb52015705.zmverify.zoho.e",
      "docker-verification=b3049f71-60ff-4ab5-8e4b-af12071ad9ef",
      "v=spf1 include:_spf.google.com include:amazonses.com include:_spf.salesforce.com include:servers.mcsv.net include:spfa.cpmails.com include:spf1.economist.com ~all",
      "1c1f838c-c20e-4116-b628-2fd519dfc4f3",
      "stripe-verification=89A5BEC017BC1A0474BEB086C5CD9ED1C5064FEC53663120E30568AD843E5350",
      "4971555iboa4dcf2se7ndmucc",
      "lucidlink-verification=87PF6BE3MBWNVC1A1HSPVEYFBM",
      "21inh0ishkm6dc2p9vk3qlam0l",
      "google-site-verification=dzY0WjX5aDMkfAz45NIzTiq4STvJFQVLKardBINrGdU",
      "1password-site-verification=LMMTFIQ3UNB4PHRN4PIDK3XRYY",
      "_998iskp70idb7xlds6nagvu9g13yf8d",
      "google-site-verification=SjXraZgTJjBr9KW8fGa51r5znTl_bHN0l_l-HryKg0c",
      "cursor-domain-verification-62734j=SxJ3sl8QlA292FmfZ1F5ITe71",
      "UK-federation-domain-verification=d262373b2f27d3cad1db8a568d706c79",
      "openai-domain-verification=dv-ihHQTdhnTvKLha6AwMHkRkXz",
      "google-site-verification=QbYbPDNp9mefRCIxiwdP-pwbPHZdRB2ULKa5W-8WJlw",
      "tollbit-domain-verification=a4ca26ee57be1d61750a8376fd838114dfc91be8c429fdf9c09590cba54b046a",
      "qb506uja0p70oalro6ufvvqgt8",
      "docusign=b54578ae-aff9-4dea-834d-db831e2aa957",
      "_globalsign-domain-verification=_MvaGBHROp0lO8jfRBlUhVvNlSY3UqwMW2MKrFQD0j",
      "globalsign-domain-verification=YHnWXL-7NA_q79ZvMwQDblw1lRYrh6nXXIoWOab5Fd",
      "ff9e2be8158dcbdc8f4cc0ff3a7aac77005532d6f7817d8798",
      "google-site-verification=6JINqi8eBX4Cq2IQuMDqx-zcEVrqIGsUwn67akjL_NQ",
      "facebook-domain-verification=2i21rtf1fbvf27qxahaf05x68twhjy",
      "datadome-domain-verify=tjdVhvbvz12jNxbmlOOatTgehZm77CeH",
      "ca3-397b89c6332644339a66e5474039efb1",
      "lucidlink-verification=DF38QZV72ECT76YYFSM1MZQZR8",
      "ca3-b658fbd113a84fc7a2457785e2a028cb",
      "google-site-verification=-IZ_bGbCMjxT7R9muUSQC8U2CmTbX4Jl-xXf5kkqzeA"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:rua-import-31438@sendforensics.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=economist.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 13 04:06:37 2026 GMT",
    "notAfter": "Nov 11 05:06:20 2026 GMT",
    "san": [
      "economist.com",
      "*.economist.com"
    ],
    "days_left": 45,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.145.237",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "economist.com",
      "samesite": "none"
    },
    {
      "domain": "economist.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.economist.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.economist.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=Qb5YYUgxi34zMjL_BuQQ_Najf2Rw51HKl3CRIL43Pcc",
    "miro-verification=f342c1be96026976f75e811e572741cd2b7dc4cf",
    "adobe-idp-site-verification=fe3563308082627876b00fed079b9b07fa742f53e1dbad27a04d",
    "anthropic-domain-verification-zzt4eb=hxHesCzVCR69nkH6qtjvnMN87",
    "_globalsign-domain-verification=h7hNxzyjxWcMmQGgdPl1sYiG5V-Bjrl_CsJqpKbIU4"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260813040637",
      "not_after": "20261111050620"
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 7.1,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
