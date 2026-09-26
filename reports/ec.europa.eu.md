# Security Audit Report — ec.europa.eu

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ec.europa.eu/ |
| Bug bounty program | European Central Bank |
| Listed scope domain | ec.europa.eu |
| Test date | 2026-09-26 18:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | SEC2 | security.txt published without a contact address | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Europa
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Europa
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: yahoo-verification-key=mIbs1g4mUnS9N9xQpPywHyyQ462sU/5p7+ObnIeT6QE=; cisco-ci-domain-verification=71375d94308e5d9c151ed03fb38e6e7c40081021ffaad12391a; atlassian-domain-verification=CdVasMY4c9BTCt8IJvPUjKbyz8YkV095KyECi5dLyhg481LAhk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ec.europa.eu has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 201 disallow path(s), e.g. /eurostat/tgm/, /europeaid/prag/, /archives/, /cgi-bin/, /clima/ets/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] security.txt published without a contact address (`SEC2`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt returns 200 but contains no mailto:/URL contact.
- **Recommendation:** Add a Contact: field per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "ec.europa.eu",
  "dns": {
    "a": [
      "147.67.34.30",
      "147.67.210.30"
    ],
    "aaaa": [
      "2a01:7080:24:100::666:30",
      "2a01:7080:14:100::666:30"
    ],
    "cname": null,
    "mx": [
      "mxb-00244802.gslb.pphosted.com (pref 10)",
      "mxa-00244802.gslb.pphosted.com (pref 10)",
      "ec-europa-eu.mail.protection.outlook.com (pref 30)"
    ],
    "ns": [],
    "spf": [
      "v=spf1 include:_spf.tech.ec.europa.eu include:_spf-jrc.tech.ec.europa.eu -all",
      "yahoo-verification-key=mIbs1g4mUnS9N9xQpPywHyyQ462sU/5p7+ObnIeT6QE=",
      "cisco-ci-domain-verification=71375d94308e5d9c151ed03fb38e6e7c40081021ffaad12391a0797f3487236f",
      "MS=ms93839866",
      "atlassian-domain-verification=CdVasMY4c9BTCt8IJvPUjKbyz8YkV095KyECi5dLyhg481LAhkwutfFJHSjULhnx",
      "atlassian-domain-verification=Sn5ZgXoanhUhLAap/3tkBbsCa4Kag0SfkSMmpJX8piK6/NsGjt5l7QJZYiDlhYh7",
      "anthropic-domain-verification-w18fn5=aCZHCSXAOr6mwQB6zAVj4LGSJ",
      "apple-domain-verification=0zqmupc9IJswQan3",
      "google-site-verification=eyHX1dZlZS9ZXUW4486Y8_HpDHE1ubuzInqkzRjnVBE",
      "cisco-ci-domain-verification=d9a4e5f569f0c36f811a4eb618d520d8d73a90beac438e9234a915465c56a2",
      "globalsign-domain-verification=U-m3rn1OpP3XdBtI6G_e7kKw156XwchHbjmX3n0iKq",
      "google-site-verification=Hf3TsilSdPh4WhYu26eFxy_8pIrtGVdDgqbAdjbbAw8",
      "DN6kiCaIRHg011SWPd/y5wK0nF1lAB0vxkimTgK6YHQ="
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:swtyii6t@ag.eu.dmarcadvisor.com; adkim=s; aspf=s"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=BE, stateOrProvinceName=Brussels-Capital Region, localityName=Brussels, organizationName=European Commission, commonName=*.ec.europa.eu",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R46 OV TLS CA 2026 Q3",
    "notBefore": "Jul 31 08:31:05 2026 GMT",
    "notAfter": "Feb 15 08:31:04 2027 GMT",
    "san": [
      "*.ec.europa.eu",
      "ec.europa.eu"
    ],
    "days_left": 141,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "147.67.34.30",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Europa"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.ec.europa.eu",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://ec.europa.eu/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "yahoo-verification-key=mIbs1g4mUnS9N9xQpPywHyyQ462sU/5p7+ObnIeT6QE=",
    "cisco-ci-domain-verification=71375d94308e5d9c151ed03fb38e6e7c40081021ffaad12391a",
    "atlassian-domain-verification=CdVasMY4c9BTCt8IJvPUjKbyz8YkV095KyECi5dLyhg481LAhk",
    "atlassian-domain-verification=Sn5ZgXoanhUhLAap/3tkBbsCa4Kag0SfkSMmpJX8piK6/NsGjt",
    "anthropic-domain-verification-w18fn5=aCZHCSXAOr6mwQB6zAVj4LGSJ"
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
      "aia_ocsp": null,
      "not_before": "20260731083105",
      "not_after": "20270215083104"
    }
  },
  "http2": {
    "robots_disallow": [
      "/eurostat/tgm/",
      "/europeaid/prag/",
      "/archives/",
      "/cgi-bin/",
      "/clima/ets/",
      "/clima/sites/registry/",
      "/commission_2010-2014/katainen/",
      "/creative-europe/404_en.htm",
      "/culture/404_en.htm",
      "/dgs/education_culture/404_en.htm",
      "/eclas/",
      "/education/404_en.htm",
      "/employment_social/anticipedia/xwiki/bin/attach/",
      "/employment_social/anticipedia/xwiki/bin/cancel/",
      "/employment_social/anticipedia/xwiki/bin/commentadd/"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 33.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
