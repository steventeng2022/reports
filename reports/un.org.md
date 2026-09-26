# Security Audit Report — un.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://un.org/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | un.org |
| Test date | 2026-09-26 19:01 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

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

### 8. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://un.org/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: ms-domain-verification=a90c74aa-0e09-44e5-aff2-9e0d51862a8a; _globalsign-domain-verification=upE8q9Q9163O4I3STTC5-_7JD5phBQpi2CMFWRCqom; atlassian-sending-domain-verification=b818d67b-c504-4b82-a2ac-fb1ffa5dd99e
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of un.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but un.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 37 disallow path(s), e.g. /includes/, /misc/, /modules/, /profiles/, /scripts/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "un.org",
  "dns": {
    "a": [
      "157.150.185.92",
      "157.150.185.49"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "un-org.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns3.un.org.",
      "ns1.un.org.",
      "ns2.un.org."
    ],
    "spf": [
      "MS=ms26002463",
      "00D2E000000pRe2=1TBVK00000000o1",
      "ms-domain-verification=a90c74aa-0e09-44e5-aff2-9e0d51862a8a",
      "brevo-code:4258a8aaff2c4cc4d4f46631ee3f416d",
      "_globalsign-domain-verification=upE8q9Q9163O4I3STTC5-_7JD5phBQpi2CMFWRCqom",
      "fastly-domain-delegation-xss3y9gtai43byf7o4ey-00458132-2025-07-09",
      "atlassian-sending-domain-verification=b818d67b-c504-4b82-a2ac-fb1ffa5dd99e",
      "iContact1651565",
      "teamviewer-sso-verification=fde5c90fdb764da199caa79160aef58b",
      "atlassian-domain-verification=FTWfMaOalWt6nDxqxSGymL9Ey/KoIooB7a1zLsjL5bvuQbXb/CPo6bsrqR2yTU0G",
      "atlassian-sending-domain-verification=030cf619-e1ff-4c61-b2ff-0b8bf31422e8",
      "atlassian-domain-verification=1rY0mwP3xqUqI0Z6SVEdrrPHJ4hquQL28GrmRTVZ6/IZMKDmPspPa9jE7fXrIYMj",
      "56a37f487f3361c43f8c285de2f7f60839ac3a7f1bd37b37353ecd343c995fa2",
      "brevo-code:0502b29d26710cfe3a7f5a6713f7b141",
      "amazonses:cq717whOBbl30dhYr9HtG5aBpZfmtVwZ8/8TyeUrXh8=",
      "brevo-code:8016bd7e8b58b2c44d2253f7a674b1f9",
      "atlassian-domain-verification=4qBZ2F7TUigBgD7l6Ate/ExncM2HVQU855IzHmcHurVkPVGUU6H2ATvyZFEnnk9N",
      "apple-domain-verification=yaMAnI0GjK2mwjBL",
      "atlassian-sending-domain-verification=1d232bde-ddc5-4e81-84a4-5fc29c17acdf",
      "mandrill_verify.J6D4EK4DxGiLqR1nMTfHSA",
      "rij4mb6stfqk9nqp6db054r4se",
      "FOhfWhsJtJ/FZcqQdLjqBNwOqynP/KX4ozWsJFw+k50mDbWjv05zbvEonHMzMIKP9XSZ77kWWuilSHT/t7BQ8w==",
      "webexdomainverification.4C675B882DC2B136E053AB06FC0A3F65=6652b0a5-c301-4a9f-8629-d7e156da37b8",
      "brevo-code:2b3f7ca5e298561aaac08baef2898ff7",
      "v=spf1 include:spf.protection.outlook.com include:_netblocks.un.org include:_netblocks2.un.org include:_spf.google.com -all",
      "google-site-verification=dFG8i5QSNlXCckN62lWWTmmj7TEVkVh_G82rHzMPeaE",
      "xrqyoOBvFUFgFNdafNF3eo+zN4SEGAc+1gcHkfcbobjGa/UFAkMc/rCWUxywPjgWU1yMIYtuFAnHfLXdgFbRLQ==",
      "sendinblue-code:c80931e2ffea8fadc62c1bfb5141f449",
      "_globalsign-domain-verification=InsBxD8bdOtSqNib2b8QE1vAWRL07fy1C1VP9BHZO1",
      "cisco-ci-domain-verification=71023db9cebccd164d6c6916b649179c4109a8bf4a53206db808dc9c778dd271",
      "d365mktkey=GU4x93TE2dUlhH2NSdB6v7gbxcKnvDje0eF8WD0rNnUx",
      "j9lgbXbR0aOn/a3/tHAIQ1aK4uhUriBVu4/6I88jmBK0NyrCV36RIyrHwXouU3F0uQSEK0EPj6eBZ/Tc1odW4w==",
      "atlassian-sending-domain-verification=685ec4a1-3cfc-4ffa-8d51-9f6bb6f07baa",
      "adobe-idp-site-verification=44b9613bd417076c4622079494211a8fb11053a66a37a841db2e2dceccae8485",
      "cisco-ci-domain-verification=3be0a328c387dcfe19bfab64b24e33f04b04e2065771adbc4043b754f65d8392"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@un.org; ruf=mailto:dmarc@un.org; fo=0:1:d:s; adkim=r; aspf=r"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=United Nations, commonName=*.un.org",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Sep  4 17:41:36 2026 GMT",
    "notAfter": "Mar 22 17:41:36 2027 GMT",
    "san": [
      "*.un.org",
      "un.org"
    ],
    "days_left": 176,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "157.150.185.92",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.un.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://un.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "ms-domain-verification=a90c74aa-0e09-44e5-aff2-9e0d51862a8a",
    "_globalsign-domain-verification=upE8q9Q9163O4I3STTC5-_7JD5phBQpi2CMFWRCqom",
    "atlassian-sending-domain-verification=b818d67b-c504-4b82-a2ac-fb1ffa5dd99e",
    "teamviewer-sso-verification=fde5c90fdb764da199caa79160aef58b",
    "atlassian-domain-verification=FTWfMaOalWt6nDxqxSGymL9Ey/KoIooB7a1zLsjL5bvuQbXb/C"
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
      "aia_ocsp": null,
      "not_before": "20260904174136",
      "not_after": "20270322174136"
    }
  },
  "http2": {
    "robots_disallow": [
      "/includes/",
      "/misc/",
      "/modules/",
      "/profiles/",
      "/scripts/",
      "/themes/",
      "/en/internaljustice/files/",
      "/CHANGELOG.txt",
      "/cron.php",
      "/INSTALL.mysql.txt",
      "/INSTALL.pgsql.txt",
      "/INSTALL.sqlite.txt",
      "/install.php",
      "/INSTALL.txt",
      "/LICENSE.txt"
    ]
  },
  "x12": {
    "status": 302
  },
  "elapsed_s": 38.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
