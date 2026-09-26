# Security Audit Report — abebooks.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://abebooks.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | abebooks.com |
| Test date | 2026-09-26 17:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

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
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
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
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=VpUsJZxt_16j3r7pcOpdvg; google-site-verification=JTPx2-G7CvPiiPJsAsMAWAx1tJVn9aviyV_B6rY2yWM; docker-verification=fb08c2c0-f24a-48ef-9186-9afd873786ff
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of abebooks.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 66 disallow path(s), e.g. /servlet/, /abe/, /abep/, /cgi/, /search/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "abebooks.com",
  "dns": {
    "a": [
      "99.83.223.161",
      "75.2.69.186"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "amazon-smtp.amazon.com (pref 10)"
    ],
    "ns": [
      "ns-148.awsdns-18.com.",
      "ns-1700.awsdns-20.co.uk.",
      "ns-1492.awsdns-58.org.",
      "ns-647.awsdns-16.net."
    ],
    "spf": [
      "MS=ms14925990",
      "canva-site-verification=VpUsJZxt_16j3r7pcOpdvg",
      "MS=D34F561A65A1538CFE519E225C47127473C0B6AD",
      "00D2E00000131R3=1TBat00000002mb",
      "google-site-verification=JTPx2-G7CvPiiPJsAsMAWAx1tJVn9aviyV_B6rY2yWM",
      "docker-verification=fb08c2c0-f24a-48ef-9186-9afd873786ff",
      "00Df4000001cwvQ=1TBat00000002WT",
      "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbDvoGpRaIwj/tgPH",
      "v=spf1 include:spf1.amazon.com include:spf2.amazon.com include:amazonses.com -all",
      "MS=ms57068388",
      "stripe-verification=FD47CFC0B7963A0C1F1188BD521D2A02CFE12E6D26B3E5C7A280B16C38E86E8D",
      "stripe-verification=B0AD8DC1918B8A717E5B6A29C2E04594A9872AB05F8DA24CB762BBA0A0487BC6",
      "TS1760027",
      "e1d8d3c2-7a00-4668-aa88-4f0012f5b901"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=quarantine;",
      "pct=100;",
      "rua=mailto:report@dmarc.amazon.com;",
      "ruf=mailto:report@dmarc.amazon.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=prod.aberedirectservice.redirectservice.abebooks.a2z.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Aug  4 00:00:00 2026 GMT",
    "notAfter": "Feb 17 23:59:59 2027 GMT",
    "san": [
      "prod.aberedirectservice.redirectservice.abebooks.a2z.com",
      "www.community.abebooks.com",
      "www.abebooks.ca",
      "splunk-aws.abebooks.com",
      "data.abebooks.de",
      "soporte-comprador.iberlibro.com",
      "aide-acheteur.abebooks.fr",
      "stash.kokanee.abebooks.com",
      "data.zvab.com",
      "password.abebooks.com",
      "forums.abebooks.de",
      "jiratest.kokanee.abebooks.com",
      "abebooks.com",
      "soporte-libreria.iberlibro.com",
      "splunk-aws-prod.abebooks.com",
      "verkaeuferhilfe.abebooks.de",
      "password.ops.abebooks.com",
      "redirect-service.ops.abebooks.com",
      "splunk.abebooks.com",
      "www.feriadeprimavera.com",
      "prod.jira.abeatlassian.abebooks.a2z.com",
      "jira.kokanee.abebooks.com",
      "homebase-hilfe.abebooks.de",
      "oneboxalb.prod.aberedirectservice.redirectservice.abebooks.a2z.com",
      "data.abebooks.com",
      "data.iberlibro.com",
      "alb.prod.aberedirectservice.redirectservice.abebooks.a2z.com",
      "aiuto-homebase.abebooks.it",
      "data.abebooks.fr",
      "help.abebooks.com",
      "stashtest.kokanee.abebooks.com",
      "kaeuferhilfe.zvab.com",
      "forums.abebooks.co.uk",
      "feriadeprimavera.com",
      "www.community.abebooks.co.uk",
      "aide-vendeur.abebooks.fr",
      "sellerhelp.abebooks.co.uk",
      "forums.abebooks.com",
      "kaeuferhilfe.abebooks.de",
      "aiuto-acquirenti.abebooks.it",
      "aide-homebase.abebooks.fr",
      "splunk-aws-dev.abebooks.com",
      "aiuto-libreria.abebooks.it",
      "forums.abebooks.fr",
      "prod.confluence.abeatlassian.abebooks.a2z.com",
      "data.abebooks.it",
      "data.abebooks.co.uk",
      "buyerhelp.abebooks.co.uk",
      "confluence.kokanee.abebooks.com",
      "confluence02.kokanee.abebooks.com",
      "ayuda-homebase.iberlibro.com"
    ],
    "days_left": 144,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "99.83.223.161",
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
      "origin": "https://sub.abebooks.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.abebooks.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "canva-site-verification=VpUsJZxt_16j3r7pcOpdvg",
    "google-site-verification=JTPx2-G7CvPiiPJsAsMAWAx1tJVn9aviyV_B6rY2yWM",
    "docker-verification=fb08c2c0-f24a-48ef-9186-9afd873786ff",
    "atlassian-domain-verification=ZT4AapXgobCpXIWoNcd7gtMjZyOUdr4EDFMnFUWrqqqgdaQVbD",
    "stripe-verification=FD47CFC0B7963A0C1F1188BD521D2A02CFE12E6D26B3E5C7A280B16C38E8"
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
      "/servlet/",
      "/abe/",
      "/abep/",
      "/cgi/",
      "/search/",
      "/docs/Newsletters/BD",
      "/es/docs/BooksellerCentral/informativos",
      "/collections/",
      "/checkout/",
      "/discovery/",
      "/docs/asdfrawq/",
      "/checkout/",
      "/servlet/",
      "/abe/",
      "/abep/"
    ]
  },
  "elapsed_s": 27.1,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
