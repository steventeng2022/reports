# Security Audit Report — penguinrandomhouse.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://penguinrandomhouse.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | penguinrandomhouse.com |
| Test date | 2026-09-26 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=qrGQ4gxWAdHknibYOR88zw; miro-verification=20deb2e76b80e8360f078ce72b4c1b020ccbe7e1; atlassian-domain-verification=Kl3ByU1tsfV9fKiC7TDDZYz1uCeTeUo0SSEh5SitZ9q99Ua74O
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of penguinrandomhouse.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "penguinrandomhouse.com",
  "dns": {
    "a": [
      "170.171.208.137"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)",
      "us-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-1709.awsdns-21.co.uk.",
      "ns-1259.awsdns-29.org.",
      "ns-643.awsdns-16.net.",
      "ns-362.awsdns-45.com."
    ],
    "spf": [
      "canva-site-verification=qrGQ4gxWAdHknibYOR88zw",
      "p^80Ofvy%178DnED&JH$OktbSDSDHdBu8r5TXqXJUzrLTNplO6PB1VAb%#xV06wEKl7lOoFd2erdL@$w0BThd9#s6rEd%9C%tPu",
      "miro-verification=20deb2e76b80e8360f078ce72b4c1b020ccbe7e1",
      "atlassian-domain-verification=Kl3ByU1tsfV9fKiC7TDDZYz1uCeTeUo0SSEh5SitZ9q99Ua74O571fgiIg//j5Hn",
      "apple-domain-verification=fSsk2qTskZIXUkhu",
      "monday-com-verification=TT0Hb7qY-id2x_o-2OkWXSSLVpTxTADfmHwVAOcLHIk",
      "anthropic-domain-verification-p3yxqz=0oTx7Z8mJYN8MCnVfLRuy7xrz",
      "openai-domain-verification=dv-Rhm7Hg5yRtoNsmysb1sZR4hb",
      "asv=300738b15ca5d787a896887a6179da76",
      "twilio-domain-verification=fc6fe5f3866856223b427fe22f87cacc",
      "applause-verification:e7f9bc17-1978-415a-83ab-955ebc93e7eb",
      "airtable-verification=07656b9d1c59ef275dc5cf2cc40f902f",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "d240bb6782951c680216e3b2c275a67a287ab413a4dbc83ff6",
      "smartsheet-site-validation=cVJvac04NWxSPbNbKVyoQXTc977egjBr",
      "HmQrtF+YeGABOOs4sUIGNzx5oH/hxa/uuKITM72aP2D3Mmo45+IYTHRRNErkCFI5FluDKT7Og9fYZwF4n3wWlw==",
      "sophos-domain-verification=30c16c4ad4dd85043d6766d195b3be1bf04c9425e55a4a79745bd7a135474f3b"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r; rua=mailto:dmarc_agg@vali.email,mailto:4065f1db5e3e741@rep.dmarcanalyzer.com,mailto:bb918c48@inbox.ondmarc.com; ruf=mailto:4065f1db5e3e741@for.dmarcanalyzer.com,mailto:bb918c48@inbox.ondmarc.com; fo=1; ri=",
      "3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "commonName=*.penguinrandomhouse.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV R36",
    "notBefore": "Dec 16 00:00:00 2025 GMT",
    "notAfter": "Jan  9 23:59:59 2027 GMT",
    "san": [
      "*.penguinrandomhouse.com",
      "penguinrandomhouse.com"
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
    "ip": "170.171.208.137",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.penguinrandomhouse.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.penguinrandomhouse.com/"
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
    "canva-site-verification=qrGQ4gxWAdHknibYOR88zw",
    "miro-verification=20deb2e76b80e8360f078ce72b4c1b020ccbe7e1",
    "atlassian-domain-verification=Kl3ByU1tsfV9fKiC7TDDZYz1uCeTeUo0SSEh5SitZ9q99Ua74O",
    "apple-domain-verification=fSsk2qTskZIXUkhu",
    "monday-com-verification=TT0Hb7qY-id2x_o-2OkWXSSLVpTxTADfmHwVAOcLHIk"
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
  "elapsed_s": 35.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
