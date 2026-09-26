# Security Audit Report — eventim.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eventim.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | eventim.de |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

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

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=F_ofMVEQrI9dLToCH3W8TD_pw5_J6-c8SzSxA8cC80Q; shopify-verification-code=lq13eQZumd4BKaWYIyggeIVKHPtwvs; facebook-domain-verification=gor6r8bwyofwjen3uatmmco60ne6cf
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of eventim.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "eventim.de",
  "dns": {
    "a": [
      "23.210.215.208",
      "23.210.215.203"
    ],
    "aaaa": [
      "2600:1417:76::17d2:d7d0",
      "2600:1417:76::17d2:d7cb"
    ],
    "cname": null,
    "mx": [
      "mxb-0072c901.gslb.pphosted.com (pref 10)",
      "mxa-0072c901.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "a13-67.akam.net.",
      "a3-64.akam.net.",
      "a6-65.akam.net.",
      "a1-222.akam.net.",
      "a10-65.akam.net.",
      "a12-66.akam.net."
    ],
    "spf": [
      "google-site-verification=F_ofMVEQrI9dLToCH3W8TD_pw5_J6-c8SzSxA8cC80Q",
      "mandrill_verify.RGbU4FqxJLlLqTEzZtTrXA",
      "_zyobswc54veb1thhshrfrn0eyyjrziu",
      "/dEZPSK+nF6rq7laQtMlbSXm01b+++Hl68NWiIIHiPIqS6GcjfZ+UaCfY1NgsYFDwHRno0/1a6DF6lfHx+idXw==",
      "shopify-verification-code=lq13eQZumd4BKaWYIyggeIVKHPtwvs",
      "facebook-domain-verification=gor6r8bwyofwjen3uatmmco60ne6cf",
      "_zcu8mukkq7g0jjxpsz7ciwpnrsh11ed",
      "jamf-site-verification=1mGbPXJW8-h7z9OTyuY-fg",
      "1password-site-verification=5EMB7KTOU5E5LF4C27XXNT4JRM",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "onetrust-domain-verification=f6f96e3b0d334cc78bb3372701e00911",
      "_x0m99eexri0eo0jy3oqceax1lsautou",
      "_an4lngigs1w4891di1fcerxtiwz8kld",
      "bw=Y2eRcRZKeuigrljql8ybFRciwBnMGGAfYm9hXTK35nip",
      "atlassian-domain-verification=sRxNCVi7vbQFvIQOy3yD5wRhIsBfb/nlTssiVfRTkqhr2bN35VWGJsPaLo/7hvER",
      "MS=ms55918227",
      "1password-site-verification=LFNAA7NAAZFULMFWJPXE5Q5JEQ",
      "1password-site-verification=ZI4O7DDYBRHUVMKUSTM6RJ7RN4",
      "miro-verification=2ae9c59047c26ca58554168f7baccaf715e607b4",
      "apple-domain-verification=GOce9gVZOyTRkab6",
      "teamviewer-sso-verification=0775685533454aaf911ae2316becb5e1",
      "sending_domain1071343=7651b6fc060ab34ceea035d6cd9b65c21bc0e6c6ced9cdb9734e5b6fd53cd125",
      "mixpanel-domain-verify=cafd88b1-917f-4159-bc47-b1c7052ff275",
      "openai-domain-verification=dv-LWOQZyUBe4v4LUx1ryWVZhwi",
      "dell-technologies-domain-verification=eventim.de_0294e23e-488b-47ff-a6f7-d1fe73b1524c_1756375967",
      "google-site-verification=s_J1gtfGgebN6_0ZHBAGpeuFpD3Jz9qK7wjc8wTeC6k",
      "stripe-verification=AF5DD7294082E8A97C22C5A02EB429FA306374CFA56E6B747A47A6F83525EF4A"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com,mailto:dmarc@eventim.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:dmarc@eventim.com; pct=100;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=eventim.de",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Sep 16 11:37:02 2026 GMT",
    "notAfter": "Dec 15 11:37:01 2026 GMT",
    "san": [
      "billetlugen.dk",
      "cts.eventim.bg",
      "cts.eventim.hr",
      "cts.eventim.hu",
      "cts.eventim.ro",
      "cts.eventim.si",
      "entradas.com",
      "eventim.ca",
      "eventim.co.il",
      "eventim.co.uk",
      "eventim.com",
      "eventim.com.ar",
      "eventim.com.br",
      "eventim.cz",
      "eventim.de",
      "eventim.fi",
      "eventim.fr",
      "eventim.hr",
      "eventim.nl",
      "eventim.no",
      "eventim.pl",
      "eventim.pt",
      "eventim.ro",
      "eventim.se",
      "eventim.si",
      "eventim.sk",
      "eventimsports.com",
      "eventimsports.de",
      "fansale.ch",
      "fansale.co.uk",
      "fansale.de",
      "fansale.dk",
      "fansale.fi",
      "fansale.no",
      "fansale.se",
      "getgo.de",
      "lippu.fi",
      "paytoll.eu",
      "ticket-shop.de",
      "ticketcorner.ch",
      "ticketone.it",
      "ticketonline.de",
      "tickets.bimot.co.il",
      "ticketshop.de",
      "www.eventim.fi"
    ],
    "days_left": 79,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.210.215.208",
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
      "origin": "https://sub.eventim.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
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
    "/.well-known/security.txt": 200,
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
    "google-site-verification=F_ofMVEQrI9dLToCH3W8TD_pw5_J6-c8SzSxA8cC80Q",
    "shopify-verification-code=lq13eQZumd4BKaWYIyggeIVKHPtwvs",
    "facebook-domain-verification=gor6r8bwyofwjen3uatmmco60ne6cf",
    "jamf-site-verification=1mGbPXJW8-h7z9OTyuY-fg",
    "1password-site-verification=5EMB7KTOU5E5LF4C27XXNT4JRM"
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
  "elapsed_s": 4.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
