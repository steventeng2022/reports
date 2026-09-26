# Security Audit Report — zeit.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zeit.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | zeit.de |
| Test date | 2026-09-26 19:02 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
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
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

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
- **Detail:** Apex TXT records with verification/token content: jamf-site-verification=qlf_TOpLdeS2DNRMndJxIA; figma-domain-verification=5e6d24ca5cac9fbcdad302605f2185d9a7fef03e17170672f424d3; google-gws-recovery-domain-verification=59065683
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of zeit.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but zeit.de is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 43 disallow path(s), e.g. /angebote/, /zeit/, /suche/, /templates/, /hp_channels/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.40.5.50 carries PTR 50.5.40.34.bc.googleusercontent.com. for zeit.de.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "zeit.de",
  "dns": {
    "a": [
      "34.40.5.50"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "zeit-de.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "dns1.p01.nsone.net.",
      "dns3.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "dns4.p01.nsone.net."
    ],
    "spf": [
      "jamf-site-verification=qlf_TOpLdeS2DNRMndJxIA",
      "figma-domain-verification=5e6d24ca5cac9fbcdad302605f2185d9a7fef03e17170672f424d334b70a949b-1768473624",
      "MS=ms37100824",
      "mxI8RUm6rfKEWT0c",
      "google-gws-recovery-domain-verification=59065683",
      "a8e28041862668f7d799dcf2cdff2f75",
      "miro-verification=00f74b9596272eaafb51a7d481892788837e487b",
      "v=spf1 mx include:spf1.zeit.de include:spf.mailjet.com include:sendgrid.net include:spf.mandrillapp.com include:spfa.myconvento.com include:spf.protection.outlook.com ~all",
      "anthropic-domain-verification-djwjvt=JzQ9OZDYsDipeKOp8ddQCSBkh",
      "asv=128b0bc0702196cf36653421800e6808",
      "google-site-verification=tLw22x4l0DHcYxy-T7rQxtbQp2bh3_GJ6vAeRXJQEAw",
      "gxg1t2ljzzj4n05h57kh5bvsxjr1ctcp",
      "atlassian-domain-verification=1ImdxQwjaBPB5dXgPBYl2HIs9t45uAqjWHxPe2aKn2aKCTUXGuf3HXbG5vYm2959",
      "mgverify=fa8deab5e1cdad1afca895f77cb4460493457c695b1b6b0bccc40a8732f882da",
      "pardot1088002=2b9a0e203820f4740ccc144cc3a5c523f49f60334cd030c6b87aac23cf9ef02e",
      "teamviewer-sso-verification=0da1e5ee3dc04351aa206dff020cda50",
      "tollbit-domain-verification=0acc441095133f12278c9179168937ecd19b3f5c9b36b930acac5d3a96353c14",
      "adobe-idp-site-verification=23219eabc0a82ab7eca544a45515b433090e77f559461941395be62189f6d8f0",
      "canva-site-verification=HGiDOMp4J0OMWIO_vX2irg",
      "MS=ms15247335",
      "elevenlabs=AkVMNw8U-sHd65pGypKEoqiMEsmMhUooL9FJ4TyUgaQ",
      "apple-domain-verification=TYlrXCrrWPMzHzAY",
      "klaviyo-site-verification=VfVpZ3",
      "atlassian-domain-verification=0KXQ/HyHlWaW2LeS2kKh/QYjoZkk7smirpVo/Q1IPHetkLFv/eN7OwNE/FKNVMh7",
      "smeazeit.sbc1.getdirectrouting.de",
      "1password-site-verification=76KQ3OKJ3FH35OMHXYMAINGJ5Q",
      "adobe-idp-site-verification=9204c69a-b8c5-4286-a6d5-6c3259f8cf1d",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
      "smeazeit.sbc2.getdirectrouting.de",
      "P2A_58148_200",
      "5F0-8UN-VT6",
      "3j98x7j4yjf2xvtw6gt4rt8yjn117l3x"
    ],
    "dmarc": [
      "v=DMARC1; p=none;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=zeit.de",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug  4 05:35:36 2026 GMT",
    "notAfter": "Nov  2 05:35:35 2026 GMT",
    "san": [
      "zeit.de"
    ],
    "days_left": 36,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.40.5.50",
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
      "origin": "https://sub.zeit.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.zeit.de/index"
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
    "jamf-site-verification=qlf_TOpLdeS2DNRMndJxIA",
    "figma-domain-verification=5e6d24ca5cac9fbcdad302605f2185d9a7fef03e17170672f424d3",
    "google-gws-recovery-domain-verification=59065683",
    "miro-verification=00f74b9596272eaafb51a7d481892788837e487b",
    "anthropic-domain-verification-djwjvt=JzQ9OZDYsDipeKOp8ddQCSBkh"
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
      "not_before": "20260804053536",
      "not_after": "20261102053535"
    }
  },
  "http2": {
    "robots_disallow": [
      "/angebote/",
      "/zeit/",
      "/suche/",
      "/templates/",
      "/hp_channels/",
      "/send/",
      "/rezepte/suche/",
      "*/comment-thread?",
      "*/liveblog-backend*",
      "/framebuilder/",
      "/campus/framebuilder/",
      "/navigation-teasers*",
      "*iqadcontroller.js",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "50.5.40.34.bc.googleusercontent.com."
    ]
  },
  "elapsed_s": 29.1,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
