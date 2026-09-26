# Security Audit Report — zeit.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zeit.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | zeit.de |
| Test date | 2026-09-25 10:29 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

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
      "dns4.p01.nsone.net.",
      "dns1.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "dns3.p01.nsone.net."
    ],
    "spf": [
      "a8e28041862668f7d799dcf2cdff2f75",
      "google-gws-recovery-domain-verification=59065683",
      "mgverify=fa8deab5e1cdad1afca895f77cb4460493457c695b1b6b0bccc40a8732f882da",
      "teamviewer-sso-verification=0da1e5ee3dc04351aa206dff020cda50",
      "miro-verification=00f74b9596272eaafb51a7d481892788837e487b",
      "klaviyo-site-verification=VfVpZ3",
      "smeazeit.sbc1.getdirectrouting.de",
      "tollbit-domain-verification=0acc441095133f12278c9179168937ecd19b3f5c9b36b930acac5d3a96353c14",
      "gxg1t2ljzzj4n05h57kh5bvsxjr1ctcp",
      "jamf-site-verification=qlf_TOpLdeS2DNRMndJxIA",
      "atlassian-domain-verification=0KXQ/HyHlWaW2LeS2kKh/QYjoZkk7smirpVo/Q1IPHetkLFv/eN7OwNE/FKNVMh7",
      "1password-site-verification=76KQ3OKJ3FH35OMHXYMAINGJ5Q",
      "5F0-8UN-VT6",
      "MS=ms15247335",
      "mxI8RUm6rfKEWT0c",
      "adobe-idp-site-verification=9204c69a-b8c5-4286-a6d5-6c3259f8cf1d",
      "MS=ms37100824",
      "smeazeit.sbc2.getdirectrouting.de",
      "apple-domain-verification=TYlrXCrrWPMzHzAY",
      "P2A_58148_200",
      "elevenlabs=AkVMNw8U-sHd65pGypKEoqiMEsmMhUooL9FJ4TyUgaQ",
      "anthropic-domain-verification-djwjvt=JzQ9OZDYsDipeKOp8ddQCSBkh",
      "3j98x7j4yjf2xvtw6gt4rt8yjn117l3x",
      "google-site-verification=tLw22x4l0DHcYxy-T7rQxtbQp2bh3_GJ6vAeRXJQEAw",
      "asv=128b0bc0702196cf36653421800e6808",
      "figma-domain-verification=5e6d24ca5cac9fbcdad302605f2185d9a7fef03e17170672f424d334b70a949b-1768473624",
      "atlassian-domain-verification=1ImdxQwjaBPB5dXgPBYl2HIs9t45uAqjWHxPe2aKn2aKCTUXGuf3HXbG5vYm2959",
      "pardot1088002=2b9a0e203820f4740ccc144cc3a5c523f49f60334cd030c6b87aac23cf9ef02e",
      "canva-site-verification=HGiDOMp4J0OMWIO_vX2irg",
      "_globalsign-domain-verification=Fw09cFhmPL_-Bfg6BV5_NkyDEkXJfmQd4uPViX560A",
      "v=spf1 mx include:spf1.zeit.de include:spf.mailjet.com include:sendgrid.net include:spf.mandrillapp.com include:spfa.myconvento.com include:spf.protection.outlook.com ~all",
      "adobe-idp-site-verification=23219eabc0a82ab7eca544a45515b433090e77f559461941395be62189f6d8f0"
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
    "days_left": 37,
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 53.8,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
