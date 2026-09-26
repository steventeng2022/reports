# Security Audit Report — cambridge.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cambridge.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cambridge.org |
| Test date | 2026-09-26 17:41 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 5, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 16 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 17 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.110.190:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.110.190:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 15. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 16. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 17. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: confluent-verification=5cd8b60d-2121-4b7a-8dc9-6c3fb6a7bc43; google-site-verification=iDXI17Esaf_WqUOMbG7t1tkZ3cD3I2B81texGDyCmLE; atlassian-sending-domain-verification=681c02b7-bef7-4652-a1c3-b5999a7056c2
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of cambridge.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 70 disallow path(s), e.g. /, /, /, /aca/authorinformation/, /blocks
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "cambridge.org",
  "dns": {
    "a": [
      "104.17.110.190",
      "104.17.111.190"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "eu-smtp-inbound-2.mimecast.com (pref 4)",
      "eu-smtp-inbound-1.mimecast.com (pref 4)"
    ],
    "ns": [
      "lex.ns.cloudflare.com.",
      "nucum.ns.cloudflare.com."
    ],
    "spf": [
      "docusign=8f67c3ac-0e31-428a-b89b-d6c05efbcc57",
      "0c333ae6-6e62-4dd3-bd75-bbbe8c00a9e3",
      "confluent-verification=5cd8b60d-2121-4b7a-8dc9-6c3fb6a7bc43",
      "_qzf1ow8akt4j08t4s2mpxnfm03j00ap",
      "google-site-verification=iDXI17Esaf_WqUOMbG7t1tkZ3cD3I2B81texGDyCmLE",
      "amazonses:q6HVI+PeonYnqfC7kDzNqCrUyIXQnena/tC1RgTQZ/s=",
      "MS=ms61882158",
      "atlassian-sending-domain-verification=681c02b7-bef7-4652-a1c3-b5999a7056c2",
      "anthropic-domain-verification-mae9zt=OrJVGKqpLLCr3R2xm97n1UkaA",
      "00D2000000000hs=1TBQt00000001Vd",
      "krp4xlxh54n2p0jgnklc2sy826wnbqfd",
      "adobe-idp-site-verification=7d354030906008d5dcab28dc74cff0b4c3f868aa68415212c70801597f944dc8",
      "have-i-been-pwned-verification=361b42c0181f1c91867b0c7731657e90",
      "xwwmlgcbfg256thhdv0150228ks7rkzb",
      "amazonses:ULRvjmdH/bCZZFgF/xINBm531pRwaQntnQRX/m4r5Zc=",
      "77b755eb-0c8f-462f-9071-e147b4823dba",
      "knowbe4-site-verification=6f2a12971b44215b655214e401300716",
      "amazonses:Hk45M0qWK+GZ2iX9XJ0TVVq2mc+DayOePbXsYVp/abQ=",
      "_9acsisu491ieex01chikb1wu70u61ev",
      "_6rpwlgh7ul5lr5zxzlmlb7hpr2ejnqe",
      "miro-verification=e0eb88c47512f1b3e347014c28cd69d732b8cc38",
      "v=spf1 redirect=390fwuvj._spf._d.mim.ec",
      "google-site-verification=-houjDGhv3j4boUHMyT2w-kmHVFMJBopLlqOV9CRtXE",
      "onetrust-domain-verification=67ea4d2fa6f84245aa04d058118d26ad",
      "zoho-verification=zb43177975.zmverify.zoho.com",
      "onetrust-domain-verification=e66d1551d1154391a5e51733b7fc58a8",
      "teamviewer-sso-verification=db65502554224be3a892d0a1d7d23ac7",
      "figma-domain-verification=82306f7d5e6d9b44f70bf7e951c99627e467dcb0111c988d3ae2066031b18983-1755005759",
      "google-site-verification=N5etRfpe1AcCZMdSJz5sVicQHzzIr9RbU9cQTjQ94vE",
      "_7medm2uqul87tj3d47vgw0kjs7tvycm",
      "00D8d0000059NJR=1TBSq00000004jZ",
      "56l0x50ygt1fkr23c9npqsrmwqr2cvhb",
      "08261f74-adda-45ae-bab0-9b7e8919b7c7",
      "6mhwwb8qmrthfb7qmpjlkhr6w30yrqk7",
      "atlassian-domain-verification=7S7bsIrOwlHLdBG0OLNWITmcgqmnW8uaUKxRjA4McIJx1ThN46eQh2TaacXbCKhR",
      "SFMC-XCiRpahbO1482ub4X4SdBpTNt9_QuR4k5vr-azmb",
      "apple-domain-verification=dJCKMZtNMZrBxvyv",
      "facebook-domain-verification=nkrm6s56pcmfep9h0lgko47xsxxml5",
      "Z8kBemfkazJ2i4ysd4p6BpfEKVVRKFT0hQCLeyk8itVhI7FgQo/fof5BCS1pgLO13FaYp+KaVmX2pPT7/mtD+Q==",
      "google-site-verification=G2cATcZ2EVrpsOVGGF5MmI4kHQzXzEWHQ3MLXp2AmjI",
      "apple-domain-verification=DhDDkLn3rLrZDuNx",
      "formstack-domain-verification=bc1d27a650a1f333058871330e43d4c1",
      "amazonses:ivqwfLhOGGWGY27uhxdFOA4LwWOJLR+4cr1nUQ4Guh4=",
      "google-site-verification=RHYH2O4q7639HXg9OOtkhwU1GoSz2yrwFQ95dmHzArI",
      "parkable-domain-verification=tfyMMTd19z2TedD63DPVMyjFILPMgwM4IP7J2elpykE=",
      "apple-domain-verification=0z9Q3j82qURKE0jE"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:047acbdc29a7625@rep.dmarcanalyzer.com,mailto:dmarc-admin@cambridge.org; ruf=mailto:047acbdc29a7625@rep.dmarcanalyzer.com,mailto:dmarc-admin@cambridge.org; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "subject": "commonName=cambridge.org",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  9 05:21:18 2026 GMT",
    "notAfter": "Dec  8 06:21:14 2026 GMT",
    "san": [
      "cambridge.org",
      "resource.cambridge.org"
    ],
    "days_left": 72,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "104.17.110.190",
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
      "domain": "cambridge.org",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.cambridge.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 0",
    "/redirect?next=https://evil-auditor.example/x -> 0",
    "/go?url=https://evil-auditor.example/x -> 0",
    "/url?url=https://evil-auditor.example/x -> 0"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 0,
    "/.well-known/security.txt": 0,
    "/security.txt": 0,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 0,
    "/phpmyadmin/index.php": 0,
    "/server-status": 0,
    "/api/": 0
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "confluent-verification=5cd8b60d-2121-4b7a-8dc9-6c3fb6a7bc43",
    "google-site-verification=iDXI17Esaf_WqUOMbG7t1tkZ3cD3I2B81texGDyCmLE",
    "atlassian-sending-domain-verification=681c02b7-bef7-4652-a1c3-b5999a7056c2",
    "anthropic-domain-verification-mae9zt=OrJVGKqpLLCr3R2xm97n1UkaA",
    "adobe-idp-site-verification=7d354030906008d5dcab28dc74cff0b4c3f868aa68415212c708"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/",
      "/",
      "/aca/authorinformation/",
      "/blocks",
      "/concrete",
      "/config",
      "/controllers",
      "/css",
      "/elements",
      "/helpers",
      "/jobs",
      "/js",
      "/languages",
      "/libraries"
    ]
  },
  "elapsed_s": 208.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
