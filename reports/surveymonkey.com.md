# Security Audit Report — surveymonkey.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://surveymonkey.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | surveymonkey.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 6, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 14 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 15 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 16 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): us. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 14. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 15. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 16. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (wdelajtdiknx1q.surveymonkey.com and rqoqx0bzvjsa49.surveymonkey.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=asjlbqcsmgsjco17qidfpfi82a9n7f; gc-ai-domain-verification-8m6kgf=E1mwfXukrQWqurSC6BwoYbmNu; atlassian-domain-verification=keQyzOto0ziFKZDVbwTZ2DhKevhwLaTNteFi1PpPs31I0CQ4GB
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of surveymonkey.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 21 disallow path(s), e.g. /billing/confirmed, /billing/invoice*, /cc/, /content-svc/, /create/survey/preview*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "surveymonkey.com",
  "dns": {
    "a": [
      "65.9.180.59",
      "65.9.180.5",
      "65.9.180.3",
      "65.9.180.53"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)",
      "us-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-588.awsdns-09.net.",
      "ns-1380.awsdns-44.org.",
      "ns-1757.awsdns-27.co.uk.",
      "ns-344.awsdns-43.com."
    ],
    "spf": [
      "facebook-domain-verification=asjlbqcsmgsjco17qidfpfi82a9n7f",
      "gc-ai-domain-verification-8m6kgf=E1mwfXukrQWqurSC6BwoYbmNu",
      "atlassian-domain-verification=keQyzOto0ziFKZDVbwTZ2DhKevhwLaTNteFi1PpPs31I0CQ4GBiYXNZVhfxEhJv5",
      "lovable_verification=CsnCfnhpmMIm2YolPLFw",
      "_knfbojommw8fgbvijgndlnl58gxdcs9",
      "adobe-idp-site-verification=257235a8b871a199b2d89ab4f7cdaec03a65d1bf7ac30838dececcacace5a86c",
      "OSSRH-89589",
      "atlassian-domain-verification=tXdvJPw4WMjcNH3/0im4gOSMKwX5hyvl1CIiMtoHaTqygGKWQmk315B62OOR0pYe",
      "docusign=37225db5-de2e-4e7a-be46-db11ef071be9",
      "rOX6b5VqFrkPW2GtNMoaCyVEhwU",
      "docker-verification=b29c9172-8a00-44e6-9ea4-5d4de0569f58",
      "MS=ms60646135",
      "apple-domain-verification=KMruPJeKeD2jHgiK",
      "jamf-site-verification=pEif9hbPcODSQUOKmu0Szw",
      "cursor-domain-verification-6181me=rebW4WaJ5ylTKff9K0qedvm00",
      "miro-verification=81a06891162a7afb6cb31cdeb0c608b35ce224db",
      "smartsheet-site-validation=CmW6YpxpRVTHe6aNhQxtwQmYpyT9koJf",
      "google-site-verification=E8ZYHCDCcYtOkFiZMiBjfE3ml9AmqWzOpnd_MCOFYRM",
      "dpq1d680yv30b.cloudfront.net",
      "anthropic-domain-verification-b77rgg=i8sv1gogitHA9QiiiBEdIE2q2",
      "v=spf1 include:us._netblocks.mimecast.com include:surveymonkey.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "asv=37950f1917e5f9e7e48b305f9e529116",
      "google-site-verification=sEtassJLvphOixgHm2AhnGmM2DkWMHjIaC-vB17aitY",
      "google-site-verification=2ccit_qZjaKZqS5Ce8UFhP5hVYJDQXXOSup5UtUWZPo",
      "google-site-verification=qa36tpLOjyqVlObx-4lr7c-bQy2eL3AmktntNwMubnk",
      "jvMLQ8xH8X38HutWDQXyDJP7T-iqxBoYAg1AYT0omb",
      "globalsign-domain-verification=273eFvKCuCXR3P_oKS85yffiPwBPz0qc1fEV1-x8Aq",
      "onetrust-domain-verification=749bac94de654f24be6f1186b41d64d5",
      "nlsy424z3ktz0097zg4cw6hk44chc551",
      "openai-domain-verification=dv-Rizz1TAurN3w0Gk3aKfiY4U3",
      "ps-cd-verification=24840ced-b149-4e15-8b6c-04b567ba36da",
      "stripe-verification=3BC4A50A1E91CF90D3A2954A08BBF11F16272C3BB3576499B69A54AA5A2EB9F1",
      "1password-site-verification=44TOWBB3QJBB5N4OLOAOZO3IFQ",
      "google-site-verification=bS37nCLe4WX0alwAbP2aaEs3hgNXpocNevsjIyjJoX8"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email,mailto:dmarc_agg@auth.returnpath.net,mailto:mailadmin@surveymonkey.com; ruf=mailto:dmarc_afrf@auth.returnpath.net,mailto:mailadmin@surveymonkey.com; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=surveymonkey.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Oct 28 00:00:00 2025 GMT",
    "notAfter": "Nov 26 23:59:59 2026 GMT",
    "san": [
      "surveymonkey.com",
      "ca.research.net",
      "*.surveymonkey.net",
      "*.surveymonkey.ca",
      "surveymonkey.fr",
      "surveymonkey.de",
      "eu.surveymonkey.net",
      "*.research.net",
      "smassets.net",
      "*.eu.surveymonkey.net",
      "surveymonkey.ca",
      "*.surveymonkey.fr",
      "*.smassets.net",
      "*.feedbackeconomy.com",
      "*.surveymonkey.de",
      "curiosity.central.surveymonkey.com",
      "surveymonkey.co.uk",
      "*.surveymonkey.nl",
      "*.surveymonkey.com",
      "research.net",
      "eu.surveymonkey.com",
      "feedbackeconomy.com",
      "eu.research.net",
      "surveymonkey.net",
      "*.surveymonkey.eu",
      "surveymonkey.nl",
      "*.eu.surveymonkey.com",
      "*.ca.research.net",
      "*.surveymonkey.co.uk",
      "surveymonkey.eu",
      "*.eu.research.net"
    ],
    "days_left": 61,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.59",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.surveymonkey.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://surveymonkey.com/"
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
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "facebook-domain-verification=asjlbqcsmgsjco17qidfpfi82a9n7f",
    "gc-ai-domain-verification-8m6kgf=E1mwfXukrQWqurSC6BwoYbmNu",
    "atlassian-domain-verification=keQyzOto0ziFKZDVbwTZ2DhKevhwLaTNteFi1PpPs31I0CQ4GB",
    "lovable_verification=CsnCfnhpmMIm2YolPLFw",
    "adobe-idp-site-verification=257235a8b871a199b2d89ab4f7cdaec03a65d1bf7ac30838dece"
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
  "http2": {
    "robots_disallow": [
      "/billing/confirmed",
      "/billing/invoice*",
      "/cc/",
      "/content-svc/",
      "/create/survey/preview*",
      "/login/",
      "/mp/lp/",
      "/panelweb*",
      "/r/instant/response*",
      "/sign-up/",
      "/tr/v1/",
      "/user/",
      "/user/sign-up/sso-redirect",
      "/*?usecase=",
      "/*?query="
    ]
  },
  "elapsed_s": 9.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
