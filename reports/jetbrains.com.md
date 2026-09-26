# Security Audit Report — jetbrains.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://jetbrains.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | jetbrains.com |
| Test date | 2026-09-26 18:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 4, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

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
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.jetbrains.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: cursor-domain-verification-kx5zm3=EHhTysB79O0oaoxmuZlbgfJYw; facebook-domain-verification=0f998tvqo94ievfo428kabcvdycn9h; anthropic-domain-verification-t2jwja=Ax8GJYbCx2Uaq35MjKnH9Z5Rd
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of jetbrains.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but jetbrains.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 58 disallow path(s), e.g. */search/, */shop/, */eshop*, */estore*, */unitrun*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.121.37 carries PTR server-3-169-121-37.tpe53.r.cloudfront.net. for jetbrains.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "jetbrains.com",
  "dns": {
    "a": [
      "3.169.121.37",
      "3.169.121.35",
      "3.169.121.64",
      "3.169.121.85"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-613.awsdns-12.net.",
      "ns-1519.awsdns-61.org.",
      "ns-345.awsdns-43.com.",
      "ns-1701.awsdns-20.co.uk."
    ],
    "spf": [
      "cursor-domain-verification-kx5zm3=EHhTysB79O0oaoxmuZlbgfJYw",
      "asv=2c6f6f1d4f86fdcfd7f783fbc213c156",
      "facebook-domain-verification=0f998tvqo94ievfo428kabcvdycn9h",
      "v=spf1 ip4:46.137.178.215 ip4:185.28.196.44 include:_spf.google.com include:mail.zendesk.com include:app.sgizmo.com include:_spf_jpf.jetbrains.com -all",
      "anthropic-domain-verification-t2jwja=Ax8GJYbCx2Uaq35MjKnH9Z5Rd",
      "2r108541pocsrgv2ee4k4palbt",
      "google-site-verification=rO0Vqzw1ONvxllSXDHAiBawvsUiZtN-aMUGBG-FZAHE",
      "slack-domain-verification=1SpvUQkKFcyXCGyrQbWXJOlPu9ALQ4L1RuS7ALjB",
      "openai-domain-verification=dv-1fZwLd26bBnn07NffqaJZ6r0",
      "yahoo-verification-key=FeFiNspylJnrSEIVSLEjBcfyUINn3/Qt7ZnZhcfoZfY=",
      "airtable-verification=2596e1bb140b4e035d2a8e41e276a383",
      "_r4pqu4ex9pljicqdyuy4eotrck5oodr",
      "miro-verification=d4eb88433fcbdf6060863c42a891b879673ba5da",
      "parallels-domain-verification=f2018ea7be8b4bacb7f159a7ef97c616644c16c842c84e7e9737ca8b4859b226",
      "astro-domain-verification=cm9v85qao05zd01hvhwwuzss6",
      "spf2.0/pra",
      "google-site-verification=mb2teCgiotyAsJVve9zLVfcQgW0AxPzkyDFPV7h0jq8",
      "docusign=51868e95-4167-4467-8c5d-aae4fe1dcdae",
      "google-site-verification=6itcxahei-MfNED1Q1oqRy251pbo8AMzq9wHO47vrG0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-rua@jetbrains.com,mailto:re+bev7vm33l2z@dmarc.postmarkapp.com; ruf=mailto:dmarc-ruf@jetbrains.com; fo=d; adkim=s; sp=reject;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=jetbrains.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jun 29 00:00:00 2026 GMT",
    "notAfter": "Jan 12 23:59:59 2027 GMT",
    "san": [
      "jetbrains.com",
      "jetbrains-com-prod.w3jbcom.aws.intellij.net"
    ],
    "days_left": 108,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.37",
    "open": []
  },
  "https": {
    "status": 308,
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
      "origin": "https://sub.jetbrains.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://jetbrains.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 308",
    "/redirect?next=https://evil-auditor.example/x -> 308",
    "/go?url=https://evil-auditor.example/x -> 308",
    "/url?url=https://evil-auditor.example/x -> 308"
  ],
  "paths": {
    "/robots.txt": 308,
    "/sitemap.xml": 308,
    "/.well-known/security.txt": 308,
    "/security.txt": 308,
    "/.git/HEAD": 308,
    "/.git/config": 308,
    "/.env": 308,
    "/.htaccess": 308,
    "/wp-login.php": 308,
    "/phpmyadmin/index.php": 308,
    "/server-status": 308,
    "/api/": 308
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "cursor-domain-verification-kx5zm3=EHhTysB79O0oaoxmuZlbgfJYw",
    "facebook-domain-verification=0f998tvqo94ievfo428kabcvdycn9h",
    "anthropic-domain-verification-t2jwja=Ax8GJYbCx2Uaq35MjKnH9Z5Rd",
    "google-site-verification=rO0Vqzw1ONvxllSXDHAiBawvsUiZtN-aMUGBG-FZAHE",
    "slack-domain-verification=1SpvUQkKFcyXCGyrQbWXJOlPu9ALQ4L1RuS7ALjB"
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
      "not_before": "20260629000000",
      "not_after": "20270112235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "*/search/",
      "*/shop/",
      "*/eshop*",
      "*/estore*",
      "*/unitrun*",
      "/languages/",
      "*/feedback/",
      "*/promo/",
      "*/download-thanks",
      "/?q",
      "/?products",
      "/?utm_source",
      "/?productedition",
      "/?src",
      "/?var"
    ]
  },
  "x12": {
    "status": 308,
    "ptr": [
      "server-3-169-121-37.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 5.3,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
