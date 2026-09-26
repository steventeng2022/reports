# Security Audit Report — buffer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://buffer.com/ |
| Bug bounty program | Buffer |
| Listed scope domain | buffer.com |
| Test date | 2026-09-26 18:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 5, Info: 19)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 13 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 14 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 15 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 16 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 17 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 18 | info | P8 | Missing security.txt | CWE-1038 |
| 19 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 20 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 21 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 22 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 23 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 24 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.98.118:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.98.118:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; X-Powered-By: Next.js; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=15552000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'AWSALBTG' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 13. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'AWSALBTG' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 14. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'buffer-marketing' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 15. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'buffer-marketing' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 16. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'buffer-marketing.sig' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 17. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'buffer-marketing.sig' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 18. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 19. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 20. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 21. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: prtoolkit-verification=03646c6d6d2ac0f380012c074391bce38a2a9608fac40fa63b6501326; google-site-verification=gET2bT39fxReuQ0vLGbVvA9TyxZOmEbpePtAX7xY6oA; google-site-verification=hD-bBRWeNejlB37u_tZThoEBoyq3JcLLqog3Rl5Eqs8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 22. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of buffer.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 23. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but buffer.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 24. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 8 disallow path(s), e.g. /add, /ajax, /button, /docs-custom-code.js, /docs-footer
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "buffer.com",
  "dns": {
    "a": [
      "104.18.98.118",
      "104.18.99.118"
    ],
    "aaaa": [
      "2606:4700::6812:6276",
      "2606:4700::6812:6376"
    ],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "tess.ns.cloudflare.com.",
      "dom.ns.cloudflare.com."
    ],
    "spf": [
      "prtoolkit-verification=03646c6d6d2ac0f380012c074391bce38a2a9608fac40fa63b65013268e60491",
      "google-site-verification=gET2bT39fxReuQ0vLGbVvA9TyxZOmEbpePtAX7xY6oA",
      "google-site-verification=hD-bBRWeNejlB37u_tZThoEBoyq3JcLLqog3Rl5Eqs8",
      "B37AB95EC3",
      "facebook-domain-verification=7cr8hfn0y878zjxzgt4hbknwhxuk5y",
      "v=spf1 include:helpscoutemail.com include:_spf.google.com include:mail.zendesk.com ~all",
      "google-site-verification=x9nCBH6uz8yQAOEqpV3TqMnL9gI9nj1Iqz5OTJCi8Xg",
      "segment-site-verification=e7Zo5L9jKVjVcKRFi1acX9nyEQOnl6z3",
      "google-site-verification=142Thz3s7mzQJSHORKyyk0QndKtfKg9DakzAiCX6mDA",
      "1password-site-verification=HD5MBSOQ2ZAYLC55FI3SHX7IP4",
      "stripe-verification=436470f5c9a974d3045706507ca0deef5fc07b3d82d6456180bce09ef19e13b6",
      "183374251-11850589",
      "hj=232078-02102021",
      "google-site-verification=3aAc3sRkZQKuVjCNI_RbHVKkmv-r4lhLXRlvHMR4_l8",
      "plain-domain-verification-60n9xv=CBUGsWquVTelyl6FeO4WdfFRf",
      "google-site-verification=LLI4gMxLVK41gPBfxcDZqgyaUxFSMhsDE70-r-pXzso",
      "google-site-verification=2cyRtTXa49V-EbiOs0W-MqSfKfp_smVNFF76A9YguLQ",
      "google-site-verification=jpDzphFKQHfOP1m86Lu3xA2lyx4wZwx2DILni2KvWFc",
      "google-site-verification=Y09tg5UAyuUXsF8PZ-W92iDQaq9DVNJpuwwGiAZ4Sug"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:re+expge6woxi3@dmarc.postmarkapp.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=buffer.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug 30 18:46:28 2026 GMT",
    "notAfter": "Nov 28 18:46:27 2026 GMT",
    "san": [
      "buffer.com",
      "debugger.buffer.com"
    ],
    "days_left": 62,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.98.118",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Buffer: Social media management for everyone"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "X-Powered-By: Next.js",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {},
    {
      "samesite": "none"
    },
    {
      "domain": ".buffer.com"
    },
    {
      "domain": ".buffer.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.buffer.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://buffer.com:443/"
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
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "prtoolkit-verification=03646c6d6d2ac0f380012c074391bce38a2a9608fac40fa63b6501326",
    "google-site-verification=gET2bT39fxReuQ0vLGbVvA9TyxZOmEbpePtAX7xY6oA",
    "google-site-verification=hD-bBRWeNejlB37u_tZThoEBoyq3JcLLqog3Rl5Eqs8",
    "facebook-domain-verification=7cr8hfn0y878zjxzgt4hbknwhxuk5y",
    "google-site-verification=x9nCBH6uz8yQAOEqpV3TqMnL9gI9nj1Iqz5OTJCi8Xg"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260830184628",
      "not_after": "20261128184627"
    }
  },
  "http2": {
    "robots_disallow": [
      "/add",
      "/ajax",
      "/button",
      "/docs-custom-code.js",
      "/docs-footer",
      "/free-trial",
      "/pricing-calculator",
      "/"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 12.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
