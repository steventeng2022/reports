# Security Audit Report — upwork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://upwork.com/ |
| Bug bounty program | Upwork |
| Listed scope domain | upwork.com |
| Test date | 2026-09-26 17:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 1, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.128.226:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.128.226:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: openai-domain-verification=dv-0pTGTkARXsArFAKKZwc6Fzbl; stripe-verification=E9104449B2742089788253DB69E0E9C226D3F54E519514A3698526A4594B; miro-verification=6a8362f817d4ea530843a04d46c6418e011c951d
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of upwork.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 263 disallow path(s), e.g. /att/, /att-old/, /freelancers/public/api/, /messages/, /*/jobs/search*
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "upwork.com",
  "dns": {
    "a": [
      "104.18.128.226",
      "104.18.129.226"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "fay.ns.cloudflare.com.",
      "jim.ns.cloudflare.com."
    ],
    "spf": [
      "docusign=277af459-13d2-4b85-bb45-53efc4b671f6",
      "MS=6100C439A4691C31E2EC1342F09C3607B3B64DAC",
      "openai-domain-verification=dv-0pTGTkARXsArFAKKZwc6Fzbl",
      "stripe-verification=E9104449B2742089788253DB69E0E9C226D3F54E519514A3698526A4594B7D62",
      "miro-verification=6a8362f817d4ea530843a04d46c6418e011c951d",
      "adobe-idp-site-verification=45e831bcd7ad9667a0be62ad1db9971caa65d4c68af84b32f30ca18dd29d6bac",
      "Dynatrace-site-verification=10887f73-4311-4a4b-83e3-312614aeb532__h68in82ubsmc8a7c1j8g0e6v6d",
      "MS=ms47394909",
      "google-site-verification=MK7qfjAI4BOyhzOcaFe2WjFleaX2gKcUUu6VKf5X-qE",
      "logmein-domain-confirmation 2141230743",
      "zapier-domain-verification-challenge=0ab7c0ae-a354-49d6-9012-16a12e53b121",
      "google-site-verification=sD8rL1N3j5vS_miQGy_NwdmJHTmFUU42SDhYa4rdQ84",
      "google-site-verification=LSicnKkde4b1FmPqfr0FX6l7R4VvjAxTVzZP0sebXKk",
      "google-site-verification=-LgXVF8adhy30B1kiNabPgT-Pymy3WZOOvfGFgp6XGE",
      "google-site-verification=BkuVDFrIY09DX823uWROsYHLrLeCUKJ366m1k4AmoT4",
      "google-site-verification=PkziJTcGbOV4cv301PZ8KfBzni-MN_cB3J4ngmLA9Ps",
      "bugcrowd-verification=dae371187bf32cac11a23664ea291f6c",
      "linear-domain-verification=z536v5rd3xih",
      "google-site-verification=4p2pqAQ0yiDL2lc81zb89ZA-Wt6u9uBY25QEMjp-b4s",
      "docker-verification=ccc1198a-92ef-4bca-8e5c-896b7c508065",
      "_6lgpbootvod9h9mgfdn7efsdz52nzx0",
      "google-site-verification=f3f7WfTf8cecTKAI3cwfnA-cmQP1WlyDMfzuzG6BB-8",
      "chariot=chariot+upwork@praetorian.com",
      "hcp-domain-verification=b36955e77a08570a83deddbbdfa15fe1894a5c747597bc9941fc15f6f6bf22aa",
      "anthropic-domain-verification-a50qdm=eDDAJvU3hKqefx59gXmsODCgG",
      "google-site-verification=3jXROOXzwXZqaI-z95yNNpu9L8mSRW3Jd5VCpjVOxwk",
      "_gxokjwki7xqlmqjp3mp918p6j6w1peg",
      "facebook-domain-verification=8nwzxhaovba8tj7d2ldml1bhssa1pm",
      "jamf-site-verification=GjhSBwax0Pxacxf38XbNHw",
      "16359333",
      "google-site-verification=MFfOuTSDuMVfAuZmNHfYJA16r0P_BeZX5F60NQnSHNA",
      "paloaltonetworks-site-verification=e10a924e19c474e2b83aa85600a8d52fb39615b7834f93971c13687f13e8d326",
      "liveramp-site-verification=qn4k0EIcwgkwW6N80DcWp-G_gQeo9SCk4fdGh21URyw",
      "cursor-domain-verification-z00fy8=8sg38uSSHGnTzRvM2sEDPoIl3",
      "v=spf1 include:upwork.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.clinchtalent.com include:spf.mandrillapp.com include:sendgrid.net ~all",
      "asv=54832828144bb4ff89f152511204f3e2",
      "mongodb-site-verification=xc3WGhQz20Yw7Lm6yMoC6L4b5gf08icW",
      "asv=a52d93b02babfa60a71bdd4128a06b39",
      "sjlh98brgm4j879mz0km0f9kz0s61mf8",
      "google-site-verification=4g4BiPppYs75ob9yO422K5BqFPttTmPK_fmNtaopAI8",
      "google-site-verification=hJI07_9hhjkWQFySSiVg5v3vNIpZBMwOkA1Il7-tCMY",
      "mixpanel-domain-verify=2a906114-e222-4323-bbd7-0a671f9d90ee",
      "nlmdbpv52ts89j835vzt3c71d201hqk5",
      "google-site-verification=zTEmbU71ZrIPR7JRRlWSGiQurNYft76eEdSdP6aAQkQ",
      "_vmdb9wrav5ukmzhtyzh5cps8gs2zooy"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=upwork.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  8 04:52:43 2026 GMT",
    "notAfter": "Dec  7 05:52:39 2026 GMT",
    "san": [
      "upwork.com",
      "*.upwork.com",
      "*.email.upwork.com",
      "*.t.upwork.com"
    ],
    "days_left": 71,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.128.226",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
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
      "domain": "upwork.com",
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
      "origin": "https://sub.upwork.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://upwork.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 200,
    "/security.txt": 301,
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
    "openai-domain-verification=dv-0pTGTkARXsArFAKKZwc6Fzbl",
    "stripe-verification=E9104449B2742089788253DB69E0E9C226D3F54E519514A3698526A4594B",
    "miro-verification=6a8362f817d4ea530843a04d46c6418e011c951d",
    "adobe-idp-site-verification=45e831bcd7ad9667a0be62ad1db9971caa65d4c68af84b32f30c",
    "Dynatrace-site-verification=10887f73-4311-4a4b-83e3-312614aeb532__h68in82ubsmc8a"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
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
    "hsts_preloaded": true,
    "robots_disallow": [
      "/att/",
      "/att-old/",
      "/freelancers/public/api/",
      "/messages/",
      "/*/jobs/search*",
      "/search/profiles/*",
      "/catalog-images/*",
      "/ab/",
      "/hire/de/sem/",
      "/nx/",
      "/j/view_opening_popup.php",
      "/leaving_odesk.php",
      "/leaving-odesk",
      "/leaving",
      "/nx/top-nav-ssi/visitor-gql-token"
    ]
  },
  "elapsed_s": 7.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
