# Security Audit Report — upwork.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://upwork.com/ |
| Bug bounty program | Upwork |
| Listed scope domain | upwork.com |
| Test date | 2026-09-25 10:25 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **7** (High: 0, Medium: 0, Low: 1, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |

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
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "jim.ns.cloudflare.com.",
      "fay.ns.cloudflare.com."
    ],
    "spf": [
      "logmein-domain-confirmation 2141230743",
      "google-site-verification=LSicnKkde4b1FmPqfr0FX6l7R4VvjAxTVzZP0sebXKk",
      "jamf-site-verification=GjhSBwax0Pxacxf38XbNHw",
      "MS=ms47394909",
      "google-site-verification=f3f7WfTf8cecTKAI3cwfnA-cmQP1WlyDMfzuzG6BB-8",
      "adobe-idp-site-verification=45e831bcd7ad9667a0be62ad1db9971caa65d4c68af84b32f30ca18dd29d6bac",
      "google-site-verification=MFfOuTSDuMVfAuZmNHfYJA16r0P_BeZX5F60NQnSHNA",
      "MS=6100C439A4691C31E2EC1342F09C3607B3B64DAC",
      "asv=54832828144bb4ff89f152511204f3e2",
      "facebook-domain-verification=8nwzxhaovba8tj7d2ldml1bhssa1pm",
      "google-site-verification=hJI07_9hhjkWQFySSiVg5v3vNIpZBMwOkA1Il7-tCMY",
      "cursor-domain-verification-z00fy8=8sg38uSSHGnTzRvM2sEDPoIl3",
      "_vmdb9wrav5ukmzhtyzh5cps8gs2zooy",
      "_gxokjwki7xqlmqjp3mp918p6j6w1peg",
      "chariot=chariot+upwork@praetorian.com",
      "paloaltonetworks-site-verification=e10a924e19c474e2b83aa85600a8d52fb39615b7834f93971c13687f13e8d326",
      "google-site-verification=3jXROOXzwXZqaI-z95yNNpu9L8mSRW3Jd5VCpjVOxwk",
      "16359333",
      "docker-verification=ccc1198a-92ef-4bca-8e5c-896b7c508065",
      "zapier-domain-verification-challenge=0ab7c0ae-a354-49d6-9012-16a12e53b121",
      "google-site-verification=-LgXVF8adhy30B1kiNabPgT-Pymy3WZOOvfGFgp6XGE",
      "google-site-verification=BkuVDFrIY09DX823uWROsYHLrLeCUKJ366m1k4AmoT4",
      "google-site-verification=sD8rL1N3j5vS_miQGy_NwdmJHTmFUU42SDhYa4rdQ84",
      "hcp-domain-verification=b36955e77a08570a83deddbbdfa15fe1894a5c747597bc9941fc15f6f6bf22aa",
      "google-site-verification=MK7qfjAI4BOyhzOcaFe2WjFleaX2gKcUUu6VKf5X-qE",
      "mongodb-site-verification=xc3WGhQz20Yw7Lm6yMoC6L4b5gf08icW",
      "asv=a52d93b02babfa60a71bdd4128a06b39",
      "mixpanel-domain-verify=2a906114-e222-4323-bbd7-0a671f9d90ee",
      "docusign=277af459-13d2-4b85-bb45-53efc4b671f6",
      "miro-verification=6a8362f817d4ea530843a04d46c6418e011c951d",
      "liveramp-site-verification=qn4k0EIcwgkwW6N80DcWp-G_gQeo9SCk4fdGh21URyw",
      "v=spf1 include:upwork.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mail.clinchtalent.com include:spf.mandrillapp.com include:sendgrid.net ~all",
      "google-site-verification=PkziJTcGbOV4cv301PZ8KfBzni-MN_cB3J4ngmLA9Ps",
      "_6lgpbootvod9h9mgfdn7efsdz52nzx0",
      "bugcrowd-verification=dae371187bf32cac11a23664ea291f6c",
      "google-site-verification=4g4BiPppYs75ob9yO422K5BqFPttTmPK_fmNtaopAI8",
      "nlmdbpv52ts89j835vzt3c71d201hqk5",
      "google-site-verification=zTEmbU71ZrIPR7JRRlWSGiQurNYft76eEdSdP6aAQkQ",
      "linear-domain-verification=z536v5rd3xih",
      "openai-domain-verification=dv-0pTGTkARXsArFAKKZwc6Fzbl",
      "google-site-verification=4p2pqAQ0yiDL2lc81zb89ZA-Wt6u9uBY25QEMjp-b4s",
      "sjlh98brgm4j879mz0km0f9kz0s61mf8",
      "anthropic-domain-verification-a50qdm=eDDAJvU3hKqefx59gXmsODCgG",
      "stripe-verification=E9104449B2742089788253DB69E0E9C226D3F54E519514A3698526A4594B7D62",
      "Dynatrace-site-verification=10887f73-4311-4a4b-83e3-312614aeb532__h68in82ubsmc8a7c1j8g0e6v6d"
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
    "days_left": 72,
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
    "location": "https://www.upwork.com"
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
    "status": "crt.sh ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='crt.sh', port=443): Read (certspotter 429)"
  },
  "elapsed_s": 22.5,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
