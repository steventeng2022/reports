# Security Audit Report — uspto.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://uspto.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | uspto.gov |
| Test date | 2026-09-26 16:43 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 5, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | info | CT1 | 2383 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 15 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.35.192:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.35.192:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [INFO] 2383 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.etc.uspto.gov, antivirus.gd.aws.uspto.gov, api.dev.efile.awslab.uspto.gov, api.dev.tm-efile.awslab.uspto.gov, api.stable.efile.awslab.uspto.gov, api.stable.tm-efile.awslab.uspto.gov, api.uspto.gov, assets.uspto.gov, auth.uspto.gov, bdr-q318-pui-httpd-0.dev.uspto.gov
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 15. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: admin.etc.uspto.gov, antivirus.gd.aws.uspto.gov, api.dev.efile.awslab.uspto.gov, api.dev.tm-efile.awslab.uspto.gov, api.stable.efile.awslab.uspto.gov; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "uspto.gov",
  "dns": {
    "a": [
      "104.18.35.192",
      "172.64.152.64"
    ],
    "aaaa": [
      "2a06:98c1:310c::ac40:9840",
      "2a06:98c1:3101::6812:23c0"
    ],
    "cname": null,
    "mx": [
      "uspto-gov.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "gold.foundationdns.net.",
      "gold.foundationdns.org.",
      "gold.foundationdns.com."
    ],
    "spf": [
      "3FKeZ5CH9TEaLgiiioa9/iDVB0WPJofaHBuumk1YRmcuggWFX3v3gDlSw5uSIbaSuvm/FsOYPRzhM87BHQ+ImA==",
      "_qf2w9oo2ieh425rh0b6gjpp829vih2b",
      "SnTiaz2QHOuDsjncHy2wc6dZmnzEFxbqKLWgzzrfBidPblmIGRxS9jP28Zb4xPjhhlE2YBm98Mu+DhbxxGOa7A==",
      "google-site-verification=5eOb2YylR8fDTIkmIs3N0CaJ_IHjjikNS-Z7BDb9jvw",
      "google-site-verification=MB6vnwbxkyN6STcgBAa5U-W1H7VhU62fSuT95KrWhlk",
      "jetbrains-domain-verification=8sj6e0d8s6q4fvu86jcfzp0g5",
      "apple-domain-verification=DQ6lsHErU2gvVyqF",
      "webexdomainverification.7PUPU=2a587b5a-c181-4a6c-9d10-a13dcaa747bd",
      "MS=ms28666523",
      "perplexity-ai-domain-verification-7tdkgd=M7VyHULqPpVV3g4SsM4BNc1mR",
      "adobe-idp-site-verification=fd06710ade06e49a5be3b877d16463b3f5f050a1e54eaaa1daff14f8da83993f",
      "facebook-domain-verification=6wqv4rmxkothypv5gij5080967l5ws",
      "_ib4pu1ottna05el605hns0p62bwkg2g",
      "v=spf1 include:uspto.gov._nspf.valigov.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.valigov.email include:spf.protection.outlook.com -all",
      "ms-domain-verification=725c3c35-24ef-43fd-a26b-2736d7cea1a6"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@valigov.email,mailto:dmarc_reports@uspto.gov,mailto:reports@dmarc.cyber.dhs.gov"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=uspto.gov",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 24 01:54:42 2026 GMT",
    "notAfter": "Nov 22 02:54:40 2026 GMT",
    "san": [
      "uspto.gov"
    ],
    "days_left": 56,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.35.192",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.uspto.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.uspto.gov/"
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
    "source": "crt.sh",
    "count": 2383,
    "notable": [
      "admin.etc.uspto.gov",
      "antivirus.gd.aws.uspto.gov",
      "api.dev.efile.awslab.uspto.gov",
      "api.dev.tm-efile.awslab.uspto.gov",
      "api.stable.efile.awslab.uspto.gov",
      "api.stable.tm-efile.awslab.uspto.gov",
      "api.uspto.gov",
      "assets.uspto.gov",
      "auth.uspto.gov",
      "bdr-q318-pui-httpd-0.dev.uspto.gov",
      "bdr-q318-pui-httpd-2.dev.uspto.gov",
      "bdr-q318-tmui-httpd-0.dev.uspto.gov",
      "bdr-q318-tmui-httpd-1.dev.uspto.gov",
      "bdr-q418-ptui-httpd-0.dev.uspto.gov",
      "careers.uspto.gov"
    ],
    "sample": [
      "10millionpatents-aws.etc.uspto.gov",
      "10millionpatents-aws.uspto.gov",
      "10millionpatents-www-sit-web.etc.uspto.gov",
      "10millionpatents-www-trn-web.uspto.gov",
      "10millionpatents.etc.uspto.gov",
      "10millionpatents.uspto.gov",
      "access-dmz.etc.uspto.gov",
      "access.etc.uspto.gov",
      "access.uspto.gov",
      "account-dev.etc.uspto.gov",
      "account-dmz-alx1-passive.uspto.gov",
      "account-dmz-alx1.uspto.gov",
      "account-fqt.etc.uspto.gov",
      "account-passive.uspto.gov",
      "account-pvt-dmz-alx1.etc.uspto.gov",
      "account-pvt-passive.etc.uspto.gov",
      "account-pvt-proto.etc.uspto.gov",
      "account-pvt.etc.uspto.gov",
      "account-rbac-fqt.etc.uspto.gov",
      "account-rbac-passive.uspto.gov"
    ],
    "dangling": [
      "admin.etc.uspto.gov",
      "antivirus.gd.aws.uspto.gov",
      "api.dev.efile.awslab.uspto.gov",
      "api.dev.tm-efile.awslab.uspto.gov",
      "api.stable.efile.awslab.uspto.gov"
    ]
  },
  "elapsed_s": 27.0,
  "rechecked": "2026-09-26 16:42 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
