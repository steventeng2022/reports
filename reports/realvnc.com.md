# Security Audit Report — realvnc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://realvnc.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | realvnc.com |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | CT1 | 36 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 13 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.135.42:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 162.159.135.42:8443 succeeded (state-only check, no payload sent).
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

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.realvnc.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=sinri451xxlUIP8XWzq2cnLcose6D3rZtQoTjN22urg; google-site-verification=1I3HJkpW6bKhSSPJBqQL0R8R2agif2aAwy-QsQl9Xe0; figma-domain-verification=4e46cf4c9d9aaec25262e168b0999452d5500da424414abfb1798c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of realvnc.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] 36 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api.realvnc.com, dev.realvnc.com, docs.realvnc.com, help.realvnc.com, static.realvnc.com, status.realvnc.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 13. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: dev.realvnc.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "realvnc.com",
  "dns": {
    "a": [
      "162.159.135.42"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "realvnc-com.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns-107.awsdns-13.com.",
      "ns-1126.awsdns-12.org.",
      "ns-697.awsdns-23.net.",
      "ns-1853.awsdns-39.co.uk."
    ],
    "spf": [
      "google-site-verification=sinri451xxlUIP8XWzq2cnLcose6D3rZtQoTjN22urg",
      "google-site-verification=1I3HJkpW6bKhSSPJBqQL0R8R2agif2aAwy-QsQl9Xe0",
      "figma-domain-verification=4e46cf4c9d9aaec25262e168b0999452d5500da424414abfb1798c4fe9233e61-1771502323",
      "access-domain-verification=c9c536439a4535e8d8dffbcb8abdeaa71e9e799dcd926e0ee962c98bc1061033",
      "anthropic-domain-verification-wk26mc=QzCmNWzkRB3fh4mHpDBWe2FdT",
      "asv=309ccc5adc09d2464ac2665e9974075c",
      "pmpI7p6",
      "atlassian-domain-verification=rslHtzOI5sqZJkCLg1ZQjp0qtLMeJMmphVrMsb925dxb2QQVv7atnG23AoAnAUSx",
      "v=spf1 include:spf1.realvnc.com mx a ip4:85.118.25.224/28 ip4:64.253.40.208/28 ip4:146.101.15.112/28 ip4:146.101.60.64/29 ip4:146.101.60.80/29 ip4:146.101.16.120/29 ip4:93.89.140.48/28 include:mail.zendesk.com -all",
      "apple-domain-verification=C1oCsNHCV8WFlmUQ",
      "Z9jkaFYlj+FbMMAK6DLQAWsT6FnAfMtRTL6T+BUM/mplV6PYR7mVhRL2nOm1DsZK2b2gv9PMa5XUVjwtcc5q9A==",
      "google-site-verification=8R_EB8SYuQWmxdEKJXObSq5BMXuZM2WXwT1uNZGMeOA",
      "openai-domain-verification=dv-WWEnkwoxDzw6l2qb8mJXwuYh",
      "bw=tsczM6ieOZ17wC3dKOHNMGYejzemjsd8DGyziHuAFUdK",
      "google-site-verification=VqytxEFfE2GGlJ_wNobagFkF_nWWGAaBalXVwGBq4Yg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; ruf=mailto:dmarcfail@realvnc.com; rua=mailto:dmarcrep@realvnc.com; adkim=r; aspf=r; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=realvnc.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 21 07:02:45 2026 GMT",
    "notAfter": "Dec 20 08:02:40 2026 GMT",
    "san": [
      "realvnc.com"
    ],
    "days_left": 84,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.159.135.42",
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
      "domain": "realvnc.com",
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
      "origin": "https://sub.realvnc.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://realvnc.com/"
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
    "source": "certspotter",
    "count": 36,
    "notable": [
      "api.realvnc.com",
      "dev.realvnc.com",
      "docs.realvnc.com",
      "help.realvnc.com",
      "static.realvnc.com",
      "status.realvnc.com"
    ],
    "sample": [
      "analytics.realvnc.com",
      "api.realvnc.com",
      "connecttv.realvnc.com",
      "corporate-maintpage.realvnc.com",
      "cport-m-gb-bdg-1.realvnc.com",
      "cport-m-us-va-1.realvnc.com",
      "dev-www.realvnc.com",
      "dev.realvnc.com",
      "developer-maintpage.realvnc.com",
      "developer.realvnc.com",
      "discover.realvnc.com",
      "docs.realvnc.com",
      "downloads.realvnc.com",
      "gsnlink.realvnc.com",
      "help.realvnc.com",
      "manage.realvnc.com",
      "mta-sts.realvnc.com",
      "partner.realvnc.com",
      "realvnc.com",
      "s-analytics.realvnc.com"
    ],
    "dangling": [
      "dev.realvnc.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=sinri451xxlUIP8XWzq2cnLcose6D3rZtQoTjN22urg",
    "google-site-verification=1I3HJkpW6bKhSSPJBqQL0R8R2agif2aAwy-QsQl9Xe0",
    "figma-domain-verification=4e46cf4c9d9aaec25262e168b0999452d5500da424414abfb1798c",
    "access-domain-verification=c9c536439a4535e8d8dffbcb8abdeaa71e9e799dcd926e0ee962c",
    "anthropic-domain-verification-wk26mc=QzCmNWzkRB3fh4mHpDBWe2FdT"
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
      "aia_ocsp": null,
      "not_before": "20260921070245",
      "not_after": "20261220080240"
    }
  },
  "x12": {
    "status": 403
  },
  "elapsed_s": 6.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
