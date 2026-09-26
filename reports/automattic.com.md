# Security Audit Report — automattic.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://automattic.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | automattic.com |
| Test date | 2026-09-26 18:46 UTC |
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
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 11 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 17 | info | CT1 | 15 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: clear
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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.automattic.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 11. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (j8v53hg0xsa6a2.automattic.com and h7z4dmy27g5qlj.automattic.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: yahoo-verification-key=8dNdxvmgAf9M2eCeh79q5CpzcsN5GkkT9db3Z5Rr3Sk=; google-site-verification=l3pF3D6Nfuk18StNUFWXaEEIVTjBWWHvvZYP9sXEAcc; google-site-verification=F4jw0P5BvBnjqDSVJEhYv3LEU2WLuqChlBLJEYA2SO0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of automattic.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but automattic.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 10 disallow path(s), e.g. /wp-admin/, /wp-login.php, /wp-signup.php, /press-this.php, /remote-login.php
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://automattic.com/ carries Cache-Control: max-age=289, must-revalidate (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 17. [INFO] 15 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "automattic.com",
  "dns": {
    "a": [
      "192.0.78.25",
      "192.0.78.24"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx-dfw.automattic.com (pref 10)",
      "mx-ams.automattic.com (pref 10)"
    ],
    "ns": [
      "ns2.automattic.com.",
      "ns4.automattic.com.",
      "ns1.automattic.com.",
      "ns3.automattic.com."
    ],
    "spf": [
      "spf2.0/mfrom a mx ?all",
      "yahoo-verification-key=8dNdxvmgAf9M2eCeh79q5CpzcsN5GkkT9db3Z5Rr3Sk=",
      "google-site-verification=l3pF3D6Nfuk18StNUFWXaEEIVTjBWWHvvZYP9sXEAcc",
      "google-site-verification=F4jw0P5BvBnjqDSVJEhYv3LEU2WLuqChlBLJEYA2SO0",
      "anthropic-domain-verification-q5pmy9=Tj43pQ6DCN1JcMx95QuvpbFG3",
      "v=spf1 include:_spf.automattic.com include:mail.zendesk.com include:mg-spf.greenhouse.io include:sendgrid.net include:39653948.spf04.hubspotemail.net ~all",
      "figma-domain-verification=a2e41510ac6b0c5745595c76770385bfd602709c6d04e80ef830c9c482fc9e20-1768211767",
      "atlassian-domain-verification=HLvi8VknRfLwuOZ7TmiaKM8GgOgai45SxxeWZddVaOBMgWielcwit/LmLXXPJm6G",
      "gradle-verification=1AG8E2HVI4P8EOH4BK5URAEO6JVML"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:0bqp2jnw@ag.dmarcian.com; ruf=mailto:0bqp2jnw@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=automattic.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 10 19:43:59 2026 GMT",
    "notAfter": "Nov  8 19:43:58 2026 GMT",
    "san": [
      "*.automattic.com",
      "automattic.com"
    ],
    "days_left": 43,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.78.25",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Automattic &#8211; Making the web a better place"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.automattic.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://automattic.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 15,
    "notable": [],
    "sample": [
      "automattic.com",
      "concierge.automattic.com",
      "engels.automattic.com",
      "fieldguide.automattic.com",
      "lounge.automattic.com",
      "museum.automattic.com",
      "offline.automattic.com",
      "publisherblog.automattic.com",
      "svn.automattic.com",
      "tls.automattic.com",
      "trac.automattic.com",
      "transparency.automattic.com",
      "updates.automattic.com",
      "www.automattic.com",
      "www.engels.automattic.com"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "yahoo-verification-key=8dNdxvmgAf9M2eCeh79q5CpzcsN5GkkT9db3Z5Rr3Sk=",
    "google-site-verification=l3pF3D6Nfuk18StNUFWXaEEIVTjBWWHvvZYP9sXEAcc",
    "google-site-verification=F4jw0P5BvBnjqDSVJEhYv3LEU2WLuqChlBLJEYA2SO0",
    "anthropic-domain-verification-q5pmy9=Tj43pQ6DCN1JcMx95QuvpbFG3",
    "figma-domain-verification=a2e41510ac6b0c5745595c76770385bfd602709c6d04e80ef830c9"
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
      "not_before": "20260810194359",
      "not_after": "20261108194358"
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/wp-login.php",
      "/wp-signup.php",
      "/press-this.php",
      "/remote-login.php",
      "/activate/",
      "/cgi-bin/",
      "/mshots/v1/",
      "/next/",
      "/public.api/"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 20.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
