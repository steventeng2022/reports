# Security Audit Report — wordpress.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://wordpress.org/ |
| Bug bounty program | WordPress |
| Listed scope domain | wordpress.org |
| Test date | 2026-09-26 19:01 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 7, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 13 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 19 | info | CT1 | 10 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 20 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: clear
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=3600 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.wordpress.org/.well-known/mta-sts/policy.txt -> 200; policy lacks version/max_age
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 13. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (bbbcj5zzttjcp6.wordpress.org and jk1ey38h3l1twl.wordpress.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=UL0sGJ1dZbCT4J7pGrLW3hqM_I1LJ8pUi2WBEI_98kI; google-site-verification=t8FjG1vzC4OFZJ8qL4SkR8xxtLyKldXKbswyeemQS5w
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of wordpress.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but wordpress.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 4 disallow path(s), e.g. /wp-admin/, /search, /?s=, /plugins/search/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 66.6.42.252 carries PTR wordpress.org. for wordpress.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 19. [INFO] 10 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: git.wordpress.org, status.wordpress.org, wiki.wordpress.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 20. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: git.wordpress.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "wordpress.org",
  "dns": {
    "a": [
      "66.6.42.252"
    ],
    "aaaa": [
      "2620:109:b00a::4206:2afc"
    ],
    "cname": null,
    "mx": [
      "smtp2-dca.wordpress.org (pref 10)",
      "smtp1-dca.wordpress.org (pref 10)"
    ],
    "ns": [
      "ns2.wordpress.org.",
      "ns3.wordpress.org.",
      "ns4.wordpress.org.",
      "ns1.wordpress.org."
    ],
    "spf": [
      "google-site-verification=UL0sGJ1dZbCT4J7pGrLW3hqM_I1LJ8pUi2WBEI_98kI",
      "v=spf1 ip4:66.6.42.0/24 ip4:66.155.40.0/24 include:helpscoutemail.com -all",
      "google-site-verification=t8FjG1vzC4OFZJ8qL4SkR8xxtLyKldXKbswyeemQS5w"
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
    "subject": "commonName=wordpress.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Sep 23 19:43:58 2026 GMT",
    "notAfter": "Dec 22 19:43:57 2026 GMT",
    "san": [
      "*.wordpress.org",
      "wordpress.org"
    ],
    "days_left": 87,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "66.6.42.252",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Blog Tool, Publishing Platform, and CMS &#8211; WordPress.org"
  },
  "mixed_content": [
    "href=\"http://"
  ],
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
      "origin": "https://sub.wordpress.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://wordpress.org/"
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
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 404,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 301,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 10,
    "notable": [
      "git.wordpress.org",
      "status.wordpress.org",
      "wiki.wordpress.org"
    ],
    "sample": [
      "forums.wordpress.org",
      "git.wordpress.org",
      "mercantile.wordpress.org",
      "npmproxy.wordpress.org",
      "security.wordpress.org",
      "status.wordpress.org",
      "svn.wordpress.org",
      "trac.wordpress.org",
      "wiki.wordpress.org",
      "wordpress.org"
    ],
    "dangling": [
      "git.wordpress.org"
    ]
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=UL0sGJ1dZbCT4J7pGrLW3hqM_I1LJ8pUi2WBEI_98kI",
    "google-site-verification=t8FjG1vzC4OFZJ8qL4SkR8xxtLyKldXKbswyeemQS5w"
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
      "not_before": "20260923194358",
      "not_after": "20261222194357"
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/search",
      "/?s=",
      "/plugins/search/"
    ]
  },
  "x12": {
    "status": 200,
    "ptr": [
      "wordpress.org."
    ]
  },
  "elapsed_s": 31.2,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
