# Security Audit Report — zdnet.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://zdnet.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | zdnet.com |
| Test date | 2026-09-26 17:56 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 5, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: figma-domain-verification=4f7cdfa45ca39f617dd7ba7b165e1bfd5e9b5e1ec18b849c6098df; tollbit-domain-verification=ed765eec87445a9c7fc97d88202a4e247d115ec1dcce8b285564; canva-site-verification=Dq2WPizCkBmFzG8pX1jdkQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of zdnet.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 17 disallow path(s), e.g. /user/*, /members/, /members/newsletters/, /members/alerts/add/, /search/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "zdnet.com",
  "dns": {
    "a": [
      "192.0.66.145"
    ],
    "aaaa": [
      "2a04:fa87:fffd::c000:4291"
    ],
    "cname": null,
    "mx": [
      "smtp.google.com (pref 1)"
    ],
    "ns": [
      "aria.ns.cloudflare.com.",
      "owen.ns.cloudflare.com."
    ],
    "spf": [
      "gpu99tm7bpjr5ffe6j6lff9c6g",
      "figma-domain-verification=4f7cdfa45ca39f617dd7ba7b165e1bfd5e9b5e1ec18b849c6098dfdc4a4cfa64-1740511309",
      "amazonses:kWgTT8gEghPg1NxciZwhrB3xu+jSMwW8T80qgRg5Kyw=",
      "tollbit-domain-verification=ed765eec87445a9c7fc97d88202a4e247d115ec1dcce8b2855644de232baa795",
      "canva-site-verification=Dq2WPizCkBmFzG8pX1jdkQ",
      "v=spf1 mx ip4:64.30.227.218 ip4:64.30.226.54/31 ip4:74.125.148.0/22 ip4:216.239.125.28/23 ip4:202.73.54.176/28 ip4:58.65.7.128/28 ip4:62.108.138.0/28 ip4:216.239.114.214/23 ip4:216.239.114.222/23 include:_spf.google.com include:spf-00262c01.pphosted.com i",
      "nclude:spf.protection.outlook.com -all",
      "anthropic-domain-verification-4sn0p2=1S8SKrvmazJTSpSOW0ZEUoQHj",
      "google-site-verification=0MpBgJlty0QJTSbL0NsxKSMQao7AtbMttqQqLBpnuqo",
      "facebook-domain-verification=qxzu4bw9l67g1b59xbja9fqgyetsfq",
      "google-site-verification=OEcQCk6m6XyHagDu-7BnHevLzPmjK8VLrehu0rHHPGs",
      "google-site-verification=VvA5ip4lC7mt45ap9Ra_PNfXXe3OgEsWiV3ZySfTRKI",
      "amazonses:tf7PxlKrP5loKZqpIoiHCfuwRc9LWPN35B8KBlvXYvU=",
      "MS=ms65532728",
      "workplace-domain-verification=q8l8dtiG9ONhEmL8nIvj0Z5L2D5A3i",
      "google-site-verification=pYonWwLh0y5UIPReObylCHtCWHGz9YmWq9OI0NnlEOk",
      "adobe-idp-site-verification=b6e27597198dfc9921fbe2ad78e9a76012bb17d0ddb65389e600ecb80de9a555",
      "qb5l10tv3ifansmtg2j67ls4vm",
      "knowbe4-site-verification=f250b2a70f1bef3a0d3e9e990a25ada0",
      "atlassian-domain-verification=QUsZX4LdPWTYZgx09JhShFot27EJnUl/5CyxXFsiGebXl2QD8Fh3zzfkYZJe42Ic"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;rua=mailto:088836b424@rua.easydmarc.us;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=www.zdnet.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep  1 08:19:37 2026 GMT",
    "notAfter": "Nov 30 08:19:36 2026 GMT",
    "san": [
      "www.zdnet.com",
      "zdnet.com"
    ],
    "days_left": 64,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.145",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.zdnet.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://zdnet.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "figma-domain-verification=4f7cdfa45ca39f617dd7ba7b165e1bfd5e9b5e1ec18b849c6098df",
    "tollbit-domain-verification=ed765eec87445a9c7fc97d88202a4e247d115ec1dcce8b285564",
    "canva-site-verification=Dq2WPizCkBmFzG8pX1jdkQ",
    "anthropic-domain-verification-4sn0p2=1S8SKrvmazJTSpSOW0ZEUoQHj",
    "google-site-verification=0MpBgJlty0QJTSbL0NsxKSMQao7AtbMttqQqLBpnuqo"
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
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/user/*",
      "/members/",
      "/members/newsletters/",
      "/members/alerts/add/",
      "/search/",
      "*Xhr*",
      "*/xhr*",
      "*/ajax/*",
      "*/fly/*/bundles/flyjs/*",
      "*/libs/*",
      "*/version!libs/*",
      "/.well-known/*",
      "/index.php/*",
      "*?beta=*",
      "*?ftag=*"
    ]
  },
  "elapsed_s": 17.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
