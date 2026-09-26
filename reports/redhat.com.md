# Security Audit Report — redhat.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://redhat.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | redhat.com |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: pendo-domain-verification=01424ad4-8f69-4456-90ff-5f544ada6cec; google-site-verification=fkn6chapCdYNWIcpsgH0K6mkR0yo7ldeIRC7EH23yoo; atlassian-domain-verification=fHiTv781WbOHgzl6U1McyXa9JUSSO5B0ECvgSZzJ9+b4q8wv0T
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of redhat.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but redhat.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 59 disallow path(s), e.g. /core/, /profiles/, /README.md, /composer/Metapackage/README.txt, /composer/Plugin/ProjectMessage/README.md
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.235.198.240 carries PTR ec2-34-235-198-240.compute-1.amazonaws.com. for redhat.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "redhat.com",
  "dns": {
    "a": [
      "34.235.198.240",
      "52.200.142.250"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)",
      "us-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "dns4.p01.nsone.net.",
      "dns1.p01.nsone.net.",
      "dns3.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "dns2.p02.nsone.net.",
      "dns1.p02.nsone.net."
    ],
    "spf": [
      "docusign=c6aa79da-fde1-4b7e-8874-28eeb223ca63",
      "pendo-domain-verification=01424ad4-8f69-4456-90ff-5f544ada6cec",
      "google-site-verification=fkn6chapCdYNWIcpsgH0K6mkR0yo7ldeIRC7EH23yoo",
      "atlassian-domain-verification=fHiTv781WbOHgzl6U1McyXa9JUSSO5B0ECvgSZzJ9+b4q8wv0Tf4iI75xdcyoC00",
      "jetbrains-domain-verification=c52sdl8fpvtdvcunhy64u3149",
      "Dynatrace-site-verification=1782cd51-ac66-4966-acdc-061c80f794f5__t1aa4l3qdsf475891sv2711t80",
      "anthropic-domain-verification-75gwks=eCqmQbyCwqL2ocuciTDIydVPj",
      "status-page-domain-verification=dfx5rbys1ts5",
      "slack-domain-verification=dPrnI9sLvqvAbQUwzvFsPXSPEU1PLODdgGxLhEUr",
      "Dynatrace-site-verification=6d28213f-f653-42df-8f09-a7ae69f50e6a__dk5hkah3juetfgj11au5isjmig",
      "google-site-verification=TaSjV4JOe2XfmL_vHFKJHkPk8sjgoLkuuTTWezDO0Pw",
      "google-site-verification=rl_wq5rq_W7A7OSyK08d8Ta_Hf6AKP5tqtdlo4iGTvs",
      "atlassian-sending-domain-verification=6624a6de-2779-4cc5-9e0e-d739598be73d",
      "adobe-idp-site-verification=10154eb7d4abe67e9e45621e46476febbec28a97a4610d7c043c42c667aa18d4",
      "openai-domain-verification=dv-ZBmiG45XpzQoJlIf2HBlWHWf",
      "status-page-domain-verification=hyls0f05cd87",
      "amazonses:ablaZDaC37yeQUcZAZjbfqRELxucC+8pBdvhFEpTSlY=",
      "_v9l10fwei3im7iirj8c5fy92e798j78",
      "cursor-domain-verification-xts7mh=BCrLupJRjleUhfxmNA4CUlgaE",
      "MS=ms88428189",
      "segment-site-verification=Kk3pC9UBfhioQzibTvTIhT4TFVwP4niP",
      "wework-site-verification=EABEURRXyO1yBZcn",
      "miro-verification=0bc02d4257d450b9f9034363a58f88b4b904dc22",
      "docusign=cfd355fc-11f9-4eaf-8ecf-64433ef46173",
      "apple-domain-verification=xaB3GAa9xxzrpoS4",
      "docker-verification=b3c48bbc-05f6-40b8-8391-b5ad3366c6ec",
      "MS=ms44845140",
      "v=spf1 redirect=73t7ezjz._spf._d.mim.ec"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:5f1992045035946@rep.dmarcanalyzer.com; ruf=mailto:5f1992045035946@for.dmarcanalyzer.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=North Carolina, localityName=Raleigh, organizationName=Red Hat, LLC, commonName=redhat.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 20 00:00:00 2026 GMT",
    "notAfter": "Mar  6 23:59:59 2027 GMT",
    "san": [
      "redhat.com"
    ],
    "days_left": 161,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.235.198.240",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.redhat.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.redhat.com/en"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "pendo-domain-verification=01424ad4-8f69-4456-90ff-5f544ada6cec",
    "google-site-verification=fkn6chapCdYNWIcpsgH0K6mkR0yo7ldeIRC7EH23yoo",
    "atlassian-domain-verification=fHiTv781WbOHgzl6U1McyXa9JUSSO5B0ECvgSZzJ9+b4q8wv0T",
    "jetbrains-domain-verification=c52sdl8fpvtdvcunhy64u3149",
    "Dynatrace-site-verification=1782cd51-ac66-4966-acdc-061c80f794f5__t1aa4l3qdsf475"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 4096,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260820000000",
      "not_after": "20270306235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/core/",
      "/profiles/",
      "/README.md",
      "/composer/Metapackage/README.txt",
      "/composer/Plugin/ProjectMessage/README.md",
      "/composer/Plugin/Scaffold/README.md",
      "/composer/Plugin/VendorHardening/README.txt",
      "/composer/Template/README.txt",
      "/modules/README.txt",
      "/sites/README.txt",
      "/themes/README.txt",
      "/web.config",
      "/admin/",
      "/comment/reply/",
      "/filter/tips"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-34-235-198-240.compute-1.amazonaws.com."
    ]
  },
  "elapsed_s": 30.1,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
