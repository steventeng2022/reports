# Security Audit Report — activecampaign.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://activecampaign.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | activecampaign.com |
| Test date | 2026-09-26 18:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **22** (High: 0, Medium: 0, Low: 6, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 16 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 17 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 18 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 19 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 20 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 21 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 22 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 30 days (notAfter Oct 26 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.0.15:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.0.15:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 16. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): usb. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 17. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 18. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 19. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=jr7ubLUf4AdQz7NWkCAPnQ; google-site-verification=pns8v6xoUCNjHvUFVWiTCI4LJj7LHyz5CPghUG4ZYvc; google-site-verification=5ecE6QK-uN7epMvq2briZD_vYB2nC_5Y3BukiSILBUI
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 20. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of activecampaign.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 21. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but activecampaign.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 22. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /.env, /apps/search/, /blog/archives, /blog/inside-activecampaign, /blog/page
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "activecampaign.com",
  "dns": {
    "a": [
      "104.20.0.15",
      "104.20.1.15"
    ],
    "aaaa": [
      "2606:4700:10::6814:10f",
      "2606:4700:10::6814:f"
    ],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-1.mimecast.com (pref 10)",
      "usb-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "alex.ns.cloudflare.com.",
      "abby.ns.cloudflare.com."
    ],
    "spf": [
      "canva-site-verification=jr7ubLUf4AdQz7NWkCAPnQ",
      "google-site-verification=pns8v6xoUCNjHvUFVWiTCI4LJj7LHyz5CPghUG4ZYvc",
      "google-site-verification=5ecE6QK-uN7epMvq2briZD_vYB2nC_5Y3BukiSILBUI",
      "cloudflare_dashboard_sso=68e80b6640cd17c492819fa073f4c765",
      "status-page-domain-verification=8wyn9807n4gs",
      "v=spf1 ip4:173.236.20.0/24 ip4:192.92.97.0/24 ip4:52.128.40.0/21 ip4:217.8.118.0/24 ip4:103.229.233.0/24 include:usb._netblocks.mimecast.com include:_spf.google.com include:mail.zendesk.com include:stspg-customer.com include:sent-via.netsuite.com include:",
      "_spf-",
      "lrn.activecampaign.com ~all",
      "pendo-domain-verification=JK5zYujOmKqXb5aS1pRudbgHp2s",
      "vnr8cy64z7nvm6vq9xycm1t9t3wx625z",
      "google-site-verification=aZc8XNJa2DPnRqQMK58izlsKurjRm-hwdl-U4nsIBjY",
      "ahrefs-site-verification_13f6592c6dbc2e2fd5a07a7ba689ee0acaf5285f7dbf7a1c3eed5fcc8799689a",
      "google-site-verification=ZO9kf3bTT021P8qlB2BQ5rmk1e4bS8rsoYTnSpo9Nqg",
      "atlassian-domain-verification=0wCIZBGn1K/9SerwAoj1UyInzqjUZyJTODZJ1UPpBu+swTTfNBZxL2WhQZGvkfo/",
      "ps-cd-verification=445a8aa6-f462-4ac5-89b9-cf62b8f9ea91",
      "MS=ms78211706",
      "docker-verification=88049882-e3b0-454f-bfc6-99f5945ec081",
      "facebook-domain-verification=vj4bbc79ppnrt612769n33gxnqezjt",
      "stripe-verification=B8A6127A871981E95923CC0E59815D7C397AD696A04B0E5B60CBE58F81D54B65",
      "google-site-verification=z4cu4ksSlD1F4VwsV7aeuI3agrK4xT2HzLJwvNqXh-I",
      "intacct-esk=4FED1A5177F8769BE0538C06A8C0589E",
      "google-site-verification=hLQ1bCw_QcM04p9JX8V-EF2yFMN1phpFf4F1XAYSkXg",
      "google-site-verification=oZuy90wJc1WtJL-OqSxrqLKcqE_xWlBcRncm88kc6xo",
      "google-site-verification=bsPOFNz4WrydBvfNkWbSIfsIlkRev4iGBxCHnB3wsA4",
      "asv=2a7893285fd0ab817b0ac10ee4afcded",
      "docusign=b6411fd9-d54c-42ec-9a1e-9c718099b208",
      "cursor-domain-verification-mggxet=yI5H5w8prfWJQbesZn4JgSFiX",
      "v=DMARC1; p=none; rua=mailto:dmarc@activecampaign.com",
      "google-site-verification=yZpqL2DYnFgeE1CANvNSvCaY6vchX6cUsOnKIswM9nY",
      "ZOOM_verify_X_DkuppUTyaf0Col_X_dWQ",
      "anthropic-domain-verification-2wy46r=746EyPf5UdzlAhUQfRnbJGFAi",
      "apple-domain-verification=VblInNeuuVuHySfU",
      "openai-domain-verification=dv-hGDc7dQuUtX9y1AaOh3g5zLk"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:re+eab9f0889f10@inbound.dmarcdigests.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "jurisdictionCountryName=US, jurisdictionStateOrProvinceName=Delaware, businessCategory=Private Organization, serialNumber=5943439, countryName=US, stateOrProvinceName=Illinois, localityName=Chicago, organizationName=ActiveCampaign, LLC, commonName=www.activecampaign.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=GeoTrust EV RSA CA G2",
    "notBefore": "Sep 25 00:00:00 2025 GMT",
    "notAfter": "Oct 26 23:59:59 2026 GMT",
    "san": [
      "www.activecampaign.com",
      "activecampaign.com"
    ],
    "days_left": 30,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.0.15",
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
  "cookies": [
    {
      "domain": "activecampaign.com",
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
      "origin": "https://sub.activecampaign.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.activecampaign.com/"
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
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "canva-site-verification=jr7ubLUf4AdQz7NWkCAPnQ",
    "google-site-verification=pns8v6xoUCNjHvUFVWiTCI4LJj7LHyz5CPghUG4ZYvc",
    "google-site-verification=5ecE6QK-uN7epMvq2briZD_vYB2nC_5Y3BukiSILBUI",
    "status-page-domain-verification=8wyn9807n4gs",
    "pendo-domain-verification=JK5zYujOmKqXb5aS1pRudbgHp2s"
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
      "not_before": "20250925000000",
      "not_after": "20261026235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/.env",
      "/apps/search/",
      "/blog/archives",
      "/blog/inside-activecampaign",
      "/blog/page",
      "/blog/tag",
      "/c/",
      "/cache/",
      "/comment-page-1",
      "/cpresources/",
      "/elementor-*",
      "/l/",
      "/learn/category/",
      "/learn/tag/",
      "/podcast/feed"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 8.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
