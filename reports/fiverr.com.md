# Security Audit Report — fiverr.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://fiverr.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | fiverr.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | SEC2 | security.txt published without a contact address | CWE-1038 |
| 19 | info | CT1 | 44 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 20 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.113.47:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.113.47:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=kMxO4LGDSjWFroQsa4yAFrJqPmPKg1S-LQ6RUC10DqQ; google-site-verification=hgsUdXptruag4sbh8wh7u9sOpz0rScqytDJKMTj_cUU; google-site-verification=O55kJ9s5kFZ4ZBKNCc0ZoJn40YyB7yM_vONo2l3W_pc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of fiverr.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 55 disallow path(s), e.g. /orders/timeline/*, */pinned_flashes/*, /gigs/*/share/, /gigs/*/share?*, /specials/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] security.txt published without a contact address (`SEC2`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt returns 200 but contains no mailto:/URL contact.
- **Recommendation:** Add a Contact: field per RFC 9116.

### 19. [INFO] 44 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: dev.fiverr.com, okteto.dev.fiverr.com, pci-internal.dev.fiverr.com, pci.dev.fiverr.com, pro.dev.fiverr.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 20. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: pci-internal.dev.fiverr.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "fiverr.com",
  "dns": {
    "a": [
      "104.18.113.47",
      "104.18.114.47"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx3.googlemail.com (pref 50)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx2.googlemail.com (pref 40)"
    ],
    "ns": [
      "lucy.ns.cloudflare.com.",
      "sid.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=kMxO4LGDSjWFroQsa4yAFrJqPmPKg1S-LQ6RUC10DqQ",
      "google-site-verification=hgsUdXptruag4sbh8wh7u9sOpz0rScqytDJKMTj_cUU",
      "sending_domain1079702=fe376d47978ba73b85655072c1359a2bde21692a90cdd2ac949ec76c9f5643f0",
      "g2hsd2r7uqt07crr95ts25hgec",
      "google-site-verification=O55kJ9s5kFZ4ZBKNCc0ZoJn40YyB7yM_vONo2l3W_pc",
      "ZOOM_verify_t3nnvUw_QNuEQ4zcJbNWvg",
      "jai1f598eosu9g2ua6hdcpvo5r",
      "google-site-verification=iNB30Gch08wWB6x_texeR3GWax3SYEanzhkPIgu5NHY",
      "mongodb-site-verification=qwSddVOKDfrufdjzWe8XcrxiXFqsH3HH",
      "monday-com-verification=DHMhr9r0SLQ1XbH-UgVehCcq-kI5NO-3gC3T2YhsHNs",
      "sendinblue-code:00c77aaa511d14ef758415286cceb8f8",
      "8faqpd2tgvlfjq9an0q8311pv4",
      "google-site-verification=SO-X1xOZnZI8nCyaqDcVFT2iMKXHKzh78QZ-hQZXdDg",
      "apple-domain-verification=9KpxtRRlTnV9CMWj",
      "google-site-verification=YRULw1rJRupVM3WOgi-oe0G-ha41QBBrm1P8irxmMj4",
      "cursor-domain-verification-snmncy=v2sK6oZqni8YXE6z4r2hYiDk2",
      "citrix-verification-code=a6b5039d-7719-4399-a895-8dc16ee2be75",
      "google-site-verification=8GwcSuHShuYh0Zl7pqbKLFl2Vy4LJwb663OKdq7oAfU",
      "google-site-verification=ngPwP5LN0jLJFSwOIs3QPjWdNeXSBaNlAaiK489xW3w",
      "globalsign-domain-verification=8frsHcE2ag-0ccaaP5BTpPmUJC8ob8pdjDQchfAWzD",
      "google-site-verification=OjzIGtAACARGfq-pzfMWJMxPn6MgwCqnz8SuJ0agnGs",
      "jamf-site-verification=qTZ2kHy5JVbJULQo_cm6sw",
      "MS=ms20976924",
      "00Df2000000vILs=1TBPn0000000Tmn",
      "pardot1046343=0c19387b5d416ad576c0938517af3c23e0ec43bb16096e6201065cda46f41092",
      "google-site-verification=ijrZ6Yqf-IkTyWct0jRahvbn9D3kphesRnUe4VZT9dE",
      "facebook-domain-verification=mzxc9iigaciqjvtj28n064sk2rzbk5",
      "mixpanel-domain-verify=90c3d81c-7a7c-4d4d-9b0d-5a60ae994e90",
      "00D7z00000Zok0H=1TB7z0000000Q0v",
      "anthropic-domain-verification-nh998a=YsbxIDUYEOhBI910nAo65cY2R",
      "miro-verification=6a9e176e900b5e728d0f62659369d5d5593e28c3",
      "apple-domain-verification=qnipzrtidRJDoQCh",
      "dropbox-domain-verification=8ilu3axidut2",
      "fastly-domain-delegation-j93rv73ms7qpmtzhqhqq-883244-2025-02-18",
      "v=spf1 ip4:34.192.34.210 ip4:34.192.87.38 ip4:34.243.203.200 include:sendgrid.net include:mail.zendesk.com include:_spf.google.com include:_spf.salesforce.com include:spf1.fiverr.com -all",
      "sending_domain1046343=a12cb274f55f4a914e10a7258cd1e59efe2d8d2d2cb275a91f531a3d4829d84b",
      "wiz-domain-verification=5c2bc898460351b783ced51189ad2f3d7ec3a8a6d63f2dc26fa3ec4123d899ab",
      "atlassian-domain-verification=an+ckXl/FPR7+1gsMUQxtq4syuZoBklOsT5vcFXtDtvx9PN0bsiMTfVAGRTmOOWT"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dca17281@mxtoolbox.dmarc-report.com; ruf=mailto:dca17281@forensics.dmarc-report.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "subject": "commonName=fiverr.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 25 18:45:45 2026 GMT",
    "notAfter": "Dec 24 19:45:27 2026 GMT",
    "san": [
      "fiverr.com",
      "*.post.workspace.fiverr.com",
      "*.nl.fiverr.com",
      "*.pt.fiverr.com",
      "*.affiliates.fiverr.com",
      "*.announce.fiverr.com",
      "*.app.develop.workspace.fiverr.com",
      "*.app.stage.workspace.fiverr.com",
      "*.app.workspace.fiverr.com",
      "*.business.fiverr.com",
      "*.de.fiverr.com",
      "*.develop.workspace.fiverr.com",
      "*.es.fiverr.com",
      "*.fr.fiverr.com",
      "*.it.fiverr.com",
      "*.notifications.fiverr.com",
      "*.post.develop.workspace.fiverr.com",
      "*.post.stage.workspace.fiverr.com",
      "*.pro.fiverr.com",
      "*.refs.develop.workspace.fiverr.com",
      "*.refs.stage.workspace.fiverr.com",
      "*.refs.workspace.fiverr.com",
      "*.stage.workspace.fiverr.com",
      "*.updates.develop.workspace.fiverr.com",
      "*.updates.stage.workspace.fiverr.com",
      "*.updates.workspace.fiverr.com",
      "*.workspace.fiverr.com",
      "pro.fiverr.com",
      "workspace.fiverr.com"
    ],
    "days_left": 89,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "104.18.113.47",
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
      "origin": "https://sub.fiverr.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://fiverr.com/"
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
    "source": "certspotter",
    "count": 44,
    "notable": [
      "dev.fiverr.com",
      "okteto.dev.fiverr.com",
      "pci-internal.dev.fiverr.com",
      "pci.dev.fiverr.com",
      "pro.dev.fiverr.com"
    ],
    "sample": [
      "affiliates.fiverr.com",
      "answers.fiverr.com",
      "capig.fiverr.com",
      "checkup-api.fiverr.com",
      "checkup.fiverr.com",
      "community.fiverr.com",
      "connect.fiverr.com",
      "contests.fiverr.com",
      "dev.fiverr.com",
      "develop.workspace.fiverr.com",
      "discover.fiverr.com",
      "enterprise.fiverr.com",
      "events.fiverr.com",
      "fiverr.com",
      "gop.fiverr.com",
      "groove.fiverr.com",
      "investors.fiverr.com",
      "land.fiverr.com",
      "learn.fiverr.com",
      "lp.enterprise.fiverr.com"
    ],
    "dangling": [
      "pci-internal.dev.fiverr.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=kMxO4LGDSjWFroQsa4yAFrJqPmPKg1S-LQ6RUC10DqQ",
    "google-site-verification=hgsUdXptruag4sbh8wh7u9sOpz0rScqytDJKMTj_cUU",
    "google-site-verification=O55kJ9s5kFZ4ZBKNCc0ZoJn40YyB7yM_vONo2l3W_pc",
    "google-site-verification=iNB30Gch08wWB6x_texeR3GWax3SYEanzhkPIgu5NHY",
    "mongodb-site-verification=qwSddVOKDfrufdjzWe8XcrxiXFqsH3HH"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
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
      "/orders/timeline/*",
      "*/pinned_flashes/*",
      "/gigs/*/share/",
      "/gigs/*/share?*",
      "/specials/*",
      "/packages/*",
      "/categories/silly",
      "/categories/fifa",
      "/categories/Halloween",
      "/categories/Postcards",
      "/purchases",
      "/user_sessions",
      "/users/",
      "/counter/*?",
      "/collaborate/*"
    ]
  },
  "elapsed_s": 5.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
