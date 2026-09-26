# Security Audit Report — apple.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://apple.com/ |
| Bug bounty program | Apple |
| Listed scope domain | apple.com |
| Test date | 2026-09-26 18:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 5, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.apple.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8; facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v; adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of apple.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 9 disallow path(s), e.g. /*shop/browse/overlay/*, /*shop/iphone/payments/overlay/*, /cn/*/aow/*, /tmall*, /*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 17.253.144.10 carries PTR apple.com.do., podcast.apple.com., brkgls.com., livepage.apple.com., seminars.apple.com., apple.it., apple.com., apple.com.my., apple.com.co., apple.com.gy., apple.com.py., firewire.apple.com., iphone.apple.com., safaricampaign.apple., applescript.apple.com., apple.ca., apple.com.pe., apple.com.ai., advertising.apple.com., applecomputer.co.kr., apple.com.uy., apple.com.cn., apple.com.tt., apple.com.bo., apple.fr., iworktrialbuy.apple.com., apple.com.lk., apple.es., world-any.aaplimg.com., apple.co.uk., apple.nl., apple.com.au., applejava.apple.com., apple.com.mx., apple.com.pa., apple.de., squeakytoytrainingcamp.com., apple.com.hn., shake.apple.com., icloud.com., aperturetrialbuy.apple.com., apple.com.sg., www.brkgls.com., vipd-healthcheck.a01.3banana.com., guide.apple.com., appstore.com., itunespartner.apple.com., asia.apple.com. for apple.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "apple.com",
  "dns": {
    "a": [
      "17.253.144.10"
    ],
    "aaaa": [
      "2620:149:af0::10"
    ],
    "cname": null,
    "mx": [
      "mx-in-ma.apple.com (pref 20)",
      "mx-in-sg.apple.com (pref 20)",
      "mx-in-rn.apple.com (pref 20)",
      "mx-in-hfd.apple.com (pref 20)",
      "mx-in-vib.apple.com (pref 20)",
      "mx-in.g.apple.com (pref 10)"
    ],
    "ns": [
      "c.ns.apple.com.",
      "d.ns.apple.com.",
      "b.ns.apple.com.",
      "a.ns.apple.com."
    ],
    "spf": [
      "webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8",
      "facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v",
      "adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c",
      "google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c",
      "lucidlink-verification=SCDW9V44GJHAVXKFS6ZY6EZ2YR",
      "atlassian-domain-verification=mLabq99iaT8kquJechF6l31FAYoNUe3WB7tLpLFUiUYVJCse9SKq83hOJzFkwqrh",
      "_eht2v8yfz1agpq7o4zdkkz3k0k86fyr",
      "cisco-ci-domain-verification=6f3bfb849796a518061f8e8c4356f687a138502d86db742791685059176547dd",
      "cerner-client-id=22dd1d8a-5e8b-4e1e-80ef-39bcdfd42798",
      "77a4a6de-da14-449c-83c4-85366e0f55f9",
      "google-site-verification=8M6XjQCzydT62jk8HY3VXPAG-nKDllTRV-JpA3-Ktyw",
      "yahoo-verification-key=Ay+djyw0qWQgXKWGA/jstjYryTMrKb+PBXI5l8u5/jw=",
      "v=spf1 include:_spf.apple.com include:_spf-txn.apple.com ~all",
      "google-site-verification=zBSq1mG5ssu2If-C17UAz_MzSZDcx03MVxmeDwMNc5w",
      "Dynatrace-site-verification=7d881a7c-c13f-4146-9d27-2731459e2509__iqls0105tagglcsaul0m16ibrf",
      "atlassian-domain-verification=qZD4TfnCAoAjCFQgafhoKQpOs9tviekNK4wYE4a5eK3XoRP06hXAvEp8SLU0v7fI",
      "apple-domain-verification=X5Jt76bn3Dnmgzjj",
      "_khcec23xgc5b2lb981hup1csjb4cdnz",
      "miro-verification=2494d255c4c50b1e521650a0659cbf3fa08b0072",
      "json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJpZW4wYWVHaGF0aG9oNmhhaHZpZWphaTNlYXkwYWh2YWhjaGFocXVhZWxlZTBZdWw0cGhpZXRoMHNvNXZpZXllZWNvaDRpZThzaGVlcGllVDNwYWVjaGVpVjZqb2h3aWVwaG82In0K",
      "cerner-client-id=ce3abf18-ee87-43b9-9927-9eb24b4bac4a",
      "json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJxdWFoMGVpamFhNGVlajh0aWVkYWlnaG9jZWljaGFlOGVUb3ppZTVmdTVhaFRoMldlaU00aWsyaHVxdThpZXBoaWVxdW9oc2hlaXBhZWdoOUthZWw3b2NoaWVuZ2llem9lc2g1In0K",
      "ValidationTokenValue=77a4a6de-da14-449c-83c4-85366e0f55f9"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "businessCategory=Private Organization, jurisdictionCountryName=US, jurisdictionStateOrProvinceName=California, serialNumber=C0806592, countryName=US, stateOrProvinceName=California, localityName=Cupertino, organizationName=Apple Inc., commonName=apple.com",
    "issuer": "countryName=US, organizationName=Apple Inc., commonName=Apple Public EV Server ECC CA 1 - G1",
    "notBefore": "Aug 13 16:20:01 2026 GMT",
    "notAfter": "Nov  5 20:55:13 2026 GMT",
    "san": [
      "apple.com"
    ],
    "days_left": 40,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "17.253.144.10",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.apple.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.apple.com/"
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
    "webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8",
    "facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v",
    "adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c",
    "google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c",
    "lucidlink-verification=SCDW9V44GJHAVXKFS6ZY6EZ2YR"
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
      "not_before": "20260813162001",
      "not_after": "20261105205513"
    }
  },
  "http2": {
    "robots_disallow": [
      "/*shop/browse/overlay/*",
      "/*shop/iphone/payments/overlay/*",
      "/cn/*/aow/*",
      "/tmall*",
      "/*",
      "/*",
      "/*",
      "/*",
      "/*"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "apple.com.do.",
      "podcast.apple.com.",
      "brkgls.com.",
      "livepage.apple.com.",
      "seminars.apple.com.",
      "apple.it.",
      "apple.com.",
      "apple.com.my.",
      "apple.com.co.",
      "apple.com.gy.",
      "apple.com.py.",
      "firewire.apple.com.",
      "iphone.apple.com.",
      "safaricampaign.apple.",
      "applescript.apple.com.",
      "apple.ca.",
      "apple.com.pe.",
      "apple.com.ai.",
      "advertising.apple.com.",
      "applecomputer.co.kr.",
      "apple.com.uy.",
      "apple.com.cn.",
      "apple.com.tt.",
      "apple.com.bo.",
      "apple.fr.",
      "iworktrialbuy.apple.com.",
      "apple.com.lk.",
      "apple.es.",
      "world-any.aaplimg.com.",
      "apple.co.uk.",
      "apple.nl.",
      "apple.com.au.",
      "applejava.apple.com.",
      "apple.com.mx.",
      "apple.com.pa.",
      "apple.de.",
      "squeakytoytrainingcamp.com.",
      "apple.com.hn.",
      "shake.apple.com.",
      "icloud.com.",
      "aperturetrialbuy.apple.com.",
      "apple.com.sg.",
      "www.brkgls.com.",
      "vipd-healthcheck.a01.3banana.com.",
      "guide.apple.com.",
      "appstore.com.",
      "itunespartner.apple.com.",
      "asia.apple.com."
    ]
  },
  "elapsed_s": 3.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
