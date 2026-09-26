# Security Audit Report — bbc.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bbc.com/ |
| Bug bounty program | BBC |
| Listed scope domain | bbc.com |
| Test date | 2026-09-25 08:43 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 3, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | CT1 | 89 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] 89 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: account-api.api.bbc.com, activity.api.bbc.com, activity.int.api.bbc.com, activity.stage.api.bbc.com, activity.test.api.bbc.com, af-dummy-ui-1.test.api.bbc.com, amservice.api.bbc.com, amservice.int.api.bbc.com, amservice.stage.api.bbc.com, amservice.test.api.bbc.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "bbc.com",
  "dns": {
    "a": [
      "151.101.0.81",
      "151.101.192.81",
      "151.101.64.81",
      "151.101.128.81"
    ],
    "aaaa": [
      "2a04:4e42:200::81",
      "2a04:4e42:400::81",
      "2a04:4e42:600::81",
      "2a04:4e42::81"
    ],
    "cname": null,
    "mx": [
      "cluster8.eu.messagelabs.com (pref 10)",
      "cluster8a.eu.messagelabs.com (pref 20)"
    ],
    "ns": [
      "dns0.bbc.com.",
      "dns1.bbc.co.uk.",
      "ddns1.bbc.com.",
      "ddns0.bbc.co.uk.",
      "ddns0.bbc.com.",
      "dns1.bbc.com.",
      "ddns1.bbc.co.uk.",
      "dns0.bbc.co.uk."
    ],
    "spf": [
      "_globalsign-domain-verification=PpIYEptb1-AaatNRPoS2XiWRmxR7zAT1MR52dvDNzx",
      "airtable-verification=b1a394c872dd6721d39a1d91cc96080d",
      "dropbox-domain-verification=mtgv0f2pudoz",
      "atlassian-domain-verification=SQsgJ5h/FqwMTXuSG/G4Nd1Gx6uX2keREOsZSa22D5XT46EsEuyaic8Aej4cR4Tr",
      "google-site-verification=mTy-FoNnG0yetpI3-0e9AXctAkUCcWGc_K3BcMfioFI",
      "adobe-idp-site-verification=c3a16fcb00ac5365e4ea125d5e59d4be11936f768b3020c4d81b4232019604a2",
      "xoCARoExwkNhLPdKaaxv",
      "docusign=75217687-3ba0-49bb-bb3b-482d888493af",
      "Validity-Domain-Verification=TYXJnAeGHNF4DGlOgE4vdoDT3a0=",
      "v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16 +include:spf.messagelabs.com ~all",
      "jamf-site-verification=28Mn3O6rTBSXkL5w6c911A",
      "docusign=57499c1f-9099-463b-a5bd-cb7583816d78",
      "slack-domain-verification=hza4gfkmctQ7A7BpMhGNVOZVZcKTFC8OC5ewDFVA",
      "atlassian-sending-domain-verification=da3721b6-1d2c-4c32-bf01-b792667aeb4d",
      "docker-verification=f89691bb-7bdd-4bc1-9673-57454d6d9c42"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;aspf=s;adkim=s;pct=100;fo=0;ri=86400; rua=mailto:dmarc_agg@vali.email;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=GB, stateOrProvinceName=London, localityName=London, organizationName=BRITISH BROADCASTING CORPORATION, commonName=www.bbc.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign GCC R46 OV TLS CA 2025",
    "notBefore": "Aug 21 11:32:02 2026 GMT",
    "notAfter": "Jan 24 05:46:23 2027 GMT",
    "san": [
      "www.bbc.com",
      "account.bbc.com",
      "session.bbc.com",
      "account.bbc.co.uk",
      "bbc.co.uk",
      "bbcrussian.com",
      "cdnedge.bbc.co.uk",
      "news.bbc.co.uk",
      "news.bbcimg.co.uk",
      "newsimg.bbc.co.uk",
      "newsrss.bbc.co.uk",
      "newsvote.bbc.co.uk",
      "node1.bbcimg.co.uk",
      "open.live.bbc.co.uk",
      "playlists.bbc.co.uk",
      "r.bbci.co.uk",
      "search.bbc.co.uk",
      "session.bbc.co.uk",
      "www.bbc.co.uk",
      "www.bbcrussian.com",
      "wwwnews.live.bbc.co.uk",
      "bbc.com"
    ],
    "days_left": 120,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.0.81",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bbc.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bbc.com/"
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
    "count": 89,
    "notable": [
      "account-api.api.bbc.com",
      "activity.api.bbc.com",
      "activity.int.api.bbc.com",
      "activity.stage.api.bbc.com",
      "activity.test.api.bbc.com",
      "af-dummy-ui-1.test.api.bbc.com",
      "amservice.api.bbc.com",
      "amservice.int.api.bbc.com",
      "amservice.stage.api.bbc.com",
      "amservice.test.api.bbc.com",
      "api.int.bbcx.test.api.bbc.com",
      "api.stage.bbcx.test.api.bbc.com",
      "api.test.bbcx.test.api.bbc.com",
      "audco.api.bbc.com",
      "audco.int.api.bbc.com"
    ],
    "sample": [
      "account-api.api.bbc.com",
      "activity.api.bbc.com",
      "activity.int.api.bbc.com",
      "activity.stage.api.bbc.com",
      "activity.test.api.bbc.com",
      "af-dummy-ui-1.test.api.bbc.com",
      "amservice.api.bbc.com",
      "amservice.int.api.bbc.com",
      "amservice.stage.api.bbc.com",
      "amservice.test.api.bbc.com",
      "api.int.bbcx.test.api.bbc.com",
      "api.stage.bbcx.test.api.bbc.com",
      "api.test.bbcx.test.api.bbc.com",
      "audco.api.bbc.com",
      "audco.int.api.bbc.com",
      "audco.stage.api.bbc.com",
      "audco.test.api.bbc.com",
      "bag.int.api.bbc.com",
      "bag.stage.api.bbc.com",
      "bag.test.api.bbc.com"
    ]
  },
  "elapsed_s": 142.4,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
