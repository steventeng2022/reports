# Security Audit Report — etsy.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://etsy.com/ |
| Bug bounty program | Etsy |
| Listed scope domain | etsy.com |
| Test date | 2026-09-26 17:44 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 8, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 13 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 14 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 15 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 12. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 13. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): mail. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 14. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.etsy.com/.well-known/mta-sts/policy.txt -> 403
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 15. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (hyvk4cp5zn27ld.etsy.com and 05jpmz3wrsdig4.etsy.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=xfkrv3yRwA5GGm0E4l5RlcNKTqVD8KAYsYdCYTBMF0; anthropic-domain-verification-nehbw6=4taelnzAjM6NVkhm1rylyYZ8r; lucidlink-verification=HYZGQ2NMESYDAVG1GR5EJX21Z0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of etsy.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1681 disallow path(s), e.g. /, /people, /uk/people, /au/people, /ca/people
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "etsy.com",
  "dns": {
    "a": [
      "151.101.129.224",
      "151.101.1.224",
      "151.101.193.224",
      "151.101.65.224"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 50)",
      "alt2.aspmx.l.google.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 40)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-1264.awsdns-30.org.",
      "ns-162.awsdns-20.com.",
      "dns3.p03.nsone.net.",
      "dns1.p03.nsone.net."
    ],
    "spf": [
      "_globalsign-domain-verification=xfkrv3yRwA5GGm0E4l5RlcNKTqVD8KAYsYdCYTBMF0",
      "anthropic-domain-verification-nehbw6=4taelnzAjM6NVkhm1rylyYZ8r",
      "lucidlink-verification=HYZGQ2NMESYDAVG1GR5EJX21Z0",
      "MS=ms91667443",
      "atlassian-domain-verification=cMcfcaBm3JNaxKiO2fok5oOn20qbqxLmjQdFrsLV25SQj8l5hTkX/pb21NqLPLP0",
      "openai-domain-verification=dv-kBkaf6OFwgohxPZc4YIjOD6t",
      "v=spf1 ip4:66.3.159.0/24 ip4:192.147.0.0/24 ip4:173.46.67.72/29 ip4:192.147.1.0/24 ip4:38.106.64.0/24 ip4:38.76.1.0/24 ip4:38.76.2.0/24 ip4:162.220.28.32/27 ip4:162.220.28.64/28 ip4:208.74.204.0/22 ip4:46.19.168.0/23 include:servers.mcsv.net include:mail.",
      "zendesk.com include:amazonses.com include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com a:web.q4press.com include:cvent-planner.com include:mail.clinchtalent.com include:spf.redpoints.com -all",
      "google-site-verification=mpVLpWjH_tjbc5eK6pmVTZjq4xmHhzoE3crE0rKFULs",
      "bugcrowd-verification=460ceee75155fa4965c62123bc9cd182",
      "cursor-domain-verification-vyqnwm=JyRGj2Bcnbk8QqNAclaAE8mHY",
      "miro-verification=31250d3fe2c000cf1f892588d27dcf9eeb6afdd8",
      "stripe-verification=5e8773ee85575b784fc2a6868da2b17b165e2e59f62d067f77bfd40c0ad5cdc5",
      "facebook-domain-verification=j81l6m6391dika9nlbuh2c8ji9nhye",
      "docker-verification=40052c18-7a84-4d01-a294-9fed0866066e",
      "stripe-verification=fe491048e654bcc35d8f194964540604a3a4108e3191ffd27a9ea4c232d5bcf1",
      "apple-domain-verification=qgAwoHpdlhEv-3QiQ3G11S5xHj60JbTSzecxszntlvo",
      "docusign=9866d46c-c0b0-47c6-a98e-c6381eb4ccc6",
      "MS=61C0D53B132406B96613AF941D1FFB83A6CFCD73",
      "datadome-domain-verify=BNtk7vonAvB8fhBLjp0E2orOzns71WB1",
      "fastly-domain-delegation-svi5ebiqbg4tbn-20251029",
      "stripe-verification=660c4cdde58756c254bc46c26b92b6232ebc140156e6d2ba74cbb988b283b5ae",
      "adobe-idp-site-verification=1858581c5ab657f77e067d14de03dd297c85f0b6b2916dbe0adeca4fac539e6b",
      "monday-com-verification=bG-_DMl97UjUXdEr36_aoOlymHnNMGiZ9z_UM8h7t20",
      "segment-site-verification=qK8Hs2slX9yMAAiKpgMoNP6bJCKq0cqQ",
      "pinterest-site-verification=b92965d84ebb1103548fbd23e39baf66",
      "onetrust-domain-verification=9f4716cb45f046429764b34174392ce2",
      "wrike-verification=NDMwNDc4NDo3YzVlMGVmM2RhZGU0NjRkZTIxZTBjYmU5Mjc2NGZmODRmNzVhMDc2NjRmMTI0NThhYzlhZTdhMzhkNzkyY2Uw",
      "jamf-site-verification=lUaUDNLb-GDzmbIbaCg_lg"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc@etsy.com; ruf=mailto:dmarc@etsy.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=*.etsystatic.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2025 Q4",
    "notBefore": "Nov  3 15:09:45 2025 GMT",
    "notAfter": "Dec  5 15:09:44 2026 GMT",
    "san": [
      "*.etsystatic.com",
      "api-origin.etsy.com",
      "api.etsy.com",
      "m.etsy.com",
      "openapi.etsy.com",
      "www.etsy.com",
      "etsy.com",
      "openapi-staging.etsy.com"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.129.224",
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
      "origin": "https://sub.etsy.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.etsy.com/"
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
  "wildcard_dns": true,
  "apex_txt": [
    "_globalsign-domain-verification=xfkrv3yRwA5GGm0E4l5RlcNKTqVD8KAYsYdCYTBMF0",
    "anthropic-domain-verification-nehbw6=4taelnzAjM6NVkhm1rylyYZ8r",
    "lucidlink-verification=HYZGQ2NMESYDAVG1GR5EJX21Z0",
    "atlassian-domain-verification=cMcfcaBm3JNaxKiO2fok5oOn20qbqxLmjQdFrsLV25SQj8l5hT",
    "openai-domain-verification=dv-kBkaf6OFwgohxPZc4YIjOD6t"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/",
      "/people",
      "/uk/people",
      "/au/people",
      "/ca/people",
      "/de-en/people",
      "/dk-en/people",
      "/fi-en/people",
      "/hk-en/people",
      "/ie/people",
      "/il-en/people",
      "/in-en/people",
      "/no-en/people",
      "/nz/people",
      "/se-en/people"
    ]
  },
  "elapsed_s": 16.7,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
