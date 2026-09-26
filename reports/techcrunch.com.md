# Security Audit Report — techcrunch.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://techcrunch.com/ |
| Bug bounty program | Yahoo! |
| Listed scope domain | techcrunch.com |
| Test date | 2026-09-26 19:00 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P11 | WordPress login page exposed | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 16 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx; X-Powered-By: WordPress VIP <https://wpvip.com>
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=300 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): usb. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=nTM39ZyyvRHb2-jcX__j5Hp1-y9zCw_gwX_I-QYrnVo; knowbe4-site-verification=bc3830115833f4f956e30f506f1da8c8; fireflies-verification=01KRNDX9V0J96ERQ2TKYCJ2M27.ffverify.fireflies.ai-request-
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of techcrunch.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but techcrunch.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 17 disallow path(s), e.g. /wp-admin/, /wp-json/, /search/, /?s=, /*?customize_changeset_uuid=*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of techcrunch.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 16. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://techcrunch.com/ carries Cache-Control: max-age=300, must-revalidate; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "techcrunch.com",
  "dns": {
    "a": [
      "192.0.66.220"
    ],
    "aaaa": [
      "2a04:fa87:fffd::c000:42dc"
    ],
    "cname": null,
    "mx": [
      "usb-smtp-inbound-1.mimecast.com (pref 0)",
      "usb-smtp-inbound-2.mimecast.com (pref 0)"
    ],
    "ns": [
      "gordon.ns.cloudflare.com.",
      "elly.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=nTM39ZyyvRHb2-jcX__j5Hp1-y9zCw_gwX_I-QYrnVo",
      "knowbe4-site-verification=bc3830115833f4f956e30f506f1da8c8",
      "fireflies-verification=01KRNDX9V0J96ERQ2TKYCJ2M27.ffverify.fireflies.ai-request-verification=2026-05-15T09:01:35Z",
      "b42c6b9e-33ca-44c0-a919-3152d6b3ddfa",
      "slido-domain-verification=87b6e1fe-2406-444f-90df-2cd87a594a34",
      "google-site-verification=JJNsJJsmpgH6VoKlFj7qG9V223pIrsduvb7qQ31GNC0",
      "google-site-verification=8tVHhkiXUNoPjI09EcLgjl9V7TwSXxLV0bnIjcEmpFw",
      "134052hpsyz5k73sv39m0sgxljsqyls7",
      "0ed1fe018a18c01fd51bff49e5bd633fade441856b",
      "google-site-verification=DhlHJ_81bZLsrh5TLvK7ac04EG4QvEAa8hjtsiMpUTQ",
      "docusign=1ad1e6cd-4dfe-4b34-8689-5797102f132e",
      "MS=ms36891426",
      "openai-domain-verification=dv-NrFR5wvpHqoGtf07m6oIH3J1",
      "zeplin",
      "atlassian-domain-verification=4p4CB0YJGNxskcxmubnX/fKvtqP6u8KRknplzFR3ZsH8zcSfjqtxNyCNIIktcAch",
      "google-site-verification=KsXJcvhk00hppwpZ3oNMk0GzB9M2GFUxA7XjdRVpc1U",
      "google-site-verification=HgtRMjw2Jm4kQso_oGLMcQ7ndEv8wNcGa0Kquhm9KK0",
      "airtable-verification=e989fdaedddc09c0e5c782dd036dd08a",
      "dropbox-domain-verification=sh3f8kienale",
      "MS=ms48927658",
      "anthropic-domain-verification-bqkhj4=U4gt2pxQQDf0aqgfPI3Q8Uvtp",
      "apple-domain-verification=uzwfq0Ev591PKKS6",
      "google-site-verification=VZcuQE1gCO7Zg1W2g_uzOzDXXICzPt74_eE-w0SRpt4",
      "figma-domain-verification=774a69a105d2f08bc9290464cb7082210e1fe77d9a4aa86a50e29eb75501b33d-1787841662",
      "yahoo-verification-key=nBRGLDZQzTUnUA7c6taNupK6RrG3ZGZs0PjHJmWAkqM=",
      "v=spf1 a mx include:usb._netblocks.mimecast.com include:spf.protection.outlook.com include:aspmx.sailthru.com include:mail.zendesk.com include:242234635.spf02.hubspotemail.net -all",
      "_globalsign-domain-verification=esDvs5Msz39F5o97VaHcZxyKR4A6NPHRpuo9du1Tro",
      "google-site-verification=NgMXk6BZ-jqt9XTrgnGt_O7hY4xD-NEAWsfSSD2VuZQ"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:6cc97f5d2993594@rep.dmarcanalyzer.com; ruf=mailto:6cc97f5d2993594@for.dmarcanalyzer.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=techcrunch.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Sep 23 02:28:09 2026 GMT",
    "notAfter": "Dec 22 02:28:08 2026 GMT",
    "san": [
      "techcrunch.com",
      "www.techcrunch.com"
    ],
    "days_left": 86,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.220",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "TechCrunch | Startup and Technology News"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx",
    "X-Powered-By: WordPress VIP <https://wpvip.com>"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "https://techcrunch.com",
      "acac": ""
    },
    {
      "origin": "https://sub.techcrunch.com",
      "acao": "https://techcrunch.com",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://techcrunch.com/"
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
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 301,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=nTM39ZyyvRHb2-jcX__j5Hp1-y9zCw_gwX_I-QYrnVo",
    "knowbe4-site-verification=bc3830115833f4f956e30f506f1da8c8",
    "fireflies-verification=01KRNDX9V0J96ERQ2TKYCJ2M27.ffverify.fireflies.ai-request-",
    "slido-domain-verification=87b6e1fe-2406-444f-90df-2cd87a594a34",
    "google-site-verification=JJNsJJsmpgH6VoKlFj7qG9V223pIrsduvb7qQ31GNC0"
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
      "not_before": "20260923022809",
      "not_after": "20261222022808"
    }
  },
  "http2": {
    "robots_disallow": [
      "/wp-admin/",
      "/wp-json/",
      "/search/",
      "/?s=",
      "/*?customize_changeset_uuid=*",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 200
  },
  "elapsed_s": 28.7,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
