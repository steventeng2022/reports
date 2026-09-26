# Security Audit Report — techcrunch.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://techcrunch.com/ |
| Bug bounty program | Yahoo! |
| Listed scope domain | techcrunch.com |
| Test date | 2026-09-26 23:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 3, Info: 17)

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
| 17 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 20 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: _globalsign-domain-verification=esDvs5Msz39F5o97VaHcZxyKR4A6NPHRpuo9du1Tro; google-site-verification=HgtRMjw2Jm4kQso_oGLMcQ7ndEv8wNcGa0Kquhm9KK0; google-site-verification=DhlHJ_81bZLsrh5TLvK7ac04EG4QvEAa8hjtsiMpUTQ
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

### 17. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk5udqnoom3yrh.html -> 404; error page/headers match: Nginx, WordPress.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for techcrunch.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of techcrunch.com loads 3 cross-origin script(s) without an integrity attribute, e.g. https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit, https://public.servenobid.com/partner/163965/163966/wrapup_1.0.0.js?ver=66e1dba3ef08ae9649dc, https://experiments.parsely.com/vip-experiments.js?apiKey=techcrunch.com&amp;ver=3.24.1; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 20. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on techcrunch.com lists 2059 <loc> URL(s) across 2060 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

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
      "usb-smtp-inbound-2.mimecast.com (pref 0)",
      "usb-smtp-inbound-1.mimecast.com (pref 0)"
    ],
    "ns": [
      "elly.ns.cloudflare.com.",
      "gordon.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "b42c6b9e-33ca-44c0-a919-3152d6b3ddfa",
      "_globalsign-domain-verification=esDvs5Msz39F5o97VaHcZxyKR4A6NPHRpuo9du1Tro",
      "google-site-verification=HgtRMjw2Jm4kQso_oGLMcQ7ndEv8wNcGa0Kquhm9KK0",
      "google-site-verification=DhlHJ_81bZLsrh5TLvK7ac04EG4QvEAa8hjtsiMpUTQ",
      "MS=ms36891426",
      "dropbox-domain-verification=sh3f8kienale",
      "yahoo-verification-key=nBRGLDZQzTUnUA7c6taNupK6RrG3ZGZs0PjHJmWAkqM=",
      "airtable-verification=e989fdaedddc09c0e5c782dd036dd08a",
      "google-site-verification=JJNsJJsmpgH6VoKlFj7qG9V223pIrsduvb7qQ31GNC0",
      "figma-domain-verification=774a69a105d2f08bc9290464cb7082210e1fe77d9a4aa86a50e29eb75501b33d-1787841662",
      "slido-domain-verification=87b6e1fe-2406-444f-90df-2cd87a594a34",
      "0ed1fe018a18c01fd51bff49e5bd633fade441856b",
      "MS=ms48927658",
      "google-site-verification=nTM39ZyyvRHb2-jcX__j5Hp1-y9zCw_gwX_I-QYrnVo",
      "fireflies-verification=01KRNDX9V0J96ERQ2TKYCJ2M27.ffverify.fireflies.ai-request-verification=2026-05-15T09:01:35Z",
      "google-site-verification=VZcuQE1gCO7Zg1W2g_uzOzDXXICzPt74_eE-w0SRpt4",
      "v=spf1 a mx include:usb._netblocks.mimecast.com include:spf.protection.outlook.com include:aspmx.sailthru.com include:mail.zendesk.com include:242234635.spf02.hubspotemail.net -all",
      "apple-domain-verification=uzwfq0Ev591PKKS6",
      "google-site-verification=KsXJcvhk00hppwpZ3oNMk0GzB9M2GFUxA7XjdRVpc1U",
      "134052hpsyz5k73sv39m0sgxljsqyls7",
      "anthropic-domain-verification-bqkhj4=U4gt2pxQQDf0aqgfPI3Q8Uvtp",
      "docusign=1ad1e6cd-4dfe-4b34-8689-5797102f132e",
      "atlassian-domain-verification=4p4CB0YJGNxskcxmubnX/fKvtqP6u8KRknplzFR3ZsH8zcSfjqtxNyCNIIktcAch",
      "openai-domain-verification=dv-NrFR5wvpHqoGtf07m6oIH3J1",
      "google-site-verification=8tVHhkiXUNoPjI09EcLgjl9V7TwSXxLV0bnIjcEmpFw",
      "zeplin",
      "google-site-verification=NgMXk6BZ-jqt9XTrgnGt_O7hY4xD-NEAWsfSSD2VuZQ",
      "knowbe4-site-verification=bc3830115833f4f956e30f506f1da8c8"
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
    "_globalsign-domain-verification=esDvs5Msz39F5o97VaHcZxyKR4A6NPHRpuo9du1Tro",
    "google-site-verification=HgtRMjw2Jm4kQso_oGLMcQ7ndEv8wNcGa0Kquhm9KK0",
    "google-site-verification=DhlHJ_81bZLsrh5TLvK7ac04EG4QvEAa8hjtsiMpUTQ",
    "dropbox-domain-verification=sh3f8kienale",
    "yahoo-verification-key=nBRGLDZQzTUnUA7c6taNupK6RrG3ZGZs0PjHJmWAkqM="
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
      "serial": 537823086950644908497079562679692420626639,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye2.c.lencr.org/80.crl"
      ],
      "subject_dn": "311730150603550403130e746563686372756e63682e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594532",
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
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=300;includeSubdomains",
    "sitemap": {
      "urls": 2059,
      "indexes": 2060
    },
    "crl": {
      "url": "http://ye2.c.lencr.org/80.crl",
      "status": 200
    }
  },
  "elapsed_s": 31.0,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
