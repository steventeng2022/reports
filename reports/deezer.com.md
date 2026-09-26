# Security Audit Report — deezer.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://deezer.com/ |
| Bug bounty program | Deezer |
| Listed scope domain | deezer.com |
| Test date | 2026-09-26 23:23 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
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
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: segment-site-verification=GlpHielfWK2mAxw280lnbJndwol19aGH; teamviewer-sso-verification=f9da86a27d794c74b772287a9d5787c2; google-site-verification=vvyvPgv8IufaTIaccQQlinaL8TQ85_PHDAfcZWtE6O0
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 3.169.55.41 carries PTR server-3-169-55-41.tpe54.r.cloudfront.net. for deezer.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for deezer.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

## Evidence (raw response observations)

```json
{
  "domain": "deezer.com",
  "dns": {
    "a": [
      "3.169.55.41",
      "3.169.55.75",
      "3.169.55.83",
      "3.169.55.100"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-340.awsdns-42.com.",
      "ns-1072.awsdns-06.org.",
      "ns-1935.awsdns-49.co.uk.",
      "ns-672.awsdns-20.net."
    ],
    "caa": [],
    "spf": [
      "segment-site-verification=GlpHielfWK2mAxw280lnbJndwol19aGH",
      "teamviewer-sso-verification=f9da86a27d794c74b772287a9d5787c2",
      "google-site-verification=vvyvPgv8IufaTIaccQQlinaL8TQ85_PHDAfcZWtE6O0",
      "apple-domain-verification=P57n1OdYT_c47nnR4KwTymOZrOA0cl32GWqj5pkCGQ0",
      "brevo-code:fa2e70dc2bb0553ba7f879cdb321c3f0",
      "teamviewer-sso-verification=255ec7551d7b4b16bfc94d0cba632b63",
      "google-site-verification=7I-SYis8ZeMmOpyppnK8xwO0zl0svUEAhj8Z2Y9PFcI",
      "wsbvv2s5vf",
      "docusign=8d8c13b3-cb80-43af-a6f3-0036bba8d3fc",
      "miro-verification=dfdce60c3dafe475e66cee1a7dff403050e298a9",
      "docusign=842e27e7-d700-4873-af3e-0cee181088e5",
      "docker-verification=2fcbee18-9629-4252-b876-b5f09e7f0d52",
      "atlassian-domain-verification=OKs3QGwhDbZrt7WH4gOo+3G6aSPoFiiO04wvktNpPRFGSzbDMhOz5OKfZMCP+F7Q",
      "MS=ms80038696",
      "TAILSCALE-35IXkmM36zZhS07BnS3k",
      "google-site-verification=od_WkSXO534wNFRABA-6zoxUIVwn60Md6SlU2i5i8iE",
      "anthropic-domain-verification-2kxj5s=ldg3Froq5PB3Ue61ZLWcJ120B",
      "tiktok-developers-site-verification=biDigQ8eMAwiHueSlRfgZYYDQnasm3L2",
      "bvAlPqTZ=c6edbdd62238ef342b47a23d07284dad",
      "jamf-site-verification=KLk9LYux1EXjBffu88rVgg",
      "browserstack-domain-verification=79af734f-e88b-487f-9191-55c52b27be0b",
      "google-site-verification=F8ZbIRsZzJL9xffCHf3E56G59z6HjD2CP6I1SRSDP68",
      "bitrise-verification=07f1c1d2f9ad3bc9-LO62dmQufLLX",
      "gradle-verification=F2ED2BTRLBH4T55MB7BLMAHMU3PKH",
      "facebook-domain-verification=wbu2pxqkdmso2hjz7j14fm2hoccy4z",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com include:servers.mcsv.net ip4:78.40.120.128/26 ip4:78.40.121.0/24 ip4:78.40.123.0/24 ip4:78.40.120.244 ip4:185.159.104.113 ip4:35.241.138.172 -all",
      "yandex-verification: ecd5587d4fbf1dc6",
      "tiktok-developers-site-verification=fsHQ2q4rKdukpTPlO15oSq88WsUbzChs"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_report@deezer.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=FR, localityName=Paris, organizationName=Deezer SA, commonName=*.deezer.com",
    "issuer": "countryName=FR, organizationName=Gandi SAS, commonName=GandiCert",
    "notBefore": "Jul 16 00:00:00 2026 GMT",
    "notAfter": "Jan 30 23:59:59 2027 GMT",
    "san": [
      "*.deezer.com",
      "deezer.com"
    ],
    "days_left": 126,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.55.41",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.deezer.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://deezer.com/"
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
    "segment-site-verification=GlpHielfWK2mAxw280lnbJndwol19aGH",
    "teamviewer-sso-verification=f9da86a27d794c74b772287a9d5787c2",
    "google-site-verification=vvyvPgv8IufaTIaccQQlinaL8TQ85_PHDAfcZWtE6O0",
    "apple-domain-verification=P57n1OdYT_c47nnR4KwTymOZrOA0cl32GWqj5pkCGQ0",
    "teamviewer-sso-verification=255ec7551d7b4b16bfc94d0cba632b63"
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
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 2473292772969040272899121726657427255,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/GandiCert.crl",
        "http://crl4.digicert.com/GandiCert.crl"
      ],
      "subject_dn": "310b3009060355040613024652310e300c06035504071305506172697331123010060355040a13094465657a65722053413115301306035504030c0c2a2e6465657a65722e636f6d",
      "issuer_dn": "310b300906035504061302465231123010060355040a130947616e646920534153311230100603550403130947616e646943657274",
      "not_before": "20260716000000",
      "not_after": "20270130235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-3-169-55-41.tpe54.r.cloudfront.net."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.deezer.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://crl3.digicert.com/GandiCert.crl",
      "status": 200
    }
  },
  "elapsed_s": 5.5,
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
