# Security Audit Report — about.me

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://about.me/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | about.me |
| Test date | 2026-09-27 00:08 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **29** (High: 0, Medium: 0, Low: 7, Info: 22)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 6 | info | TECH1 | Technology fingerprint | CWE-200 |
| 7 | low | H1 | Missing HSTS header | CWE-319 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 15 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 16 | info | P8 | Missing security.txt | CWE-1038 |
| 17 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 18 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 19 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 20 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 21 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 22 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 23 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 24 | low | CK6 | Session-like cookie lacks both Secure and SameSite | CWE-614 |
| 25 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 26 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 27 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 28 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 29 | info | CT1 | 14 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.175.226:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.175.226:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 6. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 7. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 14. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'authtkt' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 15. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'authtkt' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 16. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 17. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 18. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 19. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 20. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=pYlAjtdFCdm86YjcBC66jyhpSUvzeoPlFPVHLqLqV5Y; google-site-verification=ezRBJTbsEc9ZMG8NFFOM5yPUnskJqSaJQPxjrUQBF_0; google-site-verification=mh9O3ZTO4tnj11WMoX06xfXsrMXZ4LXH4z-tFNM6H7c
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 21. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of about.me has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 22. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'authtkt' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 23. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 119 disallow path(s), e.g. /facebook/, /twitter/, /linkedin/, /random/, /content/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 24. [LOW] Session-like cookie lacks both Secure and SameSite (`CK6`)

- **CWE:** CWE-614
- **Detail:** Cookie 'authtkt' set on about.me has neither the Secure nor the SameSite attribute: interception exposure plus un-gated CSRF usability.
- **Recommendation:** Set Secure and SameSite=Lax (or Strict) on session-like cookies.

### 25. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkdw9bwcbugtve.html -> 404; error page/headers match: Cloudflare, Heroku.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 26. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for about.me, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 27. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of about.me loads 1 cross-origin script(s) without an integrity attribute, e.g. https://www.googletagmanager.com/gtag/js?id=G-LE3EMX7RDC; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 28. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of about.me references 12 distinct third-party registrable domains (e.g. w3.org, vendasta.com, b-cdn.net, googletagmanager.com, nicolekanieski.com); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 29. [INFO] 14 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: about.me, agendadw.about.me, api.about.me, billing.about.me, blog.about.me, campus.about.me, click.about.me, click.team.about.me, dw.about.me, images.about.me
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "about.me",
  "dns": {
    "a": [
      "172.66.175.226",
      "104.20.34.88"
    ],
    "aaaa": [
      "2606:4700:10::ac42:afe2",
      "2606:4700:10::6814:2258"
    ],
    "cname": null,
    "mx": [
      "mxb.mailgun.org (pref 10)",
      "mxa.mailgun.org (pref 10)"
    ],
    "ns": [
      "nola.ns.cloudflare.com.",
      "matteo.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "rYv22oBgkBJCPUaoK6nsdSqH9oQ",
      "google-site-verification=pYlAjtdFCdm86YjcBC66jyhpSUvzeoPlFPVHLqLqV5Y",
      "google-site-verification=ezRBJTbsEc9ZMG8NFFOM5yPUnskJqSaJQPxjrUQBF_0",
      "F960-D4BE-061D-9E99-175E-9D68-FC3C-A9CF",
      "33e6c9f3152c4b8893a2e464d922b9e5",
      "google-site-verification=mh9O3ZTO4tnj11WMoX06xfXsrMXZ4LXH4z-tFNM6H7c",
      "v=spf1 include:sendgrid.net -all",
      "google-site-verification=h1eVFLL2x1CNJ3DncGFyBuQ0Uf_lgs7Vz8XAmvxAr2w"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:webmaster@team.about.me",
      "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=about.me",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 31 10:48:54 2026 GMT",
    "notAfter": "Nov 29 11:48:44 2026 GMT",
    "san": [
      "about.me",
      "*.about.me"
    ],
    "days_left": 63,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.66.175.226",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "about.me | your personal homepage"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {},
    {
      "domain": ".about.me"
    },
    {
      "domain": "about.me",
      "samesite": "lax"
    },
    {
      "domain": "about.me",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.about.me",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://about.me/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 302,
    "/security.txt": 404,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 302,
    "/server-status": 404,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 14,
    "notable": [
      "about.me",
      "agendadw.about.me",
      "api.about.me",
      "billing.about.me",
      "blog.about.me",
      "campus.about.me",
      "click.about.me",
      "click.team.about.me",
      "dw.about.me",
      "images.about.me",
      "support.about.me",
      "team.about.me",
      "tool.about.me",
      "www.about.me"
    ],
    "sample": [
      "about.me",
      "agendadw.about.me",
      "api.about.me",
      "billing.about.me",
      "blog.about.me",
      "campus.about.me",
      "click.about.me",
      "click.team.about.me",
      "dw.about.me",
      "images.about.me",
      "support.about.me",
      "team.about.me",
      "tool.about.me",
      "www.about.me"
    ]
  },
  "apex_txt": [
    "google-site-verification=pYlAjtdFCdm86YjcBC66jyhpSUvzeoPlFPVHLqLqV5Y",
    "google-site-verification=ezRBJTbsEc9ZMG8NFFOM5yPUnskJqSaJQPxjrUQBF_0",
    "google-site-verification=mh9O3ZTO4tnj11WMoX06xfXsrMXZ4LXH4z-tFNM6H7c",
    "google-site-verification=h1eVFLL2x1CNJ3DncGFyBuQ0Uf_lgs7Vz8XAmvxAr2w"
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
      "serial": 101611129023465183517576395017752499648,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://c.pki.goog/we1/JYtLkK6NxCo.crl"
      ],
      "subject_dn": "3111300f0603550403130861626f75742e6d65",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531",
      "not_before": "20260831104854",
      "not_after": "20261129114844"
    }
  },
  "http2": {
    "robots_disallow": [
      "/facebook/",
      "/twitter/",
      "/linkedin/",
      "/random/",
      "/content/",
      "/n/",
      "/ajax/",
      "/me/",
      "/dw/",
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
    "crl": {
      "url": "http://c.pki.goog/we1/JYtLkK6NxCo.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "elapsed_s": 14.2,
  "rechecked": "2026-09-27 00:08 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- Findings are reported against the public program scope; submission through the program tracker is pending.
