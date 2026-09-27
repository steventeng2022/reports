# Security Audit Report — acm.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://acm.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | acm.org |
| Test date | 2026-09-27 00:08 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 16 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | info | CT1 | 196 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 19 days (notAfter Oct 16 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.78.30:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.17.78.30:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=0 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.acm.org/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: duo_sso_verification=oFRYT7Y1MADnakU5K1wxwe47F9TsTRZ76IZL8bgH2J0NFoipvgi5tAE6kTm; google-site-verification=lqxyh1_UaHYvgAfZ3gvxIDJi3quBVO_5Lq_pDUOKdNw; google-site-verification=8gUY1AtsZ3BzLVSHLSv3wXIE8MpnWrGgVrmvVxM1MjE
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but acm.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 18 disallow path(s), e.g. /live-search, /404, /landing-page-documents/, /referenced-ctalist/, /Member/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on acm.org indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 16. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk43hxvie4zhrj.html -> 403; error page/headers match: Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for acm.org, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [INFO] 196 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: idp.acm.org, mail.arg.hosting2.acm.org, mail.nsuacmsc.hosting.acm.org, mail.nsusc.hosting.acm.org, mail.selects.acm.org, staging.ubicomp.hosting.acm.org, webmail.arg.hosting2.acm.org, webmail.nsusc.hosting.acm.org, webmail.selects.acm.org, www.staging.gmritchapter.hosting.acm.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "acm.org",
  "dns": {
    "a": [
      "104.17.78.30",
      "104.17.79.30"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mail.mailroute.net (pref 10)"
    ],
    "ns": [
      "olga.ns.cloudflare.com.",
      "skip.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "MS=F1C3025E76F2E7036C9EAF6DBC2DF0C8D2D4AA87",
      "p0yygcm8ljrr9v47xkgrk4cjdvpctb6t",
      "duo_sso_verification=oFRYT7Y1MADnakU5K1wxwe47F9TsTRZ76IZL8bgH2J0NFoipvgi5tAE6kTmlRfY8",
      "_isyuzeobyu2bijfg78028dab2ac4f5r",
      "google-site-verification=lqxyh1_UaHYvgAfZ3gvxIDJi3quBVO_5Lq_pDUOKdNw",
      "google-site-verification=8gUY1AtsZ3BzLVSHLSv3wXIE8MpnWrGgVrmvVxM1MjE",
      "v=spf1 include:_spf.acm_org._d.easydmarc.pro ~all",
      "83zn0ndgz9jvwx563vp9qbyz38hqb7kl",
      "brevo-code:e7393522d4f06661f44afbccb0cebfc6",
      "3w6lthcz5h4qpgtd8n8szx1m474v73tz",
      "abuseipdb-verification=D4c0J6WF",
      "_ead5vviqjla5mjijrh4zvhsujcx843n"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=quarantine;pct=100;rua=mailto:9adb8cf49b@rua.easydmarc.us;ruf=mailto:9adb8cf49b@ruf.easydmarc.us;fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Association for Computing Machinery, Inc., commonName=*.acm.org",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Apr  1 00:00:00 2026 GMT",
    "notAfter": "Oct 16 23:59:59 2026 GMT",
    "san": [
      "*.acm.org",
      "acm.org"
    ],
    "days_left": 19,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.17.78.30",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
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
      "domain": "acm.org",
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
      "origin": "https://sub.acm.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://acm.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "source": "certspotter",
    "count": 196,
    "notable": [
      "idp.acm.org",
      "mail.arg.hosting2.acm.org",
      "mail.nsuacmsc.hosting.acm.org",
      "mail.nsusc.hosting.acm.org",
      "mail.selects.acm.org",
      "staging.ubicomp.hosting.acm.org",
      "webmail.arg.hosting2.acm.org",
      "webmail.nsusc.hosting.acm.org",
      "webmail.selects.acm.org",
      "www.staging.gmritchapter.hosting.acm.org",
      "www.staging.ubicomp.hosting.acm.org",
      "www.test.gmritchapter.hosting.acm.org",
      "www.test.nmamit.hosting.acm.org",
      "www.wiki.sigmobile.hosting.acm.org"
    ],
    "sample": [
      "acm.org",
      "acmftpvm01.acm.org",
      "acmsmtpvm03.acm.org",
      "acmsmtpvm03.priv.acm.org",
      "acmtvx.hosting.acm.org",
      "allegheny.acm.org",
      "allegheny.hosting.acm.org",
      "arg.hosting2.acm.org",
      "asplos-conference.org.asplos.hosting2.acm.org",
      "autoconfig.arg.hosting2.acm.org",
      "autoconfig.buildsys.hosting.acm.org",
      "autoconfig.nsusc.hosting.acm.org",
      "autoconfig.selects.acm.org",
      "autodiscover.arg.hosting2.acm.org",
      "autodiscover.nsusc.hosting.acm.org",
      "autodiscover.selects.acm.org",
      "avemaria.acm.org",
      "azerbaijan.hosting.acm.org",
      "bennett.acm.org",
      "bennett.hosting.acm.org"
    ]
  },
  "apex_txt": [
    "duo_sso_verification=oFRYT7Y1MADnakU5K1wxwe47F9TsTRZ76IZL8bgH2J0NFoipvgi5tAE6kTm",
    "google-site-verification=lqxyh1_UaHYvgAfZ3gvxIDJi3quBVO_5Lq_pDUOKdNw",
    "google-site-verification=8gUY1AtsZ3BzLVSHLSv3wXIE8MpnWrGgVrmvVxM1MjE",
    "abuseipdb-verification=D4c0J6WF"
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
      "serial": 8585147015611556010611612945268820675,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084e657720596f726b3111300f060355040713084e657720596f726b31323030060355040a13294173736f63696174696f6e20666f7220436f6d707574696e67204d616368696e6572792c20496e632e3112301006035504030c092a2e61636d2e6f7267",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260401000000",
      "not_after": "20261016235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/live-search",
      "/404",
      "/landing-page-documents/",
      "/referenced-ctalist/",
      "/Member/",
      "/history-acm-org/",
      "/amturing-acm-org/",
      "/student-chapter-excellence-awards/",
      "/chapters/students/excellence-awards/",
      "/conferences/non-acm-events",
      "/conferences/conference-events",
      "/chapters/local-activities",
      "/award_winners",
      "/chapters.html",
      "/amg.html"
    ]
  },
  "x12": {
    "status": 403
  },
  "x13": {
    "root_status": 403,
    "http_status": 301,
    "p404_status": 403,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "hsts": "max-age=0",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 403
  },
  "elapsed_s": 7.0,
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
