# Security Audit Report — snapchat.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://snapchat.com/ |
| Bug bounty program | Snapchat |
| Listed scope domain | snapchat.com |
| Test date | 2026-09-26 23:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 5, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 19 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 20 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 20 days (notAfter Oct 16 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: canva-site-verification=blQT_XTqOBtV9rXZPJYTvg; openai-domain-verification=dv-qRVXfFNUY6fVpEXy5skTuRnd; google-site-verification=Eo-pwhENGkrh6E74BafjjhjK4dGk0B1Tv12bUn5UPSY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 61 disallow path(s), e.g. /verificationofemployment, /static_files/deletion_request.pdf, /static/gla/, /invite/, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.149.46.130 carries PTR 130.46.149.34.bc.googleusercontent.com. for snapchat.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on snapchat.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for snapchat.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The snapchat.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 19. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on snapchat.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 20. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on snapchat.com lists 12 <loc> URL(s) across 13 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "snapchat.com",
  "dns": {
    "a": [
      "34.149.46.130"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx3.googlemail.com (pref 50)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 40)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-530.awsdns-02.net.",
      "ns-1892.awsdns-44.co.uk.",
      "ns-220.awsdns-27.com.",
      "ns-1468.awsdns-55.org."
    ],
    "caa": [],
    "spf": [
      "canva-site-verification=blQT_XTqOBtV9rXZPJYTvg",
      "TAILSCALE-bAU9TfNGoz4iD4hioxcp",
      "openai-domain-verification=dv-qRVXfFNUY6fVpEXy5skTuRnd",
      "google-site-verification=Eo-pwhENGkrh6E74BafjjhjK4dGk0B1Tv12bUn5UPSY",
      "krea-verification=b6d6daff3226c8bdfa48187fc11d00d721aa8ed08878659c1ee40b73104da392",
      "pardot_346841_*=de35b68dd0e766cfba41cc068f8b424a6ce7ac92052cb30fe9a4a55ac88a0583",
      "autodesk-domain-verification=S6bhF0FKFgY957I6SLKW",
      "arcules-domain-verification=kEVxs7LUGURYpDYCelXSgp02wBuL6A82zKQMMw8lGzR",
      "MS=255BA8D56417782169DA12894F5A53521A65F7F2",
      "smartsheet-site-validation=dw0MifosV2eGg1JG9ZTtiGpSGNuiqybJ",
      "parallels-domain-verification=58886ce349db42dfbfb94599884a65ead28c9543a5c947df8fc596694c81eba6",
      "google-site-verification=tHsCd67KywyjuYvvr7V9I4PFTXXznN48z-jvPm20yBE",
      "onetrust-domain-verification=faca66624bfe477db467f97c7583b7ba",
      "yahoo-verification-key=xUKCyvTR9ya3lyjYFuWPLGfSFLC/5C0y2txg4crwEbw=",
      "google-site-verification=eye-nbnjs2nv4ll-8vo9ijpgkdvyrs8h2j_1bzkp-t0",
      "apple-domain-verification=hAi0YbrGnN5ny4wm",
      "yahoo-verification-key=T1Hbkkgw9crF2nr93/q/Zb+IzUPXWSZEmqh1G5VCds0=",
      "yahoo-verification-key=hbsSgAjgGym9aXgBQSAX5APr5RKaTlmtGlqFTCMIEXo=",
      "atlassian-domain-verification=t2mP/OxdJvz/S28h3o/5egOc105U1aKneVRngll9cfhI4Un8gQxYaQjIPVaKpKpT",
      "atlassian-domain-verification=P7v4/0SuI03V2xsQfPTYYZLbRwBN1QkqBg4E/zqmJVvyWKraMaJRbamwkK2vWrx0",
      "docker-verification=2351a4bf-bc17-42ff-8fca-521e86376280",
      "snapchat-domain-verification-zx5hhx=Q7zL5FmxwFKyQWOuKc4blSh7k",
      "dropbox-domain-verification=oypu2eeh56yg",
      "censys-domain-verification=9U1U43sYXK5eDeoXbt8WB090FMa8IystN7iMx0waR50S",
      "google-site-verification=bgzZGVgOr4py5YcPQHFZYJFJbarBD_shCxIvjQS1grI",
      "logmein-verification-code=fd76bf0c-ec62-4587-bb84-4511579e41f4",
      "adobe-idp-site-verification=1b7089e1333b1302c4f425ff60baae967ac377d76fb6aa7bb61c9f0282fd664d",
      "miro-verification=b341b9dfb098865b7517b6c662e94e5538603be4",
      "nyy2gbb26yz2kntxp7ynycsvql0swn71",
      "_hh9zpxhf35itout7v7mwibqktr44s3s",
      "jamf-site-verification=_Y2-z-8UweEkmdMZsNbTJg",
      "https://issues.sonatype.org/browse/OSSRH-54682",
      "hubspot-developer-verification=Zjk1NTNlNmYtODAxNi00YzNhLTgzNGEtY2JlNWQyNGRhZmFk",
      "3ae8f0a14f7a4c98a9023fe8947467bd",
      "anthropic-domain-verification-kg6835=FrP90V31rmTTa7Cu3plqLLMEx",
      "segment-site-verification=e6U89hyQcmGvDFTApWYKvbj7NFSMu8zj",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:aspmx.pardot.com -all",
      "shopify-verification-code=6AbSmjYHNX0fOCzG0oBfncSsCVJfgT",
      "atlassian-domain-verification=TH6BFQJRvZM36e0pNbXcEI/RpTrqBb2JDxzoBsBLa3RajLrpmc6pK6Quau40P7oa",
      "google-site-verification=Ro2UVvcjx7U_bRc-_HAUELMOxwk4Y6n5FX9FQt8BDsQ",
      "onetrust-domain-verification=32eb1654587e494fbd3b4f8a54a6b57f",
      "linear-domain-verification=v82bwvzkpw5w"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-report@snapchat.com; rf=afrf; pct=100; ri=86400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Santa Monica, organizationName=Snap Inc., commonName=*.snap.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Apr  1 00:00:00 2026 GMT",
    "notAfter": "Oct 16 23:59:59 2026 GMT",
    "san": [
      "*.snap.com",
      "*.snapchat.com",
      "*.ats.snapchat.com",
      "*.snapads.com",
      "*.snap-dev.net",
      "*.snappcm.com",
      "*.snappcm-dev.com",
      "*.snapar.com",
      "*.snapkit.com",
      "*.arcadiacreativestudio.com",
      "*.bitmoji.com",
      "*.lensstudio.com",
      "*.pixy.com",
      "*.spectacles.com",
      "*.api.snapchat.com",
      "*.sc-gw-dev.snapchat.com",
      "*.saturn.live",
      "*.specs.com",
      "*.api.specs.com",
      "snap.com",
      "snapchat.com",
      "ats.snapchat.com",
      "snapads.com",
      "snap-dev.net",
      "snappcm.com",
      "snappcm-dev.com",
      "snapar.com",
      "snapkit.com",
      "arcadiacreativestudio.com",
      "bitmoji.com",
      "lensstudio.com",
      "pixy.com",
      "spectacles.com",
      "api.snapchat.com",
      "sc-gw-dev.snapchat.com",
      "saturn.live",
      "specs.com"
    ],
    "days_left": 20,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.149.46.130",
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
      "origin": "https://sub.snapchat.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://snapchat.com:443/"
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
    "/.well-known/security.txt": 200,
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
    "canva-site-verification=blQT_XTqOBtV9rXZPJYTvg",
    "openai-domain-verification=dv-qRVXfFNUY6fVpEXy5skTuRnd",
    "google-site-verification=Eo-pwhENGkrh6E74BafjjhjK4dGk0B1Tv12bUn5UPSY",
    "krea-verification=b6d6daff3226c8bdfa48187fc11d00d721aa8ed08878659c1ee40b73104da3",
    "autodesk-domain-verification=S6bhF0FKFgY957I6SLKW"
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
      "serial": 5533853326838885267031333254921031307,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e6961311530130603550407130c53616e7461204d6f6e69636131123010060355040a1309536e617020496e632e3113301106035504030c0a2a2e736e61702e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260401000000",
      "not_after": "20261016235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/verificationofemployment",
      "/static_files/deletion_request.pdf",
      "/static/gla/",
      "/invite/",
      "/",
      "/",
      "/getreplies",
      "/explore/",
      "/getreplies",
      "/explore/",
      "/getreplies",
      "/explore/",
      "/getreplies",
      "/explore/",
      "/getreplies"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "130.46.149.34.bc.googleusercontent.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.snapchat.com:443/",
    "http_status": 301,
    "p404_status": 301,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "security_txt": "/.well-known/security.txt",
    "sitemap": {
      "urls": 12,
      "indexes": 13
    },
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "elapsed_s": 12.4,
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
