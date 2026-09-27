# Security Audit Report — eventim.de

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://eventim.de/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | eventim.de |
| Test date | 2026-09-27 02:28 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 4, Info: 16)

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
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 17 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 18 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 19 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 20 | info | HTML15 | Root document has no <html lang> declaration | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
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
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

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
- **Detail:** Apex TXT records with verification/token content: shopify-verification-code=lq13eQZumd4BKaWYIyggeIVKHPtwvs; google-site-verification=s_J1gtfGgebN6_0ZHBAGpeuFpD3Jz9qK7wjc8wTeC6k; stripe-verification=AF5DD7294082E8A97C22C5A02EB429FA306374CFA56E6B747A47A6F83525
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of eventim.de has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.210.215.203 carries PTR a23-210-215-203.deploy.static.akamaitechnologies.com. for eventim.de.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xk2fcsh6vs22mp.html -> 403; error page/headers match: Akamai.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 17. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for eventim.de, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 18. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on eventim.de is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 19. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on eventim.de identify the edge as Akamai; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 20. [INFO] Root document has no <html lang> declaration (`HTML15`)

- **CWE:** CWE-200
- **Detail:** The root document of eventim.de declares <html> without a lang attribute; language is a baseline accessibility/internationalization signal that assistive tech and tooling rely on.
- **Recommendation:** Add lang to the <html> element.

## Evidence (raw response observations)

```json
{
  "domain": "eventim.de",
  "dns": {
    "a": [
      "23.210.215.203",
      "23.210.215.208"
    ],
    "aaaa": [
      "2600:1417:76::17d2:d7cb",
      "2600:1417:76::17d2:d7d0"
    ],
    "cname": null,
    "mx": [
      "mxb-0072c901.gslb.pphosted.com (pref 10)",
      "mxa-0072c901.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "a1-222.akam.net.",
      "a13-67.akam.net.",
      "a6-65.akam.net.",
      "a3-64.akam.net.",
      "a12-66.akam.net.",
      "a10-65.akam.net."
    ],
    "caa": [],
    "spf": [
      "shopify-verification-code=lq13eQZumd4BKaWYIyggeIVKHPtwvs",
      "_x0m99eexri0eo0jy3oqceax1lsautou",
      "google-site-verification=s_J1gtfGgebN6_0ZHBAGpeuFpD3Jz9qK7wjc8wTeC6k",
      "stripe-verification=AF5DD7294082E8A97C22C5A02EB429FA306374CFA56E6B747A47A6F83525EF4A",
      "jamf-site-verification=1mGbPXJW8-h7z9OTyuY-fg",
      "/dEZPSK+nF6rq7laQtMlbSXm01b+++Hl68NWiIIHiPIqS6GcjfZ+UaCfY1NgsYFDwHRno0/1a6DF6lfHx+idXw==",
      "1password-site-verification=ZI4O7DDYBRHUVMKUSTM6RJ7RN4",
      "onetrust-domain-verification=f6f96e3b0d334cc78bb3372701e00911",
      "_zyobswc54veb1thhshrfrn0eyyjrziu",
      "google-site-verification=F_ofMVEQrI9dLToCH3W8TD_pw5_J6-c8SzSxA8cC80Q",
      "apple-domain-verification=GOce9gVZOyTRkab6",
      "1password-site-verification=LFNAA7NAAZFULMFWJPXE5Q5JEQ",
      "MS=ms55918227",
      "mandrill_verify.RGbU4FqxJLlLqTEzZtTrXA",
      "openai-domain-verification=dv-LWOQZyUBe4v4LUx1ryWVZhwi",
      "_zcu8mukkq7g0jjxpsz7ciwpnrsh11ed",
      "mixpanel-domain-verify=cafd88b1-917f-4159-bc47-b1c7052ff275",
      "sending_domain1071343=7651b6fc060ab34ceea035d6cd9b65c21bc0e6c6ced9cdb9734e5b6fd53cd125",
      "1password-site-verification=5EMB7KTOU5E5LF4C27XXNT4JRM",
      "bw=Y2eRcRZKeuigrljql8ybFRciwBnMGGAfYm9hXTK35nip",
      "dell-technologies-domain-verification=eventim.de_0294e23e-488b-47ff-a6f7-d1fe73b1524c_1756375967",
      "facebook-domain-verification=gor6r8bwyofwjen3uatmmco60ne6cf",
      "miro-verification=2ae9c59047c26ca58554168f7baccaf715e607b4",
      "teamviewer-sso-verification=0775685533454aaf911ae2316becb5e1",
      "atlassian-domain-verification=sRxNCVi7vbQFvIQOy3yD5wRhIsBfb/nlTssiVfRTkqhr2bN35VWGJsPaLo/7hvER",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "_an4lngigs1w4891di1fcerxtiwz8kld"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com,mailto:dmarc@eventim.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:dmarc@eventim.com; pct=100;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=eventim.de",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Sep 16 11:37:02 2026 GMT",
    "notAfter": "Dec 15 11:37:01 2026 GMT",
    "san": [
      "billetlugen.dk",
      "cts.eventim.bg",
      "cts.eventim.hr",
      "cts.eventim.hu",
      "cts.eventim.ro",
      "cts.eventim.si",
      "entradas.com",
      "eventim.ca",
      "eventim.co.il",
      "eventim.co.uk",
      "eventim.com",
      "eventim.com.ar",
      "eventim.com.br",
      "eventim.cz",
      "eventim.de",
      "eventim.fi",
      "eventim.fr",
      "eventim.hr",
      "eventim.nl",
      "eventim.no",
      "eventim.pl",
      "eventim.pt",
      "eventim.ro",
      "eventim.se",
      "eventim.si",
      "eventim.sk",
      "eventimsports.com",
      "eventimsports.de",
      "fansale.ch",
      "fansale.co.uk",
      "fansale.de",
      "fansale.dk",
      "fansale.fi",
      "fansale.no",
      "fansale.se",
      "getgo.de",
      "lippu.fi",
      "paytoll.eu",
      "ticket-shop.de",
      "ticketcorner.ch",
      "ticketone.it",
      "ticketonline.de",
      "tickets.bimot.co.il",
      "ticketshop.de",
      "www.eventim.fi"
    ],
    "days_left": 79,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.210.215.203",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.eventim.de",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 200,
    "/security.txt": 403,
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "shopify-verification-code=lq13eQZumd4BKaWYIyggeIVKHPtwvs",
    "google-site-verification=s_J1gtfGgebN6_0ZHBAGpeuFpD3Jz9qK7wjc8wTeC6k",
    "stripe-verification=AF5DD7294082E8A97C22C5A02EB429FA306374CFA56E6B747A47A6F83525",
    "jamf-site-verification=1mGbPXJW8-h7z9OTyuY-fg",
    "1password-site-verification=ZI4O7DDYBRHUVMKUSTM6RJ7RN4"
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
      "aia_ocsp": null,
      "serial": 528893314995830080220914341825329004861097,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://yr1.c.lencr.org/42.crl"
      ],
      "san": [
        "billetlugen.dk",
        "cts.eventim.bg",
        "cts.eventim.hr",
        "cts.eventim.hu",
        "cts.eventim.ro",
        "cts.eventim.si",
        "entradas.com",
        "eventim.ca",
        "eventim.co.il",
        "eventim.co.uk",
        "eventim.com",
        "eventim.com.ar",
        "eventim.com.br",
        "eventim.cz",
        "eventim.de",
        "eventim.fi",
        "eventim.fr",
        "eventim.hr",
        "eventim.nl",
        "eventim.no"
      ],
      "subject_dn": "311330110603550403130a6576656e74696d2e6465",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231",
      "not_before": "20260916113702",
      "not_after": "20261215113701"
    }
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a23-210-215-203.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://yr1.c.lencr.org/42.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 403
  },
  "x16": {
    "root_status": 403,
    "cdn": [
      "Akamai"
    ]
  },
  "x17": {},
  "elapsed_s": 11.0,
  "rechecked": "2026-09-27 02:16 UTC"
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
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
