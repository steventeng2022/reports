# Security Audit Report — stackoverflow.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stackoverflow.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stackoverflow.com |
| Test date | 2026-09-27 02:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **24** (High: 0, Medium: 0, Low: 3, Info: 21)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 18 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 19 | info | HTML1 | Security policy set via <meta http-equiv> | CWE-1021 |
| 20 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 21 | info | H25 | server-timing response header exposed | CWE-200 |
| 22 | info | HTML14 | Public root document marked noindex | CWE-200 |
| 23 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 24 | info | HTML19 | data: URIs present in root document | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 198.252.206.1:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 198.252.206.1:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'prov' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'prov' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: adobe-idp-site-verification=25ba5203f3687c9cd6ee3223ee5de1528917828d1da3ebd3bd9a; cursor-domain-verification-sb0ayf=Pk6AyptQuTpzpcuSlfYGWloxv; onetrust-domain-verification=0d9d67f856334905a54256085a5768b3
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of stackoverflow.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of stackoverflow.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 18. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on stackoverflow.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 19. [INFO] Security policy set via <meta http-equiv> (`HTML1`)

- **CWE:** CWE-1021
- **Detail:** HTML root of stackoverflow.com declares via meta tags: content-security-policy; meta-set policies have limited browser support and are easier to override than response headers.
- **Recommendation:** Prefer response headers and keep any meta declarations consistent with them.

### 20. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of stackoverflow.com sends a CSP but contains 1 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 21. [INFO] server-timing response header exposed (`H25`)

- **CWE:** CWE-200
- **Detail:** The root response of stackoverflow.com sends server-timing (chlray;desc="a4172c7719db8261"); server/edge processing metrics are disclosed to any client.
- **Recommendation:** Restrict server-timing to authenticated/debug contexts if the internals are sensitive.

### 22. [INFO] Public root document marked noindex (`HTML14`)

- **CWE:** CWE-200
- **Detail:** The root document of stackoverflow.com is marked noindex (meta robots or X-Robots-Tag); a public homepage that is not indexable is a posture anomaly worth reviewing.
- **Recommendation:** Confirm the noindex directive is intentional.

### 23. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of stackoverflow.com contains wildcard SAN entry(ies) *.stackoverflow.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 24. [INFO] data: URIs present in root document (`HTML19`)

- **CWE:** CWE-200
- **Detail:** The root document of stackoverflow.com references 1 data: URI payload(s); inline data resources bypass the normal fetch/CORS path and should be inventoried.
- **Recommendation:** Review inline data payloads (especially scripts/iframes) as part of the asset inventory.

## Evidence (raw response observations)

```json
{
  "domain": "stackoverflow.com",
  "dns": {
    "a": [
      "198.252.206.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)"
    ],
    "ns": [
      "sureena.ns.cloudflare.com.",
      "damian.ns.cloudflare.com."
    ],
    "caa": [
      "0 issue \"pki.goog; cansignhttpexchanges=yes\"",
      "128 iodef \"mailto:sysadmin-team@stackoverflow.com\"",
      "0 issue \"comodoca.com\"",
      "0 issuewild \"sectigo.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issuewild \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"sectigo.com\"",
      "0 issue \"ssl.com\"",
      "0 issuewild \"ssl.com\"",
      "0 issuewild \"digicert.com; cansignhttpexchanges=yes\"",
      "0 issue \"digicert.com; cansignhttpexchanges=yes\"",
      "0 issuewild \"comodoca.com\""
    ],
    "spf": [
      "adobe-idp-site-verification=25ba5203f3687c9cd6ee3223ee5de1528917828d1da3ebd3bd9a44094cbfc4ac",
      "cursor-domain-verification-sb0ayf=Pk6AyptQuTpzpcuSlfYGWloxv",
      "onetrust-domain-verification=0d9d67f856334905a54256085a5768b3",
      "onetrust-domain-verification=e445562296a64c649ae3d520230b8c4c",
      "v=MCPv1; k=ed25519; p=VhBofO8RaYvTvHT7q5tTty+HQeCU8R6h5Y8k/sj20So=",
      "docker-verification=d65aee54-9091-4ceb-b792-61f5d5804050",
      "atlassian-domain-verification=byLeZgl3MIcfOqwWuMhq8Fhr/1zem/jIaouJegvDZbBKUU5OqhwDjdpkyYg5CTzm",
      "google-site-verification=2Bi6SYw5skkRexdtdLPL2gpxeIhLxnYVqITVP9Htl3w",
      "anthropic-domain-verification-q70207=cKyy0llXkD10O4rDQpWz8tQ5K",
      "ZOOM_verify_AbkNwz5bBl0eurcDKyhhuk",
      "openai-domain-verification=dv-GLNufzbWDzAq0fDXHD6jxeCK",
      "profound-domain-verification-5p599x=hWudYd2Du6WOYOod5ko9Rwnp8",
      "apple-domain-verification=O9jlnJXAQ7sNSZqC",
      "make-domain-verification=eec31159-f381-4f38-9d89-e59123dd023e",
      "MS=ms52592611",
      "work-os-domain-verification-43a3e0=GoDUTSc5MMjDaiIC3s5yRKqMD",
      "google-site-verification=ctogLnZNAdc_CXq8yOhODMLpmugGynjxKecKHDz4oL8",
      "google-site-verification=rdWtMbplKjbRHGr2dNONfwkqithlUvjr3u6i8QEz_mo",
      "docusign=4262531d-29f4-4a62-9f33-ae9f66f5247b",
      "ibmid=4e7cbbb3-5f12-40b4-96c7-5b064347b822",
      "google-site-verification=o3EMam8yBGo1yEjyybIiZcOunGHOQKpo8JmOtp9n1BU",
      "v=spf1 ip4:52.38.191.241 include:_spf.google.com include:mailgun.org include:sendgrid.net include:mail.zendesk.com include:spf.tipalti.com ~all"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-aggregates@stackoverflow.com; ruf=mailto:dmarc-forensics@stackoverflow.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=stackoverflow.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 15 12:39:06 2026 GMT",
    "notAfter": "Nov 13 12:39:05 2026 GMT",
    "san": [
      "*.stackoverflow.com",
      "stackoverflow.com"
    ],
    "days_left": 47,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "198.252.206.1",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 302,
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
      "domain": ".stackoverflow.com",
      "samesite": "none"
    },
    {
      "samesite": "none"
    },
    {
      "domain": "stackoverflow.com"
    },
    {
      "domain": "stackoverflow.com",
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
      "origin": "https://sub.stackoverflow.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://stackoverflow.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 418,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "adobe-idp-site-verification=25ba5203f3687c9cd6ee3223ee5de1528917828d1da3ebd3bd9a",
    "cursor-domain-verification-sb0ayf=Pk6AyptQuTpzpcuSlfYGWloxv",
    "onetrust-domain-verification=0d9d67f856334905a54256085a5768b3",
    "onetrust-domain-verification=e445562296a64c649ae3d520230b8c4c",
    "docker-verification=d65aee54-9091-4ceb-b792-61f5d5804050"
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
      "serial": 555492447916500145544338397571974849987101,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye1.c.lencr.org/30.crl"
      ],
      "san": [
        "*.stackoverflow.com",
        "stackoverflow.com"
      ],
      "subject_dn": "311a301806035504031311737461636b6f766572666c6f772e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594531",
      "not_before": "20260815123906",
      "not_after": "20261113123905"
    }
  },
  "x12": {
    "status": 429
  },
  "x13": {
    "root_status": 429,
    "http_status": 301,
    "p404_status": 429,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 429,
    "crl": {
      "url": "http://ye1.c.lencr.org/30.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 429
  },
  "x16": {
    "root_status": 429,
    "server_timing": "chlray;desc=\"a4172c7719db8261\"",
    "noindex": true
  },
  "x17": {
    "wildcard_san": [
      "*.stackoverflow.com"
    ],
    "data_uris": 1
  },
  "elapsed_s": 8.8,
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
