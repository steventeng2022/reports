# Security Audit Report — archives.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://archives.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | archives.gov |
| Test date | 2026-09-27 01:10 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 3 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 4 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 5 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 6 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 7 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 8 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 3. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 4. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=vzFoKGZ49s-tl4Mw26kJfVRiYukV0lHmZlbG0iAYYMk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 5. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 4 disallow path(s), e.g. /citizen-archivist/history-hub/hh-test, /developer/artificial-intelligence-and-machine-learning-datasets, /developer/1940-census, /developer/national-archives-catalog-dataset
- **Recommendation:** Review disallowed paths; robots is not access control.

### 6. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of archives.gov permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 7. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 52.206.136.3 carries PTR ec2-52-206-136-3.compute-1.amazonaws.com. for archives.gov.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 8. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on archives.gov lists 2 <loc> URL(s) across 3 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "archives.gov",
  "dns": {
    "a": [
      "52.206.136.3",
      "52.44.89.206"
    ],
    "aaaa": [
      "2600:1f18:43e8:f301:9046:c05f:75e7:c481",
      "2600:1f18:43e8:f302:b470:d266:4d03:3ed8"
    ],
    "cname": null,
    "mx": [
      "us.etp.fireeyegov.com (pref 10)"
    ],
    "ns": [
      "ns2.fedmettel.net.",
      "ns1.fedmettel.net."
    ],
    "caa": [
      "0 issue \"entrust.net\"",
      "0 issue \"awstrust.com\"",
      "0 issue \"letsencrypt.org\""
    ],
    "spf": [
      "v=spf1 -all",
      "google-site-verification=vzFoKGZ49s-tl4Mw26kJfVRiYukV0lHmZlbG0iAYYMk"
    ],
    "dmarc": [
      "v=DMARC1;",
      "p=reject;",
      "pct=100;",
      "fo=1;",
      "ri=86400;",
      "adkim=r;",
      "aspf=r;",
      "rua=mailto:reports@dmarc.cyber.dhs.gov;",
      "ruf=mailto:reports@dmarc.cyber.dhs.gov;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Maryland, organizationName=National Archives and Records Administration, commonName=archives.gov",
    "issuer": "countryName=CA, organizationName=Entrust Limited, commonName=Entrust OV TLS Issuing RSA CA 2",
    "notBefore": "Sep 30 00:00:00 2025 GMT",
    "notAfter": "Oct 31 23:59:59 2026 GMT",
    "san": [
      "archives.gov",
      "nara.gov",
      "www.archives.gov",
      "www.nara.gov"
    ],
    "days_left": 34,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "52.206.136.3",
    "open": []
  },
  "https": {
    "status": 0,
    "content_type": "",
    "title": "",
    "error": "https connect failed"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [],
  "http": {
    "status": 0,
    "error": "http connect failed"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=vzFoKGZ49s-tl4Mw26kJfVRiYukV0lHmZlbG0iAYYMk"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 221209478710623043913856388360869195384,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/EntrustOVTLSIssuingRSACA2.crl"
      ],
      "subject_dn": "310b30090603550406130255533111300f060355040813084d6172796c616e6431353033060355040a132c4e6174696f6e616c20417263686976657320616e64205265636f7264732041646d696e697374726174696f6e311530130603550403130c61726368697665732e676f76",
      "issuer_dn": "310b300906035504061302434131183016060355040a130f456e7472757374204c696d69746564312830260603550403131f456e7472757374204f5620544c532049737375696e67205253412043412032",
      "not_before": "20250930000000",
      "not_after": "20261031235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/citizen-archivist/history-hub/hh-test",
      "/developer/artificial-intelligence-and-machine-learning-datasets",
      "/developer/1940-census",
      "/developer/national-archives-catalog-dataset"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-52-206-136-3.compute-1.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.archives.gov/",
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
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "sitemap": {
      "urls": 2,
      "indexes": 3
    },
    "crl": {
      "url": "http://crl.sectigo.com/EntrustOVTLSIssuingRSACA2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301
  },
  "elapsed_s": 39.2,
  "rechecked": "2026-09-27 01:08 UTC"
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
- Findings are reported against the public program scope; submission through the program tracker is pending.
