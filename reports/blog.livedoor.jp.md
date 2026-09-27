# Security Audit Report — blog.livedoor.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blog.livedoor.jp/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | blog.livedoor.jp |
| Test date | 2026-09-27 01:11 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 1, Low: 1, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 3 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 4 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 5 | info | RD3 | Plain-HTTP root sets cookies without redirecting to HTTPS | CWE-319 |
| 6 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 7 | info | TLS20 | Short certificate serial number (< 64 bits) | CWE-347 |
| 8 | info | TLS21 | Self-signed certificate served as leaf | CWE-295 |
| 9 | low | TLS22 | Leaf certificate asserts Basic Constraints CA:TRUE | CWE-295 |
| 10 | info | CT1 | 1 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate chain not trusted (`TLS1`)

- **CWE:** CWE-298
- **Detail:** TLS verification failed: CERTIFICATE_VERIFY_FAILED
- **Recommendation:** Fix the certificate chain (missing intermediate / issuer).

### 3. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=0h1iw9FD_Fh2-dKG1EaBOAguW9D69GdS2NJZc-AFAlM; _globalsign-domain-verification=Mah0BlTjp06Wm4mIqByl9THcQYJ4ntRwaKNrN7LQ_Y
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 4. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of blog.livedoor.jp has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 5. [INFO] Plain-HTTP root sets cookies without redirecting to HTTPS (`RD3`)

- **CWE:** CWE-319
- **Detail:** http://blog.livedoor.jp/ answered 200 (no 301/308 to HTTPS) and set cookie(s) ldblog_u, ldsuid over plaintext.
- **Recommendation:** Redirect plain HTTP to HTTPS and/or add the Secure attribute to cookies.

### 6. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for blog.livedoor.jp; apex livedoor.jp, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 7. [INFO] Short certificate serial number (< 64 bits) (`TLS20`)

- **CWE:** CWE-347
- **Detail:** Leaf certificate of blog.livedoor.jp carries a 64-bit serial (0xf16962d6733e5166); serials under 64 bits make collision attacks (2008 CERTEX) feasible and are no longer recommended by the CA/B Forum.
- **Recommendation:** Request certificates with 128-bit serial numbers.

### 8. [INFO] Self-signed certificate served as leaf (`TLS21`)

- **CWE:** CWE-295
- **Detail:** Leaf certificate of blog.livedoor.jp has issuer DN equal to its subject DN (self-signed); strict TLS clients reject it unless explicitly trusted.
- **Recommendation:** Use a CA-issued certificate, or confirm the self-signed deployment is intentional.

### 9. [LOW] Leaf certificate asserts Basic Constraints CA:TRUE (`TLS22`)

- **CWE:** CWE-295
- **Detail:** Leaf certificate of blog.livedoor.jp is marked CA:TRUE, which would let it certify other certificates.
- **Recommendation:** Reissue with CA:FALSE for end-entity certificates.

### 10. [INFO] 1 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: blog.livedoor.jp
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "blog.livedoor.jp",
  "dns": {
    "a": [
      "147.92.146.242"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [
      "google-site-verification=0h1iw9FD_Fh2-dKG1EaBOAguW9D69GdS2NJZc-AFAlM",
      "_globalsign-domain-verification=Mah0BlTjp06Wm4mIqByl9THcQYJ4ntRwaKNrN7LQ_Y"
    ],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "untrusted",
    "version": null,
    "cipher": null,
    "subject": null,
    "issuer": null,
    "notBefore": null,
    "notAfter": null,
    "san": null,
    "error": "CERTIFICATE_VERIFY_FAILED",
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "147.92.146.242",
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
    "status": 200
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "source": "certspotter",
    "count": 1,
    "notable": [
      "blog.livedoor.jp"
    ],
    "sample": [
      "blog.livedoor.jp"
    ]
  },
  "apex_txt": [
    "google-site-verification=0h1iw9FD_Fh2-dKG1EaBOAguW9D69GdS2NJZc-AFAlM",
    "_globalsign-domain-verification=Mah0BlTjp06Wm4mIqByl9THcQYJ4ntRwaKNrN7LQ_Y"
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
      "serial": 17395543708891238758,
      "cert_version": 3,
      "bc_ca": true,
      "bc_pathlen": null,
      "crl_urls": null,
      "subject_dn": "310b3009060355040613022d2d3112301006035504080c09536f6d6553746174653111300f06035504070c08536f6d654369747931193017060355040a0c10536f6d654f7267616e697a6174696f6e311f301d060355040b0c16536f6d654f7267616e697a6174696f6e616c556e6974311e301c06035504030c156c6f63616c686f73742e6c6f63616c646f6d61696e3129302706092a864886f70d010901161a726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e",
      "issuer_dn": "310b3009060355040613022d2d3112301006035504080c09536f6d6553746174653111300f06035504070c08536f6d654369747931193017060355040a0c10536f6d654f7267616e697a6174696f6e311f301d060355040b0c16536f6d654f7267616e697a6174696f6e616c556e6974311e301c06035504030c156c6f63616c686f73742e6c6f63616c646f6d61696e3129302706092a864886f70d010901161a726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e",
      "not_before": "20200417054914",
      "not_after": "20210417054914"
    }
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='blog.livedoor.jp', port=443): "
  },
  "x13": {
    "root_error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='blog.livedoor.jp', port=443): ",
    "http_status": 200,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "serial_bits": 64,
    "root_error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='blog.livedoor.jp', port=443): "
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='blog.livedoor.jp', port=443): "
  },
  "x16": {
    "root_error": "SSLError(MaxRetryError(\"HTTPSConnectionPool(host='blog.livedoor.jp', port=443): "
  },
  "elapsed_s": 4.5,
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
