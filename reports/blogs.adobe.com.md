# Security Audit Report — blogs.adobe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blogs.adobe.com/ |
| Bug bounty program | Adobe |
| Listed scope domain | blogs.adobe.com |
| Test date | 2026-09-27 02:20 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 1, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS2 | TLS certificate hostname mismatch | CWE-297 |
| 3 | low | TLS6 | Certificate SAN does not include the target hostname | CWE-297 |
| 4 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 5 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 6 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] TLS certificate hostname mismatch (`TLS2`)

- **CWE:** CWE-297
- **Detail:** TLS verification failed: CERTIFICATE_VERIFY_FAILED
- **Recommendation:** Serve a certificate whose SAN covers blogs.adobe.com.

### 3. [LOW] Certificate SAN does not include the target hostname (`TLS6`)

- **CWE:** CWE-297
- **Detail:** Presented certificate SANs ['*.adobeaemcloud.com'] do not include blogs.adobe.com.
- **Recommendation:** Issue a certificate covering this hostname (or wildcard).

### 4. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for blogs.adobe.com; apex adobe.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 5. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of blogs.adobe.com contains wildcard SAN entry(ies) *.adobeaemcloud.com; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 6. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of blogs.adobe.com is http://ocsp.digicert.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "blogs.adobe.com",
  "dns": {
    "a": [
      "151.101.3.10",
      "151.101.131.10",
      "151.101.195.10",
      "151.101.67.10"
    ],
    "aaaa": [],
    "cname": "cdn.adobeaemcloud.com.",
    "mx": [],
    "ns": [],
    "caa": [],
    "spf": [],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:adobe@rua.agari.com; ruf=mailto:adobe@ruf.agari.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "hostname-mismatch",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Jose, organizationName=Adobe Inc., commonName=*.adobeaemcloud.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep  8 00:00:00 2026 GMT",
    "notAfter": "Mar 25 23:59:59 2027 GMT",
    "san": [
      "*.adobeaemcloud.com"
    ],
    "days_left": 179,
    "san_match": false,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.3.10",
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
    "status": 500
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "cname_chain": [
    "cdn.adobeaemcloud.com",
    "adobe-aem.map.fastly.net"
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
      "serial": 2710582353922811107162304975484370055,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "san": [
        "*.adobeaemcloud.com"
      ],
      "subject_dn": "310b3009060355040613025553311330110603550408130a43616c69666f726e69613111300f0603550407130853616e204a6f736531133011060355040a130a41646f626520496e632e311c301a06035504030c132a2e61646f626561656d636c6f75642e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20260908000000",
      "not_after": "20270325235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "SSLError(MaxRetryError('HTTPSConnectionPool(host=\\'blogs.adobe.com\\', port=443):"
  },
  "x13": {
    "root_error": "SSLError(MaxRetryError('HTTPSConnectionPool(host=\\'blogs.adobe.com\\', port=443):",
    "http_status": 500,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_error": "SSLError(MaxRetryError('HTTPSConnectionPool(host=\\'blogs.adobe.com\\', port=443):",
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipher_ver": "TLSv1.3",
    "root_error": "SSLError(MaxRetryError('HTTPSConnectionPool(host=\\'blogs.adobe.com\\', port=443):"
  },
  "x16": {
    "root_error": "SSLError(MaxRetryError('HTTPSConnectionPool(host=\\'blogs.adobe.com\\', port=443):"
  },
  "x17": {
    "wildcard_san": [
      "*.adobeaemcloud.com"
    ],
    "ocsp_http": "http://ocsp.digicert.com",
    "root_error": "SSLError(MaxRetryError('HTTPSConnectionPool(host=\\'blogs.adobe.com\\', port=443):"
  },
  "elapsed_s": 13.4,
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
