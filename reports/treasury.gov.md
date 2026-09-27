# Security Audit Report — treasury.gov

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://treasury.gov/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | treasury.gov |
| Test date | 2026-09-27 02:47 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 5, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TLS9 | Neither TLS 1.2 nor 1.3 handshake succeeded | CWE-327 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 16 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |
| 17 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 18 | info | H22 | Server answers with HTTP/1.0 | CWE-319 |
| 19 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 20 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Neither TLS 1.2 nor 1.3 handshake succeeded (`TLS9`)

- **CWE:** CWE-327
- **Detail:** Only legacy protocols (if any) could complete a handshake.
- **Recommendation:** Upgrade TLS configuration.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Apex TXT records with verification/token content: openai-domain-verification=dv-URa4cQaZUt7TuzEHuA4cT3QK; box-domain-verification=907e0bde6b92f9b565218a2fcba8a7adaa9501f4838624d4efe57f69; apple-domain-verification=Agf1IhJ01yW5m4ka
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but treasury.gov is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for treasury.gov, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 16. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The treasury.gov certificate lists an AIA OCSP responder (http://ocsp.sectigo.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 17. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on treasury.gov has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of treasury.gov.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 18. [INFO] Server answers with HTTP/1.0 (`H22`)

- **CWE:** CWE-319
- **Detail:** The root response of treasury.gov uses HTTP/1.0, the oldest version still in use; modern sites should serve HTTP/1.1 or 2.
- **Recommendation:** Serve HTTP/1.1 or HTTP/2 from the edge.

### 19. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to treasury.gov negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 20. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of treasury.gov is http://ocsp.sectigo.com; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

## Evidence (raw response observations)

```json
{
  "domain": "treasury.gov",
  "dns": {
    "a": [
      "164.95.95.220"
    ],
    "aaaa": [
      "2610:108:3100:100c::8:153"
    ],
    "cname": null,
    "mx": [
      "cwmailhub1in.treasury.gov (pref 10)",
      "cemailhub1in.treasury.gov (pref 10)"
    ],
    "ns": [
      "margot.ns.cloudflare.com.",
      "tadeo.ns.cloudflare.com."
    ],
    "caa": [],
    "spf": [
      "openai-domain-verification=dv-URa4cQaZUt7TuzEHuA4cT3QK",
      "VRvAtqJ/zwPkVlZktq8MLIFnN/s7AgCvN4mqqqj1rX+IlRTOdWVyRhqiHZoDXnPt7rRshcAOZx5TsxFLIlY0gg==",
      "MS=ms62206556",
      "box-domain-verification=907e0bde6b92f9b565218a2fcba8a7adaa9501f4838624d4efe57f69031f9e0d",
      "apple-domain-verification=Agf1IhJ01yW5m4ka",
      "v=spf1 redirect=_spfnew.treasury.gov"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; rua=mailto:us-treasury@rua.dmp.cisco.com,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:us-treasury@ruf.dmp.cisco.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "subject": "countryName=US, stateOrProvinceName=District of Columbia, organizationName=Department of Treasury, commonName=treasury.gov",
    "issuer": "countryName=CA, organizationName=Entrust Limited, commonName=Entrust OV TLS Issuing RSA CA 2",
    "notBefore": "Oct  8 00:00:00 2025 GMT",
    "notAfter": "Nov  8 23:59:59 2026 GMT",
    "san": [
      "treasury.gov",
      "ama.gov",
      "cdfifund.gov",
      "cfius.gov",
      "ffb.gov",
      "financialresearch.gov",
      "financialstability.gov",
      "fsoc.gov",
      "irs.gov",
      "makinghomeaffordable.gov",
      "mha.gov",
      "myira.gov",
      "mymoney.gov",
      "tigta.gov",
      "tips.tigta.gov",
      "transparency.treasury.gov",
      "treas.gov",
      "usaspending.gov",
      "ustreas.gov",
      "www.cfius.gov",
      "www.tigta.gov",
      "www.treasury.gov"
    ],
    "days_left": 42,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": false,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "164.95.95.220",
    "open": []
  },
  "https": {
    "status": 302,
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
      "origin": "https://sub.treasury.gov",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://treasury.gov//"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "openai-domain-verification=dv-URa4cQaZUt7TuzEHuA4cT3QK",
    "box-domain-verification=907e0bde6b92f9b565218a2fcba8a7adaa9501f4838624d4efe57f69",
    "apple-domain-verification=Agf1IhJ01yW5m4ka"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 334416006821364615816743893683616762807,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.sectigo.com/EntrustOVTLSIssuingRSACA2.crl"
      ],
      "san": [
        "treasury.gov",
        "ama.gov",
        "cdfifund.gov",
        "cfius.gov",
        "ffb.gov",
        "financialresearch.gov",
        "financialstability.gov",
        "fsoc.gov",
        "irs.gov",
        "makinghomeaffordable.gov",
        "mha.gov",
        "myira.gov",
        "mymoney.gov",
        "tigta.gov",
        "tips.tigta.gov",
        "transparency.treasury.gov",
        "treas.gov",
        "usaspending.gov",
        "ustreas.gov",
        "www.cfius.gov"
      ],
      "subject_dn": "310b3009060355040613025553311d301b060355040813144469737472696374206f6620436f6c756d626961311f301d060355040a13164465706172746d656e74206f66205472656173757279311530130603550403130c74726561737572792e676f76",
      "issuer_dn": "310b300906035504061302434131183016060355040a130f456e7472757374204c696d69746564312830260603550403131f456e7472757374204f5620544c532049737375696e67205253412043412032",
      "not_before": "20251008000000",
      "not_after": "20261108235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 302
  },
  "x13": {
    "root_status": 302,
    "root_location": "https://www.treasury.gov/",
    "http_status": 301,
    "p404_status": 302,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 302,
    "hsts": "max-age=31536000",
    "crl": {
      "url": "http://crl.sectigo.com/EntrustOVTLSIssuingRSACA2.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "cipher_ver": "TLSv1.2",
    "root_status": 302
  },
  "x16": {
    "root_status": 302
  },
  "x17": {
    "ocsp_http": "http://ocsp.sectigo.com"
  },
  "elapsed_s": 91.6,
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
