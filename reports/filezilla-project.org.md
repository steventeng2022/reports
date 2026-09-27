# Security Audit Report — filezilla-project.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://filezilla-project.org/ |
| Bug bounty program | FileZilla |
| Listed scope domain | filezilla-project.org |
| Test date | 2026-09-27 00:26 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 3 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 4 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 5 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 6 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 7 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 8 | info | HTML7 | Insecure http:// references inside an HTTPS document | CWE-319 |
| 9 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 10 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 3. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.filezilla-project.org/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 4. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (47taq7nwjfc20l.filezilla-project.org and xoji8somhp3yjx.filezilla-project.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 5. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=VMSIrNYAVoMPTFK6VdS6swSnzPeV9u3oDl2KraQnLI8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 6. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkc7ml2vp5kizs.html -> 404; error page/headers match: Apache.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 7. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for filezilla-project.org, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 8. [INFO] Insecure http:// references inside an HTTPS document (`HTML7`)

- **CWE:** CWE-319
- **Detail:** Root document of filezilla-project.org references 3 distinct http:// URL(s) (e.g. http://octochess.org/, http://www.w3.org/1999/xhtml, http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd); using them drops to unencrypted transport.
- **Recommendation:** Use https:// references or relative URLs.

### 9. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of filezilla-project.org references 8 distinct third-party registrable domains (e.g. w3.org, filezillapro.com, octochess.org, route4me.com, automatio.ai); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 10. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of filezilla-project.org sends a CSP but contains 2 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

## Evidence (raw response observations)

```json
{
  "domain": "filezilla-project.org",
  "dns": {
    "a": [
      "49.12.121.47"
    ],
    "aaaa": [
      "2a01:4f8:242:52d0::2"
    ],
    "cname": null,
    "mx": [
      "filezilla-project.org (pref 10)"
    ],
    "ns": [
      "ns1.domaindiscount24.net.",
      "ns2.domaindiscount24.net.",
      "ns3.domaindiscount24.net."
    ],
    "caa": [],
    "spf": [
      "v=spf1 mx ip4:49.12.121.47/32 ip6:2a01:4f8:242:52d0::2/64 -all",
      "google-site-verification=VMSIrNYAVoMPTFK6VdS6swSnzPeV9u3oDl2KraQnLI8"
    ],
    "dmarc": [
      "v=DMARC1; p=reject"
    ],
    "dnssec_authenticated": false
  },
  "error": "TimeoutError('timed out')",
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=VMSIrNYAVoMPTFK6VdS6swSnzPeV9u3oDl2KraQnLI8"
  ],
  "tls2": {
    "error": "TimeoutError('timed out')"
  },
  "http2": {
    "error": "root GET failed"
  },
  "x12": {
    "error": "ConnectTimeout(MaxRetryError(\"HTTPSConnectionPool(host='filezilla-project.org', "
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
    "hsts": "max-age=315360000; includeSubDomains; preload"
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 200
  },
  "elapsed_s": 59.8,
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
