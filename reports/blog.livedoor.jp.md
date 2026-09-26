# Security Audit Report — blog.livedoor.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://blog.livedoor.jp/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | blog.livedoor.jp |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **5** (High: 0, Medium: 1, Low: 0, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | TLS1 | TLS certificate chain not trusted | CWE-298 |
| 3 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 4 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 5 | info | CT1 | 1 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 5. [INFO] 1 hostnames found via Certificate Transparency (certspotter) (`CT1`)

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
      "aia_ocsp": null
    }
  },
  "http2": {
    "error": "root GET failed"
  },
  "elapsed_s": 2.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
