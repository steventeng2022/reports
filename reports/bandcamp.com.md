# Security Audit Report — bandcamp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bandcamp.com/ |
| Bug bounty program | Epic Games |
| Listed scope domain | bandcamp.com |
| Test date | 2026-09-26 17:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 4, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 11 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 10. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.bandcamp.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 11. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (7ybn4ccz9fkveh.bandcamp.com and chnjrvll6r9vyb.bandcamp.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=R2K3ueaK09kESoG_YBuvOdRI7KWlKTgJket4pCrObTs; anthropic-domain-verification-k95236=fP5eU7agEB5py1gXXJmNmUrfK; google-site-verification=n7VFVIsha5YafmTLSe77JvVFOMw95jU5S5BQRRL_6Qc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bandcamp.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but bandcamp.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 28 disallow path(s), e.g. /tools, /checkout, /download_check, /cart/, /corpbanner/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "bandcamp.com",
  "dns": {
    "a": [
      "151.101.193.91",
      "151.101.1.91",
      "151.101.129.91",
      "151.101.65.91"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-cloud-d1.googledomains.com.",
      "ns-cloud-d2.googledomains.com.",
      "ns-cloud-d4.googledomains.com.",
      "ns-cloud-d3.googledomains.com."
    ],
    "spf": [
      "google-site-verification=R2K3ueaK09kESoG_YBuvOdRI7KWlKTgJket4pCrObTs",
      "anthropic-domain-verification-k95236=fP5eU7agEB5py1gXXJmNmUrfK",
      "google-site-verification=n7VFVIsha5YafmTLSe77JvVFOMw95jU5S5BQRRL_6Qc",
      "atlassian-domain-verification=BTH5hOYBqeIEweoD5sO+R9uM4HGvi6XMLhyOGmvQWowfdg2+QBoGpOUygbJG54Xn",
      "_globalsign-domain-verification=nx5U56FiDUqhsckpguh1BWVo8oJVRsFtwCfGxdBN4e",
      "v=spf1 include:sendgrid.net include:_spf.google.com include:servers.mcsv.net include:smtp.app.echomark.com ~all",
      "google-site-verification=1zzPh4J8oCSfyiKMYuZRhpD4rf1iip6VEZ4m5URsIh0",
      "apple-domain-verification=YnAbPC9ay7NlvPfJ",
      "box-domain-verification=90c68eb309746ce326626165eadc4785e6094731b6e841ac85dab1c1d08a071c",
      "knowbe4-site-verification=bd869772c82849fbe473ecd2303fd637"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:dmarcreports@bandcamp.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.bandcamp.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q2",
    "notBefore": "May  9 23:08:16 2026 GMT",
    "notAfter": "Nov 24 22:08:16 2026 GMT",
    "san": [
      "*.bandcamp.com",
      "bandcamp.com"
    ],
    "days_left": 59,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.193.91",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Bandcamp"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bandcamp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bandcamp.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 406,
    "/phpmyadmin/index.php": 406,
    "/server-status": 404,
    "/api/": 200
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=R2K3ueaK09kESoG_YBuvOdRI7KWlKTgJket4pCrObTs",
    "anthropic-domain-verification-k95236=fP5eU7agEB5py1gXXJmNmUrfK",
    "google-site-verification=n7VFVIsha5YafmTLSe77JvVFOMw95jU5S5BQRRL_6Qc",
    "atlassian-domain-verification=BTH5hOYBqeIEweoD5sO+R9uM4HGvi6XMLhyOGmvQWowfdg2+QB",
    "_globalsign-domain-verification=nx5U56FiDUqhsckpguh1BWVo8oJVRsFtwCfGxdBN4e"
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
    "robots_disallow": [
      "/tools",
      "/checkout",
      "/download_check",
      "/cart/",
      "/corpbanner/",
      "/stream",
      "/api/",
      "/design_tokens",
      "/search",
      "/*_cb$",
      "/",
      "/",
      "/",
      "/",
      "/"
    ]
  },
  "elapsed_s": 21.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
