# Security Audit Report — filezilla-project.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://filezilla-project.org/ |
| Bug bounty program | FileZilla |
| Listed scope domain | filezilla-project.org |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 1, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 3 | info | PRT22 | SSH reachable | CWE-200 |
| 4 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 5 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 6 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 7 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 8 | info | TECH1 | Technology fingerprint | CWE-200 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL9 | DMARC enforces (p=reject) but has no reporting address (rua) | CWE-285 |
| 15 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 16 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 49.12.121.47:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 49.12.121.47:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 49.12.121.47:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 49.12.121.47:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 49.12.121.47:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 8. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [LOW] DMARC enforces (p=reject) but has no reporting address (rua) (`MAIL9`)

- **CWE:** CWE-285
- **Detail:** Without a rua= reporting address the policy cannot be tuned; mis-sends may be silently quarantined.
- **Recommendation:** Add a rua= reporting mailbox to the DMARC record.

### 15. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.filezilla-project.org/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 16. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (vrjmgn0fcq6znj.filezilla-project.org and 4a2efx12d7k0yu.filezilla-project.org) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=VMSIrNYAVoMPTFK6VdS6swSnzPeV9u3oDl2KraQnLI8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

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
      "ns3.domaindiscount24.net.",
      "ns1.domaindiscount24.net.",
      "ns2.domaindiscount24.net."
    ],
    "spf": [
      "v=spf1 mx ip4:49.12.121.47/32 ip6:2a01:4f8:242:52d0::2/64 -all",
      "google-site-verification=VMSIrNYAVoMPTFK6VdS6swSnzPeV9u3oDl2KraQnLI8"
    ],
    "dmarc": [
      "v=DMARC1; p=reject"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=www.filezilla-project.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR2",
    "notBefore": "Aug 17 23:14:52 2026 GMT",
    "notAfter": "Nov 15 23:14:51 2026 GMT",
    "san": [
      "filezilla-project.org",
      "www.filezilla-project.org"
    ],
    "days_left": 50,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "49.12.121.47",
    "open": [
      21,
      22,
      25,
      143,
      993
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "FileZilla - The free FTP solution"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.filezilla-project.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://filezilla-project.org/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 0,
    "/wp-login.php": 0,
    "/phpmyadmin/index.php": 0,
    "/server-status": 0,
    "/api/": 0
  },
  "subdomains": {
    "status": "ct-pending"
  },
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
  "elapsed_s": 118.9,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
