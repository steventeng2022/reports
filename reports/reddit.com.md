# Security Audit Report — reddit.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://reddit.com/ |
| Bug bounty program | Reddit |
| Listed scope domain | reddit.com |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 2, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: snooserv
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: snooserv
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (ktc1qxd20jie71.reddit.com and 9xnes594kn4prc.reddit.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=aGWDxGvt+oY3p7qTWt5v2uJDVJkoJAeHxwGqKmGQLMEsUXUJJe; yahoo-verification-key=I0We5FayJi0Q8XdjDgE5oN0ujM08heSVe46o/FvsMkk=; protonmail-verification=24cb91442caf54c8b820f4a0347292f143531210
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of reddit.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 1 disallow path(s), e.g. /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://reddit.com/ carries Cache-Control: private, max-age=3600; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "reddit.com",
  "dns": {
    "a": [
      "151.101.129.140",
      "151.101.65.140",
      "151.101.1.140",
      "151.101.193.140"
    ],
    "aaaa": [
      "2a04:4e42:400::396",
      "2a04:4e42:200::396",
      "2a04:4e42::396",
      "2a04:4e42:600::396"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx2.googlemail.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-378.awsdns-47.com.",
      "ns-1029.awsdns-00.org.",
      "ns-1887.awsdns-43.co.uk.",
      "ns-557.awsdns-05.net."
    ],
    "spf": [
      "atlassian-domain-verification=aGWDxGvt+oY3p7qTWt5v2uJDVJkoJAeHxwGqKmGQLMEsUXUJJe/Pm/k+GGNPpn6M",
      "MS=ms71041902",
      "yahoo-verification-key=I0We5FayJi0Q8XdjDgE5oN0ujM08heSVe46o/FvsMkk=",
      "protonmail-verification=24cb91442caf54c8b820f4a0347292f143531210",
      "atlassian-domain-verification=vBaV6PXyyu4OAPLiQFbxFMCboSTjoR/qxKJ2OlpI46ZEpZL/FVTIfMlgoM5Hy9eY",
      "docusign=6ba0c5a9-5a5e-41f8-a7c8-8b4c6e35c10c",
      "liveramp-site-verification=hNZ5ZAy1ufTpXrpCELrrtSzTlb4KU4h7UtDPpZdj9XA",
      "v=spf1 include:spf0.reddit.com -all",
      "cursor-domain-verification-f9fw38=WVB8yAMGTZXO7Je9DLuj1DIZB",
      "stripe-verification=9bd70dd1884421b47f596fea301e14838c9825cdba5b209990968fdc6f8010c7",
      "jetbrains-domain-verification=bjn7o9fxbduga0omhaepeewtx",
      "box-domain-verification=95c33f4ee4b11d8827190dbc5371ca7df25b961019116e5565ce4aa36de9be3a",
      "postman-domain-verification=ad4c89daaf83d06f70cb6e8737cb323b039aeaae9e0e288c75081b0a715812a2d30e7c31402da867c70287ad8216da42074ffe7b4fcfcbf86f9316301329308f",
      "jamf-site-verification=EGK11tNR4hezQg0jZaIDpA",
      "google-site-verification=zZHozYbAJmSLOMG4OjQFoHiVqkxtdgvyBzsE7wUGFiw",
      "00Dbf000005OCTN=1TBbf0000000Mer",
      "google-site-verification=oh_YJE560y0e6FHP1RT7NIjyTlBhACNMvD2EgSss0sc",
      "apple-domain-verification=qC3rSSKrh10DoMI7",
      "a5897185-49e1-4181-9065-51bd24737466",
      "onetrust-domain-verification=6b98ba3dd087405399bbf45b6cbdcd37",
      "00Do0000000I6Pa=1TBcv0000000HQh",
      "00DV90000052YKT=1TBV90000000AsD",
      "google-site-verification=QO4VY1PRzsG-MxiQn3j0kxd_ZaFjcTk6MWBfKru0_5I",
      "stripe-verification=80aa7e2c9775fee2653f61b04b46da6fd227b56fecd9499e5f63cd0dcf563984",
      "google-site-verification=0uv13-wxlHK8FFKaUpgzyrVmL1YdNYW6v3PupLdw3JI",
      "google-site-verification=5Qzlkl8HJJSBKnMI7rQGDr9Sgiir4Ey6klx1rWQCJ2M",
      "twilio-domain-verification=5e37855d7c9445e967b31c5e0371ebb5",
      "00Dbf000005OCRl=1TBbf0000000MJt",
      "614ac4be-8664-4cea-8e29-f84d08ad875c"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=1; ruf=mailto:reddit@us.cp-dmarc.com; rua=mailto:reddit@us.cp-dmarc.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Reddit, Inc., commonName=*.reddit.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Aug 21 00:00:00 2026 GMT",
    "notAfter": "Feb 16 23:59:59 2027 GMT",
    "san": [
      "*.reddit.com",
      "reddit.com"
    ],
    "days_left": 143,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.129.140",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: snooserv"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.reddit.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://reddit.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 301,
    "/.git/config": 301,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "atlassian-domain-verification=aGWDxGvt+oY3p7qTWt5v2uJDVJkoJAeHxwGqKmGQLMEsUXUJJe",
    "yahoo-verification-key=I0We5FayJi0Q8XdjDgE5oN0ujM08heSVe46o/FvsMkk=",
    "protonmail-verification=24cb91442caf54c8b820f4a0347292f143531210",
    "atlassian-domain-verification=vBaV6PXyyu4OAPLiQFbxFMCboSTjoR/qxKJ2OlpI46ZEpZL/FV",
    "liveramp-site-verification=hNZ5ZAy1ufTpXrpCELrrtSzTlb4KU4h7UtDPpZdj9XA"
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
      "not_before": "20260821000000",
      "not_after": "20270216235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 12.9,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
