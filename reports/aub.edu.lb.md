# Security Audit Report — aub.edu.lb

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aub.edu.lb/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | aub.edu.lb |
| Test date | 2026-09-26 17:39 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 4, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CT1 | 299 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 18 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Microsoft-IIS/8.5; X-Powered-By: ASP.NET; X-AspNet-Version: 4.0.30319
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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
- **Detail:** Header reveals: Microsoft-IIS/8.5
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=6gAxqrh5UO8G0TgM; google-site-verification=9MsV81Hg7gw2Sgc4tNSXaQktR2FWaGTUeYxZtLBb3Lk; openai-domain-verification=dv-DWZ0HxSw0kUap6jjuTBsOiGk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of aub.edu.lb has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 5 disallow path(s), e.g. /_catalogs/, /_layouts/, /search/, /register/, /*?*/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] 299 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: ngoi-isplatform.test.ghi.aub.edu.lb, test.aub.edu.lb, vpn.aub.edu.lb
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 18. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: test.aub.edu.lb; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "aub.edu.lb",
  "dns": {
    "a": [
      "40.127.138.74"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aub-edu-lb.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "zeina.aub.edu.lb.",
      "magma.aub.edu.lb.",
      "rose.aub.edu.lb.",
      "ash.northeurope.cloudapp.azure.com.",
      "lava.aub.edu.lb."
    ],
    "spf": [
      "apple-domain-verification=6gAxqrh5UO8G0TgM",
      "google-site-verification=9MsV81Hg7gw2Sgc4tNSXaQktR2FWaGTUeYxZtLBb3Lk",
      "mentimeter-7517212d-53b0-454a-a51a-58de590aaad4",
      "HARICA-Jck6FQFsbhgljuf8FV3",
      "openai-domain-verification=dv-DWZ0HxSw0kUap6jjuTBsOiGk",
      "google-site-verification=fwk46Yls3T43Nu3xZ677JWvPpfeSfaYF_cesWhonw-Y",
      "google-site-verification=NIoCNLajkOt8Tm9mZfAcX2oYc9oWtCG3yxwLDiJXmeU",
      "v=spf1 +ip4:193.188.128.10/32 +ip4:193.188.128.39/32 ",
      "+ip4:193.188.128.41/32 +ip4:193.188.128.50/32 ",
      "+ip4:54.240.35.57/32 +ip4:193.188.129.5/32 ",
      "+ip4:193.188.128.69/32 ip4:193.188.128.16/32 ",
      "include:zeptomail.net include:_spf.salesforce.com +include:spf.protection.outlook.com include:spf.symplicity.com ~all",
      "ciscocidomainverification=421e71e3fc1322e159b9b2f1506ee2b6e8d9e3b38b975a6c68409d591b5f4c0f"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:dmarc@aub.edu.lb,mailto:dmarc-reports@aub.edu.lb; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-SHA384",
    "subject": "commonName=*.aub.edu.lb",
    "issuer": "countryName=GR, organizationName=Hellenic Academic and Research Institutions CA, commonName=GEANT TLS RSA 1",
    "notBefore": "Jul 22 23:39:43 2026 GMT",
    "notAfter": "Feb  6 23:39:42 2027 GMT",
    "san": [
      "*.aub.edu.lb",
      "aub.edu.lb",
      "*.aub.edu",
      "*.aubmc.org",
      "aubmc.org",
      "*.aubmc.org.lb",
      "aubmc.org.lb"
    ],
    "days_left": 133,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "40.127.138.74",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "American University of Beirut | AUB"
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: Microsoft-IIS/8.5",
    "X-Powered-By: ASP.NET",
    "X-AspNet-Version: 4.0.30319"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.aub.edu.lb",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 307,
    "location": "https://aub.edu.lb/"
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
    "source": "certspotter",
    "count": 299,
    "notable": [
      "ngoi-isplatform.test.ghi.aub.edu.lb",
      "test.aub.edu.lb",
      "vpn.aub.edu.lb"
    ],
    "sample": [
      "150.aub.edu.lb",
      "acdi.aub.edu.lb",
      "argos.aub.edu.lb",
      "arl.aub.edu.lb",
      "aub.edu.lb",
      "aubnetdb.aub.edu.lb",
      "bam.aub.edu.lb",
      "bandevmobile.aub.edu.lb",
      "bandevmobiletstapi.aub.edu.lb",
      "banmobile.aub.edu.lb",
      "banner-appnav.aub.edu.lb",
      "banssb1.aub.edu.lb",
      "banssb2.aub.edu.lb",
      "bantstsso.aub.edu.lb",
      "bantstwf.aub.edu.lb",
      "banwf.aub.edu.lb",
      "banwf1.aub.edu.lb",
      "banwf2.aub.edu.lb",
      "beis1.aub.edu.lb",
      "beis2.aub.edu.lb"
    ],
    "dangling": [
      "test.aub.edu.lb"
    ]
  },
  "apex_txt": [
    "apple-domain-verification=6gAxqrh5UO8G0TgM",
    "google-site-verification=9MsV81Hg7gw2Sgc4tNSXaQktR2FWaGTUeYxZtLBb3Lk",
    "openai-domain-verification=dv-DWZ0HxSw0kUap6jjuTBsOiGk",
    "google-site-verification=fwk46Yls3T43Nu3xZ677JWvPpfeSfaYF_cesWhonw-Y",
    "google-site-verification=NIoCNLajkOt8Tm9mZfAcX2oYc9oWtCG3yxwLDiJXmeU"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 4096,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null
    }
  },
  "http2": {
    "robots_disallow": [
      "/_catalogs/",
      "/_layouts/",
      "/search/",
      "/register/",
      "/*?*/"
    ]
  },
  "elapsed_s": 45.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
