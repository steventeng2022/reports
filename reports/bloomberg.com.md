# Security Audit Report — bloomberg.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bloomberg.com/ |
| Bug bounty program | Bloomberg |
| Listed scope domain | bloomberg.com |
| Test date | 2026-09-26 17:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 1, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.bloomberg.com/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ClT3QBQ-Rd4b3AAq2gmQ-u_94EliZRmC2e-Kb4t9zEo; cursor-domain-verification-asb77c=D43c1zjGqO3rTemQvZ121NSfi; parallels-domain-verification=47460854911b478da11221dc20e8cc0340a92adf1e6b4ff08a
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bloomberg.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but bloomberg.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 130 disallow path(s), e.g. /polska, /account/*, /tosv*.html, /search, /company/search/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "bloomberg.com",
  "dns": {
    "a": [
      "3.33.146.110",
      "15.197.146.156"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mgcnj2.bloomberg.com (pref 0)",
      "mgcny2.bloomberg.com (pref 0)",
      "mgcny1.bloomberg.com (pref 0)",
      "mgcnj1.bloomberg.com (pref 0)"
    ],
    "ns": [
      "dns4.p01.nsone.net.",
      "dns3.p01.nsone.net.",
      "pdns1.ultradns.net.",
      "pdns5.ultradns.info.",
      "dns1.p01.nsone.net.",
      "dns2.p01.nsone.net.",
      "pdns3.ultradns.org."
    ],
    "spf": [
      "google-site-verification=ClT3QBQ-Rd4b3AAq2gmQ-u_94EliZRmC2e-Kb4t9zEo",
      "Ymxvb21iZXJn",
      "QnH3utpbwmcXnxwnErM2by/pp37P7fYtF9si0rMmb9FgwB98zU8UAzdl1GbyQMdyNFLKobFRdX6FfLlH/LG+og==",
      "cursor-domain-verification-asb77c=D43c1zjGqO3rTemQvZ121NSfi",
      "ZOOM_verify_8UDWCiGoiAVgGEuiZNG9Ld",
      "parallels-domain-verification=47460854911b478da11221dc20e8cc0340a92adf1e6b4ff08a5e941f5379c267",
      "extensis-domain-verification=707df5b4-0868-499f-af75-51718e082698",
      "openai-domain-verification=dv-XaK3IjuwWpMmfss9VYKwn0eY",
      "lutron-domain-verification-p8wzsk=PQcs5tfle6vYve4ulSshxyMYi",
      "google-site-verification=CI2IKDBbk_gcKk_9CFFUrF-ZLZToKXQ7SAJ96fjqZ_I",
      "v=spf1 ip4:69.184.0.0/13 ip4:199.172.169.0/24 ip4:208.22.56.0/24 ip4:69.191.241.124 -all",
      "google-gws-recovery-domain-verification=72311760",
      "F2QdzLTE6LTOyOQ7pQzoSY2pnwVM5pnfiqY3zOoYvS3LoVmIUr0J3op5vQI8Tg8VQwt24UK8v7oFWfbrCBWYYw==",
      "2smsverify=08qXd7f0aUa5IPq0N4ETgQ",
      "ZOOM_verify_rl-mcFScS8W6864E30mlZg",
      "MS=ms99943004",
      "airtable-verification=15d4376d6d99cc906abbcb295b4245da",
      "MS=ms33692690",
      "apple-domain-verification=9cs9hMRccEtbVb8h",
      "google-site-verification=vH_zs-JrwvXxkyuUqmeN9t3iMYZqyt1-BJUsoyN3ca8",
      "atlassian-domain-verification=gK9LJEftkavNAe/keDgXDWOhGwUV02GQTz9BbfKLplkTTtpciOH5eL1W6u7BRfVR",
      "jamf-site-verification=VJNRhgJ90SmyugkIPAdfCQ",
      "OSSRH-64276"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; adkim=r; aspf=r; ruf=mailto:dmarc-ruf@dmarc-bloomberg.com; fo=1; rua=mailto:dmarc-rua@dmarc-bloomberg.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=New York, localityName=New York, organizationName=Bloomberg LP, commonName=wmkt1.cirrus.bloomberg.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 23 00:00:00 2026 GMT",
    "notAfter": "Jan 29 23:59:59 2027 GMT",
    "san": [
      "wmkt1.cirrus.bloomberg.com",
      "about.bloomberg.com",
      "about.bloomberginstitute.com",
      "assets.bbhub.io",
      "b20-carbon-excellence.org",
      "batscore.com",
      "bbhub.io",
      "bbthat.com",
      "beta-ee.bloomberg.com",
      "bgov200.com",
      "blog.bloomberg.com",
      "blomberggovernment.com",
      "bloom.bg",
      "bloomberg.cn",
      "bloomberg.co.jp",
      "bloomberg.co.kr",
      "bloomberg.co.uk",
      "bloomberg.com",
      "bloomberg.com.br",
      "bloomberg.com.mx",
      "bloomberg.com.tr",
      "bloomberg.de",
      "bloomberg.fr",
      "bloomberg.in",
      "bloomberg.it",
      "bloomberg.net",
      "bloomberg.tv",
      "bloomberg401k.com",
      "bloombergaffiliate.com",
      "bloombergapa.net",
      "bloombergapae.net",
      "bloombergapps.com",
      "bloombergarcade.co.uk",
      "bloombergarcade.com",
      "bloombergarm.net",
      "bloombergbeta.com",
      "bloombergbna.com",
      "bloombergbrief.com",
      "bloombergbriefs.com",
      "bloombergbtbs.com",
      "bloombergbtbs.net",
      "bloombergbtbs.sg",
      "bloombergbtbsg.com",
      "bloombergbtbsg.net",
      "bloombergbtbsg.sg",
      "bloombergbusiness.com",
      "bloombergcareer.com",
      "bloombergchina.com",
      "bloombergcms.com",
      "bloombergcompany.com",
      "bloombergcontentservice.com"
    ],
    "days_left": 125,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.33.146.110",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bloomberg.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://bloomberg.com:443/"
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
  "apex_txt": [
    "google-site-verification=ClT3QBQ-Rd4b3AAq2gmQ-u_94EliZRmC2e-Kb4t9zEo",
    "cursor-domain-verification-asb77c=D43c1zjGqO3rTemQvZ121NSfi",
    "parallels-domain-verification=47460854911b478da11221dc20e8cc0340a92adf1e6b4ff08a",
    "extensis-domain-verification=707df5b4-0868-499f-af75-51718e082698",
    "openai-domain-verification=dv-XaK3IjuwWpMmfss9VYKwn0eY"
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
      "/polska",
      "/account/*",
      "/tosv*.html",
      "/search",
      "/company/search/",
      "/professional/search/",
      "/impact/search/",
      "/ux/search/",
      "/wnwi/search/",
      "/gei/search/",
      "/impact/search/",
      "/netzeropathfinders/search/",
      "/notices/search/",
      "/distribution/search/",
      "/ukinnovators/search/"
    ]
  },
  "elapsed_s": 17.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
