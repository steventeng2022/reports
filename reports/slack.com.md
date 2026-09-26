# Security Audit Report — slack.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://slack.com/ |
| Bug bounty program | Slack |
| Listed scope domain | slack.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 9 | low | DNS3 | Wildcard DNS detected | CWE-345 |
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
- **Detail:** Detected: Server: Apache
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000, h3-29=":443"; ma=2592000, quic=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Apache
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.slack.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 9. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (iw31q82nncclrc.slack.com and m3bcf8p4seb5hd.slack.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: spycloud-domain-verification=02e4c0be-cf43-44e4-beaf-4f99702ca632; google-site-verification=v-LLB__IhraaI7ZzuE3jvRFIm2vERPLzWoepAEZJtKQ; google-site-verification=KqX3Ngw0XEjz_0GVx_xwFFlCoO-bskhqU_lxv0Q77mk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of slack.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but slack.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 15 disallow path(s), e.g. /messages, /quickstart, /go/, /unsub/, /answers/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "slack.com",
  "dns": {
    "a": [
      "35.74.58.174",
      "35.73.126.78",
      "52.196.128.139",
      "52.192.46.121"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)"
    ],
    "ns": [
      "ns-1901.awsdns-45.co.uk.",
      "ns-166.awsdns-20.com.",
      "ns-606.awsdns-11.net.",
      "ns-1493.awsdns-58.org."
    ],
    "spf": [
      "spycloud-domain-verification=02e4c0be-cf43-44e4-beaf-4f99702ca632",
      "google-site-verification=v-LLB__IhraaI7ZzuE3jvRFIm2vERPLzWoepAEZJtKQ",
      "google-site-verification=KqX3Ngw0XEjz_0GVx_xwFFlCoO-bskhqU_lxv0Q77mk",
      "v=spf1 include:_spf.qualtrics.com include:mail.zendesk.com include:_spfextra.slack.com -all",
      "google-site-verification=o2grd1TLmZZ8GrqbhVIFtzO2MRLTtSUpBBIBYfhQVCQ",
      "google-site-verification=2PK67oVPNyEtS1avSlr3PhH5nSiFuticbQv_bT4pM2k",
      "_0vidyxobp6x350odqhb4fo7fdxhmtq3",
      "hubspot-developer-verification=OTE4NzYxYTgtMDUwZi00MzgzLTk2YTUtZDAwNjBlODg1MWM0",
      "google-site-verification=QvelFPjIOe3Vavw0q-aAVYaAPKmWCRjmmVVEAjgfjQc",
      "google-site-verification=efuXt5-oMr2CdNmVi6A9IO29KMKifpseD1qokxjWwcE",
      "OSSRH-54733",
      "google-site-verification=kB1KvgpSk9YkHsFmsj1VPI5YmDvfKctPxnplhGjyqtE"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;fo=1:d:s;pct=100;rua=mailto:dmarc_agg@vali.email,mailto:0e5a5c34@inbox.ondmarc.com;ruf=mailto:0e5a5c34@inbox.ondmarc.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=slack.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug  6 09:33:39 2026 GMT",
    "notAfter": "Nov  4 09:33:38 2026 GMT",
    "san": [
      "*.slack.com",
      "slack.com"
    ],
    "days_left": 38,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "35.74.58.174",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Slack | AI Work Platform &amp; Productivity Tools"
  },
  "mixed_content": [],
  "tech": [
    "Server: Apache"
  ],
  "cookies": [
    {
      "domain": ".slack.com",
      "samesite": "none"
    },
    {
      "domain": ".slack.com",
      "samesite": "none"
    },
    {
      "domain": ".slack.com",
      "samesite": "none"
    },
    {
      "domain": ".slack.com",
      "samesite": "lax"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.slack.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://slack.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "spycloud-domain-verification=02e4c0be-cf43-44e4-beaf-4f99702ca632",
    "google-site-verification=v-LLB__IhraaI7ZzuE3jvRFIm2vERPLzWoepAEZJtKQ",
    "google-site-verification=KqX3Ngw0XEjz_0GVx_xwFFlCoO-bskhqU_lxv0Q77mk",
    "google-site-verification=o2grd1TLmZZ8GrqbhVIFtzO2MRLTtSUpBBIBYfhQVCQ",
    "google-site-verification=2PK67oVPNyEtS1avSlr3PhH5nSiFuticbQv_bT4pM2k"
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
      "/messages",
      "/quickstart",
      "/go/",
      "/unsub/",
      "/answers/",
      "/help/requests/new?app_id=*",
      "/what-is-slack",
      "/collaborating-with-slack",
      "/lp/three",
      "/documents/slack_pilot_dpa",
      "/openid",
      "/oauth",
      "/careers/",
      "/join/shared_invite",
      "/files-pri/"
    ]
  },
  "elapsed_s": 24.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
