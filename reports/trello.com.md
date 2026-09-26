# Security Audit Report — trello.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://trello.com/ |
| Bug bounty program | Trello |
| Listed scope domain | trello.com |
| Test date | 2026-09-25 10:24 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 3, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AtlassianEdge
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 8. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AtlassianEdge
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "trello.com",
  "dns": {
    "a": [
      "54.192.248.49",
      "54.192.248.39",
      "54.192.248.64",
      "54.192.248.6"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-001d9801.gslb.pphosted.com (pref 10)",
      "mxa-001d9801.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-402.awsdns-50.com.",
      "ns-2013.awsdns-59.co.uk.",
      "ns-722.awsdns-26.net.",
      "ns-1442.awsdns-52.org."
    ],
    "spf": [
      "google-site-verification=lFRc2QYcvrD1x-JP-sbqyEHEVFTzLiYr_s5TMwqDPGE",
      "google-site-verification=XiTuMrGYNDAcJ3h6FgJn-qK1wWhcRCTrwK7ihP4lgzQ",
      "atlassian-domain-verification=ZRphniOpyvhHV76mRmxnLkHJVrKnbeOIxmhbxb8PF6AarX0FypthxYB/r5XpVC2E",
      "google-site-verification=rSOg_zfvrFkmPwI-Yg4oLj8SNdFQnPCeo9a0GtDf_y4",
      "google-site-verification=L1Pv1rpciXhbLcwV1z84F6fdeNpGMIDd4nrgAzCQncc",
      "google-site-verification=klLlb7yZqSKsDzIEQ_Ck9G8vJZrZUYSl7G6SYm5ugaU",
      "google-site-verification=m3SBLzut__3UbFT85xIcXyZs4CsOKfX6MrdByMh6xSM",
      "slack-domain-verification=IQyaWt1Bt2nVwCvOsgj2ObAap344ynM5bV6C8zlZ",
      "google-site-verification=UqQbR3bkx0DW0mTjn4zpy-pFaTOtklFFLgVJPLpWBfg",
      "v=spf1 include:_spf.google.com include:_spf.salesforce.com include:spemail.trello.com include:cust-spf.exacttarget.com include:amazonses.com -all",
      "facebook-domain-verification=5g7n6qixu6oqonzuw4igcyn2fd52yi",
      "google-site-verification=dk_f7jMXJqZs_HAQ5Qvd1LMExtsW6rL0_3vK6wMWxyM",
      "google-site-verification=j10V2FxDCOpk-ZtvXbt0csUYbGo4uttk0VIeNN3pMwQ",
      "mailru-verification: 26cd15930108c82c"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=quarantine; adkim=r; aspf=r; fo=1; pct=100; rua=mailto:dmarc_rua@emaildefense.proofpoint.com,mailto:dmarc-rua@abuse.atlassian.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:dmarc-ruf@abuse.atlassian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=*.frontend.public.atl-paas.net",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Jul 27 00:00:00 2026 GMT",
    "notAfter": "Feb  9 23:59:59 2027 GMT",
    "san": [
      "*.frontend.public.atl-paas.net",
      "bitbucket.org",
      "*.bitbucket.com",
      "*.bitbucket.io",
      "*.teamworkgraph.ai",
      "*.dataapps.shared.atlassian-3p.com",
      "*.devsphere.tools.atlassian.com",
      "*.rovo.com",
      "*.halp.com",
      "halp.com",
      "*.internal.atlassian.com",
      "atlassian.design",
      "*.atlassian.com",
      "*.prod-apse.frontend.public.atl-paas.net",
      "*.us-west-2.prod.public.atl-paas.net",
      "*.atl-paas.net",
      "*.prod.atlassian-dev.net",
      "*.sbox.shared.atlassian-3p.com",
      "bitbucket.io",
      "*.prod-east.frontend.public.atl-paas.net",
      "*.remix.prod.atlassian-dev.net",
      "*.atlassian.dev",
      "teamworkgraph.com",
      "*.prod-west.frontend.public.atl-paas.net",
      "teamworkgraph.ai",
      "atlassian.dev",
      "*.pipelines-remote-access.shared.atlassian-3p.com",
      "apkg.io",
      "*.trello.com",
      "trello.com",
      "*.atlassian-isolated-3p.com",
      "*.kaizen.shared.atlassian-3p.com",
      "atlassian-3p.com",
      "atlassian.com",
      "*.prod-west2.frontend.public.atl-paas.net",
      "*.prod-euwest.frontend.public.atl-paas.net",
      "*.teamworkgraph.com",
      "*.bytebucket.org",
      "*.prod.atl-paas.net",
      "*.prod-eucentral.frontend.public.atl-paas.net",
      "rovo.com",
      "jira.com",
      "*.prod-apse2.frontend.public.atl-paas.net",
      "bitbucket.com",
      "*.atlassian-3p.com",
      "*.us-east-1.prod.public.atl-paas.net",
      "*.bitbucket.org",
      "atlassian-isolated-3p.com",
      "*.status.atlassian.com",
      "*.apkg.io",
      "bytebucket.org",
      "*.jira.com",
      "puds.prod.atl-paas.net",
      "*.prod.public.atl-paas.net"
    ],
    "days_left": 137,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.49",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Capture, organize, and tackle your to-dos from anywhere"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: AtlassianEdge"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.trello.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://trello.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 45.6,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
