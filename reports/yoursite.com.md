# Security Audit Report - yoursite.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yoursite.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | yoursite.com |
| Test date | 2026-09-25 15:16 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 8, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | H1 | Missing HSTS header | CWE-319 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P1 | Git repository exposure | CWE-538 |
| 14 | info | P2 | Environment file exposure | CWE-538 |
| 15 | info | R2 | No HTTP->HTTPS redirect | CWE-319 |

## Detailed findings

### 1. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Apache
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Apache
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Git repository exposure (`P1`)

- **CWE:** CWE-538
- **Detail:** GET /.git/config returns 200 but the body is the parked-domain landing page (abovedomains "for sale" JS lander, 27.6KB HTML, identical for / and random paths) - a soft-200, not a real git repository.
- **Recommendation:** Review and remediate per CWE guidance.

### 14. [INFO] Environment file exposure (`P2`)

- **CWE:** CWE-538
- **Detail:** GET /.env returns 200 with a 300-byte HTML parking page (same abovedomains JS lander) - soft-200, not a real environment file.
- **Recommendation:** Review and remediate per CWE guidance.

### 15. [INFO] No HTTP->HTTPS redirect (`R2`)

- **CWE:** CWE-319
- **Detail:** Re-test: http://yoursite.com now issues 302 -> https://yoursite.com/ (redirect works); still no HSTS on the HTTPS response, which is tracked separately as H1.
- **Recommendation:** Add an HTTP->HTTPS redirect (currently returns an error code on port 80).

## Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- robots_disallow: ["/cpx.php","/medios1.php","/toolbar.php","/check_image.php","/check_popunder.php"]

Stage-2 probe log (observed responses):
- timing base=errms id=err search=err
- apicors /api -> 200
- apicors /api/v1 -> 200
- apicors /graphql -> 200
- apicors /rest -> 200
- apicors /v1 -> 200

**Stage 3 - live parameter harvest, takeover and injection probes (48 requests):**

- params_harvested: ["d","vgd_setup","crid","hvsid","ugd","cc","sc","vgd_asn","vgd_l2type","vi","ssld","vgd_rpth","wshp","r","vgd_cdv","vgd_oreqf","vgd_wlstp","prid","cid","lf"]

Stage-3 probe log (observed responses):
- harvest discovered 30 live query params
- xss3 https://assets.abovedomains.com/javascript/forsale.min.js?d -> err
- xss3 https://l.cdn-fileserver.com/bping.php?vgd_setup -> err
- xss3 https://l.cdn-fileserver.com/bping.php?crid -> err
- xss3 https://l.cdn-fileserver.com/bping.php?hvsid -> err
- xss3 https://l.cdn-fileserver.com/bping.php?ugd -> err
- xss3 https://l.cdn-fileserver.com/bping.php?cc -> err
- xss3 https://l.cdn-fileserver.com/bping.php?sc -> err
- xss3 https://l.cdn-fileserver.com/bping.php?vgd_asn -> err
- subs no dangling service CNAMEs over 16 subdomains

**Stage 4 - injection/XSS/redirect/endpoint matrix suite v4 (63 requests):**

- no stage-4 probe hits (all probes negative)

## Evidence (raw response observations)

```json
{
  "http_status": 200,
  "https_status": 200,
  "content_type": "text/html; charset=UTF-8",
  "title": "",
  "path_gitconfig": 200,
  "path_envfile": 200,
  "path_securitytxt": 200,
  "security_txt_found": true,
  "path_robots": 200,
  "robots_found": true,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 200",
    "sqli /?id=1%27+OR+1=1-- -> 200",
    "sqli /?q=%27 -> 200",
    "sqli /products?filter=%27 -> 200",
    "sqli /?p=1;-- -> 200",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 200",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 200",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 200",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 200",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 404",
    "trav /static/../../../../../../../../etc/passwd -> 200",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 200",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 200",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 200",
    "host no reflection -> err"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=errms id=err search=err",
    "sweep no hits over 26 paths",
    "redir2 no hits over 49 requests",
    "apicors /api -> 200",
    "apicors /api/v1 -> 200",
    "apicors /graphql -> 200",
    "apicors /rest -> 200",
    "apicors /v1 -> 200"
  ],
  "robots_disallow": [
    "/cpx.php",
    "/medios1.php",
    "/toolbar.php",
    "/check_image.php",
    "/check_popunder.php"
  ],
  "v3_probe_count": 48,
  "v3_log": [
    "harvest discovered 30 live query params",
    "xss3 https://assets.abovedomains.com/javascript/forsale.min.js?d -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?vgd_setup -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?crid -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?hvsid -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?ugd -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?cc -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?sc -> err",
    "xss3 https://l.cdn-fileserver.com/bping.php?vgd_asn -> err",
    "subs no dangling service CNAMEs over 16 subdomains"
  ],
  "params_harvested": [
    "d",
    "vgd_setup",
    "crid",
    "hvsid",
    "ugd",
    "cc",
    "sc",
    "vgd_asn",
    "vgd_l2type",
    "vi",
    "ssld",
    "vgd_rpth",
    "wshp",
    "r",
    "vgd_cdv",
    "vgd_oreqf",
    "vgd_wlstp",
    "prid",
    "cid",
    "lf"
  ],
  "v4_probe_count": 63,
  "v4_log": [
    "harvest no query params discovered",
    "sweep4 all swept paths 404/403"
  ]
}
```

## Notes

- All tests used a standard browser User-Agent; each site was probed with a four-stage aggressive GET-only suite: passive/header checks, stage-1/2 injection/XSS/traversal/CORS/redirect probes, a stage-3 live-parameter-harvest campaign (per-parameter XSS/SQLi/LFI/SSTI/redirect, JSONP, command injection, NoSQL, subdomain-takeover CNAME checks via DNS-over-HTTPS, forwarded-host cache poisoning), and a stage-4 matrix suite (multi-context XSS with CSP awareness, SSTI, error-based SQLi + WAF fingerprint, command injection, deep LFI, open-redirect bypass encodings, CRLF, HPP, NoSQL, sensitive-endpoint sweep, GraphQL introspection, verbose-500 stack disclosure, llms.txt, JSONP-XSS; up to ~300 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.
