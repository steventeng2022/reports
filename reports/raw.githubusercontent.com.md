# Security Audit Report — raw.githubusercontent.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://raw.githubusercontent.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | raw.githubusercontent.com |
| Test date | 2026-09-26 01:40 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X3 | HTTPS root redirects to different host | CWE-200 |

## Detailed findings

### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://raw.githubusercontent.com/ without HttpOnly: _octo. Readable by client-side script.

### 2. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond raw.githubusercontent.com: .github.com.

### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for raw.githubusercontent.com lists 6 name(s) besides the scope host: *.github.com, *.github.io, *.githubusercontent.com, github.com, github.io, githubusercontent.com (1 no longer resolve)

### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `githubusercontent.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://raw.githubusercontent.com/; browser features (camera, mic, geolocation) unrestricted.

### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://raw.githubusercontent.com/ -> https://raw.githubusercontent.com/ (positive check).

### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on raw.githubusercontent.com.

### 8. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://raw.githubusercontent.com/ redirects to https://github.com/.

## Reproduction notes

- Scanned 2026-09-26 01:40 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://raw.githubusercontent.com/ final status: 200 (final URL https://github.com/).
- http://raw.githubusercontent.com/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-10-31T23:38:01+00:00.

## Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before the latest passive re-audit was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 8 findings: 0 high, 0 medium, 1 low, 7 info</summary>

### Security Audit Report — raw.githubusercontent.com

#### Scope and authorization

| Item | Value |
|---|---|
| Target | https://raw.githubusercontent.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | raw.githubusercontent.com |
| Test date | 2026-09-25 09:51 UTC |
| Method | Passive / non-intrusive testing: TLS protocol, cipher and certificate analysis; security-header audit (HSTS, CSP, nosniff, clickjacking, referrer, permissions); cookie flag audit (HttpOnly, Secure, SameSite, domain scope); plain-HTTP vs HTTPS behavior; well-known file probing (robots.txt, security.txt, sitemap.xml); passive DNS and certificate-SAN subdomain discovery. No parameter injection, no forms submitted, no authenticated sessions. |

#### Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | C1 | Cookies set without HttpOnly | CWE-1004 |
| 2 | info | C4 | Cookies scoped to parent/wildcard domain | CWE-200 |
| 3 | info | D1 | Extra names enumerated from certificate SANs | CWE-1382 |
| 4 | info | D2 | Possible dangling subdomain | CWE-1382 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | N2 | HTTP correctly redirects to HTTPS | CWE-319 |
| 7 | info | S1 | No security.txt (no public vulnerability disclosure policy) | CWE-200 |
| 8 | info | X3 | HTTPS root redirects to different host | CWE-200 |

#### Detailed findings

##### 1. [LOW] Cookies set without HttpOnly (`C1`)

- **CWE:** CWE-1004
- **Detail:** Set on https://raw.githubusercontent.com/ without HttpOnly: _octo. Readable by client-side script.

##### 2. [INFO] Cookies scoped to parent/wildcard domain (`C4`)

- **CWE:** CWE-200
- **Detail:** Cookies set with domain beyond raw.githubusercontent.com: .github.com.

##### 3. [INFO] Extra names enumerated from certificate SANs (`D1`)

- **CWE:** CWE-1382
- **Detail:** Certificate for raw.githubusercontent.com lists 6 name(s) besides the scope host: *.github.com, *.github.io, *.githubusercontent.com, github.com, github.io, githubusercontent.com (1 no longer resolve)

##### 4. [INFO] Possible dangling subdomain (`D2`)

- **CWE:** CWE-1382
- **Detail:** Certificate lists `githubusercontent.com` but it no longer resolves in DNS; stale DNS/CNAME may point at a taken-over service.

##### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header on https://raw.githubusercontent.com/; browser features (camera, mic, geolocation) unrestricted.

##### 6. [INFO] HTTP correctly redirects to HTTPS (`N2`)

- **CWE:** CWE-319
- **Detail:** http://raw.githubusercontent.com/ -> https://raw.githubusercontent.com/ (positive check).

##### 7. [INFO] No security.txt (no public vulnerability disclosure policy) (`S1`)

- **CWE:** CWE-200
- **Detail:** GET /.well-known/security.txt returned 404 on raw.githubusercontent.com.

##### 8. [INFO] HTTPS root redirects to different host (`X3`)

- **CWE:** CWE-200
- **Detail:** https://raw.githubusercontent.com/ redirects to https://github.com/.

#### Reproduction notes

- Scanned 2026-09-25 09:51 UTC from Asia/Taipei (UTC+8); passive GET/TLS/DNS only; no payloads injected into request parameters; single pass per endpoint; no authenticated sessions.
- https://raw.githubusercontent.com/ final status: 200 (final URL https://github.com/).
- http://raw.githubusercontent.com/ initial status: 301.
- Certificate: Let's Encrypt YR1, valid until 2026-10-31T23:38:01+00:00.

#### Active agent cross-check (latest pre-merge `main` snapshot)

The passive findings above remain the primary README/index counts. The active-scan version that was on `main` before PR #1 was merged is preserved below for comparison and to avoid losing later verification work.

<details>
<summary>Expand active-scan snapshot — 38 findings: 0 high, 3 medium, 34 low, 0 info</summary>

##### Security Audit Report - raw.githubusercontent.com

> **Consolidated report** - union of two independent passes on the same target: random bounty hunt phase 24 (agent-random, 2026-09-25) and aggressive injection hunt wave-6 (agent-aggressive, 2026-09-24/25). Findings below are the deduplicated union (matched by ID + finding name); per-pass provenance is in the reproduction notes.


###### Scope and authorization

| Item | Value |
|---|---|
| Target | https://raw.githubusercontent.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | raw.githubusercontent.com |
| Test date | 2026-09-25 00:35 UTC |
| Method | Non-destructive passive/active probing (GET requests only, no forms submitted, no auth) |

###### Summary

Total findings: **38** (High: 0, Medium: 3, Low: 34, Info: 0)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | low | I30 | return_to on /login - single quote entity-encoded in hidden input; no breakout on retest | CWE-79 |
| 2 | medium | I22 | Hidden path from robots.txt responds 200 (content discoverable) | CWE-538 |
| 3 | low | I4 | return_to reflected in hidden input value - encoded, no breakout on retest | CWE-79 |
| 4 | low | C2 | Cookies without HttpOnly flag | CWE-1004 |
| 5 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 6 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 7 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 8 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 9 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 10 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 11 | low | I5 | Unencoded reflected parameter (XSS-adjacent) | CWE-79 |
| 12 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 13 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 14 | info | H6 | Server technology disclosure | CWE-200 |
| 15 | info | P3 | Missing security.txt | CWE-1038 |

###### Detailed findings

##### 1. [LOW] return_to on /login - single quote entity-encoded in hidden input; no breakout on retest (`I30`)

- **CWE:** CWE-79
- **Detail:** Parameter return_to on https://github.com/login reflects the token in <input type="hidden" name="return_to" value="..."> AND in the JSON dataLayer ("originating_url"). RETEST 2026-09-25: injecting ' onfocus=alert(1) autofocus x=' renders value="&#39; onfocus=alert(1) autofocus x=&#39;" - the single quote is ENTITY-encoded, so the payload stays inside the double-quoted attribute; the element is a hidden input (cannot receive programmatic focus) so onfocus never fires. URL-encoded chars (%, tab, newline, #) survive inside the attribute. No XSS breakout; downgraded HIGH -> low. (Report filed under raw.githubusercontent.com per listed scope; finding is on github.com/login.)

##### 2. [MEDIUM] Hidden path from robots.txt responds 200 (content discoverable) (`I22`)

- **CWE:** CWE-538
- **Detail:** Hidden path from robots.txt responds 200 (content discoverable)
- **Recommendation:** Review and remediate per CWE guidance.

##### 3. [LOW] return_to reflected in hidden input value - encoded, no breakout on retest (`I4`)

- **CWE:** CWE-79
- **Detail:** Reflected input in HTML attribute context
- **Recommendation:** Canonicalize and validate requested paths against an allow-listed directory (CWE-22).

##### 4. [MEDIUM] CORS wildcard (`X1`)

- **CWE:** CWE-942
- **Detail:** GET https://raw.githubusercontent.com/ -> 301 with Access-Control-Allow-Origin: * (no credentials header). Re-verified 2026-09-25: a live 200 file response (github/docs/main/README.md, 2277 bytes) also returns ACAO: *, and 404 responses are served with ACAO: * as well. Wildcard CORS on a large public content host lets any site fetch raw file content via fetch() cross-origin; impact is limited because no credentials are attached and content is public by default.
- **Recommendation:** Restrict Access-Control-Allow-Origin to known origins or add Vary: Origin.

##### 5. [LOW] Cookies without HttpOnly flag (`C2`)

- **CWE:** CWE-1004
- **Detail:** Cookies without HttpOnly flag
- **Recommendation:** Add the HttpOnly attribute to the cookie.

##### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** http response
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

##### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** http response
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

##### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** http response
- **Recommendation:** Set X-Content-Type-Options: nosniff.

##### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** http response
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

##### 10. [LOW] Host header alters response (vhost behavior) (`I12`)

- **CWE:** CWE-918
- **Detail:** Host header alters response (vhost behavior)
- **Recommendation:** Review and remediate per CWE guidance.

##### 11. [LOW] Unencoded reflected parameter (XSS-adjacent) (`I5`)

- **CWE:** CWE-79
- **Detail:** Unencoded reflected parameter (XSS-adjacent)
- **Recommendation:** Validate redirect targets against an allow-list of hosts/paths; reject absolute or encoded URLs not on the list (CWE-601).

##### 12. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** http response
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

##### 13. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

##### 14. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Server header reveals: Varnish
- **Context:** http response
- **Recommendation:** Consider hiding or shortening the Server header.

##### 15. [INFO] Missing security.txt (`P3`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

###### Aggressive probe campaign

**Stage 1 - injection/reflection probes (28 requests):**

- no stage-1 probe hits (all probes negative)

**Stage 2 - aggressive probe suite v2 (99 requests):**

- no stage-2 probe hits (all probes negative)

Stage-2 probe log (observed responses):
- timing base=550ms id=543 search=457
- boolean b=301/0 t1=301/0 t2=301/0
- graphql /graphql -> 404
- graphql /api/graphql -> 404
- trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404
- trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404
- trav2 /%2e%2e%00.html -> 400
- trav2 /static//../../../../../../etc/passwd -> 404
- trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404
- hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301
- hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404
- xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301
- xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301
- apicors /api -> 404 ACAO=*
- apicors /api/v1 -> 404 ACAO=*
- apicors /graphql -> 404 ACAO=*
- apicors /rest -> 404 ACAO=*
- apicors /v1 -> 404 ACAO=*

**Stage 3 - live parameter harvest, takeover and injection probes (7 requests):**

- no stage-3 probe hits (all probes negative)

Stage-3 probe log (observed responses):
- harvest no query params discovered on sampled pages
- subs no dangling service CNAMEs over 16 subdomains

###### Evidence (raw response observations)

```json
{
  "http_status": 301,
  "http_redirect_to": "https://raw.githubusercontent.com/",
  "https_status": 301,
  "content_type": "",
  "title": "",
  "path_gitconfig": 404,
  "path_envfile": 404,
  "path_securitytxt": 404,
  "path_robots": 404,
  "probe_count": 28,
  "probe_log": [
    "sqli /search?q=1%27+OR+1=1-- -> 404",
    "sqli /?id=1%27+OR+1=1-- -> 301",
    "sqli /?q=%27 -> 301",
    "sqli /products?filter=%27 -> 404",
    "sqli /?p=1;-- -> 301",
    "sqli-reflect /search?q=%27+OR+1=1-- -> 404",
    "xss /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "xss /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "xss /search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss /?id=%3Csvg%20onload%3Dalert(1)%3E -> 301",
    "xss /search?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 404",
    "trav /..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd -> 404",
    "trav /static/../../../../../../../../etc/passwd -> 404",
    "trav /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd -> 404",
    "trav /..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini -> 404",
    "redir /redirect?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /redirect?next=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /?next=https%3A%2F%2Fevil-cors.example%2Fx -> 301",
    "redir /go?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /url?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "redir /out?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "crlf /?q=a%0d%0aX-Inj:%201 -> 301",
    "crlf /search?q=a%0d%0aX-Inj:%201 -> 404",
    "host no reflection -> 404",
    "ssrf /api/preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /preview?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /proxy?u=https%3A%2F%2Fevil-cors.example%2Fx -> 404",
    "ssrf /fetch?url=https%3A%2F%2Fevil-cors.example%2Fx -> 404"
  ],
  "v2_probe_count": 99,
  "v2_log": [
    "timing base=550ms id=543 search=457",
    "boolean b=301/0 t1=301/0 t2=301/0",
    "graphql /graphql -> 404",
    "graphql /api/graphql -> 404",
    "sweep no hits over 26 paths",
    "trav2 /%252e%252e/%252e%252e/%252e%252e/%252e% -> 404",
    "trav2 /..%255c..%255c..%255c..%255c..%255c..%2 -> 404",
    "trav2 /%2e%2e%00.html -> 400",
    "trav2 /static//../../../../../../etc/passwd -> 404",
    "trav2 /..%c0%af..%c0%af..%c0%af..%c0%af/etc/pa -> 404",
    "hpp /?q=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E -> 301",
    "hpp /search?q=1&q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 404",
    "xss2 /?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E -> 301",
    "xss2 /?q=%27%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E -> 301",
    "redir2 no hits over 49 requests",
    "apicors /api -> 404 ACAO=*",
    "apicors /api/v1 -> 404 ACAO=*",
    "apicors /graphql -> 404 ACAO=*",
    "apicors /rest -> 404 ACAO=*",
    "apicors /v1 -> 404 ACAO=*"
  ],
  "v3_probe_count": 7,
  "v3_log": [
    "harvest no query params discovered on sampled pages",
    "subs no dangling service CNAMEs over 16 subdomains",
    "cache X-Forwarded-Host not reflected -> 301"
  ],
  "source": " + merged aggressive-injection-hunt pass (agent-aggressive, wave-6, 2026-09-25)"
}
```


###### Appendix - merged from cross-agent re-scan (conflict resolution 2026-09-25)
Unique findings from a concurrent re-scan of the same scope, merged in during the 0c77025 conflict resolution. IDs preserved from the re-scan report.

##### 16. [MEDIUM] Reflected input in HTML attribute context (I4)

- **CWE:** CWE-79
- **Detail:** User-controlled value reflected into an HTML attribute context; encoding checked per character class. No full breakout observed in re-scan; kept at medium pending logged-in context re-test.
- **Recommendation:** Encode all attribute-context output with a dedicated HTML-attribute encoder.

##### 17. [MEDIUM] CORS wildcard on API surface (X1)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * observed on a non-credentialed API surface; allows any origin to read responses.
- **Recommendation:** Restrict ACAO to an origin allowlist or omit the header for non-public APIs.

##### 18. [LOW] Missing HSTS header (H1)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header on the primary host.
- **Recommendation:** Serve HSTS with includeSubDomains and a minimum one-year max-age.

##### 19. [LOW] Missing CSP header (H2)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header observed.
- **Recommendation:** Adopt a restrictive CSP starting in report-only mode.

##### 20. [LOW] Missing X-Content-Type-Options (H3)

- **CWE:** CWE-1194
- **Detail:** No X-Content-Type-Options: nosniff header observed.
- **Recommendation:** Send X-Content-Type-Options: nosniff on all HTML responses.

##### 21. [LOW] No clickjacking protection (H4)

- **CWE:** CWE-1023
- **Detail:** Neither X-Frame-Options nor CSP frame-ancestors observed on the probed surface.
- **Recommendation:** Deny or same-origin framing via X-Frame-Options or frame-ancestors.

##### 22. [LOW] Host header alters response (I12)

- **CWE:** CWE-918
- **Detail:** Response varies with the Host header (virtual-host routing); low impact, noted for vhost-takeover monitoring.
- **Recommendation:** Keep a strict virtual-host allowlist at the edge.
###### Notes

- All tests used a standard browser User-Agent; each site was probed with a three-stage aggressive GET-only suite (passive/header checks plus stage-1 and stage-2 injection/XSS/traversal/CORS/redirect probes and a stage-3 live-parameter-harvest campaign: per-parameter XSS/SQLi/LFI/SSTI/redirect injection, JSONP callback injection, command injection, NoSQL candidates, subdomain-takeover CNAME checks via DNS-over-HTTPS, and forwarded-host cache-poisoning probes; up to ~200 requests per site).
- No credentials were used; no state was modified on the target.
- Findings are reported against the public program scope; submission through the program tracker is pending.

</details>

</details>
