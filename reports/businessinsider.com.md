# Security Audit Report — businessinsider.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://businessinsider.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | businessinsider.com |
| Test date | 2026-09-25 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | CT1 | 37 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 12 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] 37 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: gcp.businessinsider.com, it.businessinsider.com, my.businessinsider.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 12. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: gcp.businessinsider.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "businessinsider.com",
  "dns": {
    "a": [
      "151.101.129.171",
      "151.101.1.171",
      "151.101.193.171",
      "151.101.65.171"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 10)",
      "aspmx3.googlemail.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "dns2.p03.nsone.net.",
      "dns3.p03.nsone.net.",
      "ns31.constellix.com.",
      "dns1.p03.nsone.net.",
      "ns11.constellix.com.",
      "ns51.constellix.net.",
      "dns4.p03.nsone.net.",
      "ns21.constellix.com.",
      "ns61.constellix.net.",
      "ns41.constellix.net."
    ],
    "spf": [
      "google-site-verification=MeuJIyKOrXf6e1Foju5Tqkzoms8KH0IoP01G5KhB-m8",
      "google-site-verification=hVwc4FIT_C_8DNSPQSBmv84brU443LMUlfiyDqrByVA",
      "globalsign-domain-verification=qhllLTVNbc63_k7N_0u2VjkgHnq48qKQ8gKVvHWkHI",
      "zapier-domain-verification-challenge=e10fad84-5944-470d-ae77-5d7697d0af05",
      "facebook-domain-verification=jz79wu26i92i5zpxpqra4s1p1ois9j",
      "_globalsign-domain-verification=O81xyb7YxpdGeHWkniit_VBT4vTXz9__NFrNMoTwFg",
      "google-site-verification=lhkw5_yE2VpatfjtNqFeTXshSdHOmye2FSHCz4_IZwE",
      "canva-site-verification=yOD8mjIYFWLM6qJQW-rwgg",
      "google-site-verification=dsTQoEYtkhKJUiHaf7NXBGBP5wRxmQ2ia56y9UnTeZc",
      "00Dd0000000cyqM=1TBQK00000000rF",
      "apple-domain-verification=G59n_HIhMNvtkyEDlx0g1LdxhRL8neVCOkZ-NcIa0cQ",
      "google-site-verification=HA4gcc-DAPuEX5Z3gfg-LTrtafWTIr40orlRHKZSLy0",
      "ZOOM_verify_BiuNcpuc03G4NjRCC8crLr",
      "google-site-verification=6siIDX8Eh0aPCTSxDF2-GFuuFff1H1aPGm3SfPvP7aI",
      "MS=49384EFC2AA5C920CC726E72850EA7250E18356F",
      "google-site-verification=5khzg7Aljjht1XobmkoQeX_2L4E5UJO9C1Z9_zfFTYs",
      "google-site-verification=E4A9jU1go8SQoOYqjwybQIyUhIqPRDUF2Fu5nYC77oM",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXlTSpjtg1iNnMasAJ3GsD",
      "openai-domain-verification=dv-jTz4KfMtiA6SiWiVpka2QDFr",
      "slack-domain-verification=p1y98UQQ7JwUhAuHWXgLsJqM1VDqn56eErx227bu",
      "asv=4f7bed0ed9307319569dca0dc413d303",
      "lucidlink-verification=H13VJ94S9GRFM6ZX539Q5EB8MG",
      "atlassian-domain-verification=EnHue3UwYSfo4DXgk/Bvg3WcQ2JVjyt6zf38Dox2HOZXITSpjtg1iNnMasAJ3GsD",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:_spf.salesforce.com ~all",
      "openai-domain-verification=dv-gEVeLfZWhh8fDqhgX7be0VGh"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@insider.com; ruf=mailto:dmarc-reports@insider.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=businessinsider.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign Atlas R3 DV TLS CA 2026 Q1",
    "notBefore": "Feb 11 19:00:25 2026 GMT",
    "notAfter": "Mar 15 19:00:24 2027 GMT",
    "san": [
      "businessinsider.com"
    ],
    "days_left": 171,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.129.171",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: Varnish"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.businessinsider.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.businessinsider.com/"
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
    "source": "certspotter",
    "count": 37,
    "notable": [
      "gcp.businessinsider.com",
      "it.businessinsider.com",
      "my.businessinsider.com"
    ],
    "sample": [
      "account-dev.businessinsider.com",
      "account.businessinsider.com",
      "advertising.businessinsider.com",
      "africa.businessinsider.com",
      "businessinsider.com",
      "comments.businessinsider.com",
      "consent.markets.businessinsider.com",
      "coupons.businessinsider.com",
      "e.businessinsider.com",
      "gcp.businessinsider.com",
      "i-dev-cf.businessinsider.com",
      "info.businessinsider.com",
      "ing-images.businessinsider.com",
      "it.businessinsider.com",
      "l.businessinsider.com",
      "live.businessinsider.com",
      "login-dev.businessinsider.com",
      "markets.businessinsider.com",
      "my-dev.businessinsider.com",
      "my.businessinsider.com"
    ],
    "dangling": [
      "gcp.businessinsider.com"
    ]
  },
  "elapsed_s": 12.7,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
