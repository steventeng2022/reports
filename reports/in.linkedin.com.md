# Security Audit Report — in.linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://in.linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | in.linkedin.com |
| Test date | 2026-09-26 01:45 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 1, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 9 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 10 | info | CT1 | 1 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.41:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Java session cookie (J2EE); Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'sdui_ver' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 9. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'sdui_ver' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 10. [INFO] 1 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: none flagged
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "in.linkedin.com",
  "dns": {
    "a": [
      "104.18.41.41",
      "172.64.146.215"
    ],
    "aaaa": [
      "2a06:98c1:310b::ac40:92d7",
      "2a06:98c1:3109::6812:2929"
    ],
    "cname": "cctld.linkedin.com.",
    "mx": [],
    "ns": [],
    "spf": [],
    "dmarc": [],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=ep.linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Sep  3 00:00:00 2026 GMT",
    "notAfter": "Mar  3 23:59:59 2027 GMT",
    "san": [
      "ep.linkedin.com",
      "er.linkedin.com",
      "es.linkedin.com",
      "et.linkedin.com",
      "eu.linkedin.com",
      "ev.linkedin.com",
      "ew.linkedin.com",
      "fi.linkedin.com",
      "fj.linkedin.com",
      "fk.linkedin.com",
      "fl.linkedin.com",
      "fm.linkedin.com",
      "fo.linkedin.com",
      "fq.linkedin.com",
      "fr.linkedin.com",
      "fx.linkedin.com",
      "ga.linkedin.com",
      "gb.linkedin.com",
      "gc.linkedin.com",
      "gd.linkedin.com",
      "ge.linkedin.com",
      "gf.linkedin.com",
      "gg.linkedin.com",
      "gh.linkedin.com",
      "gi.linkedin.com",
      "gl.linkedin.com",
      "gm.linkedin.com",
      "gn.linkedin.com",
      "gp.linkedin.com",
      "gq.linkedin.com",
      "gr.linkedin.com",
      "gs.linkedin.com",
      "gt.linkedin.com",
      "gu.linkedin.com",
      "gw.linkedin.com",
      "gy.linkedin.com",
      "hk.linkedin.com",
      "hm.linkedin.com",
      "hn.linkedin.com",
      "hr.linkedin.com",
      "ht.linkedin.com",
      "hu.linkedin.com",
      "hv.linkedin.com",
      "ib.linkedin.com",
      "ic.linkedin.com",
      "id.linkedin.com",
      "ie.linkedin.com",
      "il.linkedin.com",
      "im.linkedin.com",
      "in.linkedin.com",
      "io.linkedin.com",
      "iq.linkedin.com",
      "ir.linkedin.com",
      "is.linkedin.com",
      "it.linkedin.com",
      "ja.linkedin.com",
      "je.linkedin.com",
      "jm.linkedin.com",
      "jo.linkedin.com",
      "jp.linkedin.com",
      "jt.linkedin.com",
      "ke.linkedin.com",
      "kg.linkedin.com",
      "kh.linkedin.com",
      "ki.linkedin.com",
      "km.linkedin.com",
      "kn.linkedin.com",
      "kp.linkedin.com",
      "kr.linkedin.com",
      "kw.linkedin.com",
      "ky.linkedin.com",
      "kz.linkedin.com",
      "la.linkedin.com",
      "lb.linkedin.com",
      "lc.linkedin.com",
      "lf.linkedin.com",
      "li.linkedin.com"
    ],
    "days_left": 158,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.41.41",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Log In or Sign Up | LinkedIn"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Java session cookie (J2EE)",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": ".linkedin.com"
    },
    {
      "domain": ".in.linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".in.linkedin.com",
      "samesite": "none"
    },
    {
      "domain": ".linkedin.com",
      "samesite": "none"
    },
    {
      "domain": "linkedin.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.in.linkedin.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://in.linkedin.com/hp"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 400",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "crt.sh",
    "count": 1,
    "notable": [],
    "sample": [
      "in.linkedin.com"
    ]
  },
  "elapsed_s": 25.2,
  "rechecked": "2026-09-26 01:45 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
