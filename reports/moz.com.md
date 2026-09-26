# Security Audit Report — moz.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://moz.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | moz.com |
| Test date | 2026-09-25 10:02 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 3, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 8 | low | H2 | Missing CSP header | CWE-1021 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.64.25:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.16.64.25:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=2592000 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 8. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 9. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 10. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 11. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "moz.com",
  "dns": {
    "a": [
      "104.16.64.25",
      "104.16.127.24"
    ],
    "aaaa": [
      "2606:4700::6810:4019",
      "2606:4700::6810:7f18"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 40)",
      "aspmx3.googlemail.com (pref 50)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "alla.ns.cloudflare.com.",
      "karl.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=-2xOD6UrAQv_tNO6Auum4Di0T_b-JIkVZVL5DUuY9gE",
      "bc6c0735020041da878699ad1e6865b9",
      "docusign=b5f4fc26-d624-472f-916e-be13ad191a51",
      "stripe-verification=18b9aeaac5c7db0d57e521bef3f925d40471d026b5263b76386c192a40d04094",
      "google-site-verification=W8sczjwGpAVj0AwI56aOpLnr9QkYELeVFksaaSmorQY",
      "cursor-domain-verification-xfe2k4=jq0PCDhMiDNXhbfIPFtgY3ecU",
      "atlassian-domain-verification=QUsZX4LdPWTYZgx09JhShFot27EJnUl/5CyxXFsiGebXl2QD8Fh3zzfkYZJe42Ic",
      "teamviewer-sso-verification=d3c5a1ad7c6c4594b06cf03702863556",
      "v=spf1 include:_spf.google.com include:2886781.spf01.hubspotemail.net include:mail.zendesk.com include:amazonses.com include:_spf.smtp.com include:_spf.salesforce.com ip4:192.40.176.17/32 ip4:192.40.176.18/31 ~all",
      "atlassian-domain-verification=qaVThwiX6U67ZIy0EBDXXb7KGLa5atdF7YrsL4WSLvJUpyd98hNZpPOSjtmscytI",
      "cloudhealth=e5c1f20d-0921-48bd-8845-769ca1a28eb0",
      "knowbe4-site-verification=f8a0eecde40ecb172ead956570d9179c",
      "openai-domain-verification=dv-KeQmqjmjNx2VL6SVSvGuCtBn",
      "atlassian-domain-verification=ais6F15PUaVYoFUzdWkVhKUITK+2UW8BV+Prmd71cBBFC/73YuxXPiLYXWHGfrkI",
      "docker-verification=4a939ab4-d6ef-447c-ba3b-26cad14a0619",
      "google-site-verification=RIhThOSaCCGWYVN3cDCHQCFUpyGdXiN4MCnbRbZFkAY",
      "google-site-verification=rDkrzYNA-m4FC6AKeZ1d5mYKl02VGu438r_kLWzuYGY",
      "zapier-domain-verification-challenge=6310926b-0d6e-4194-9469-54942fda3750",
      "MVNCENTRAL-7735",
      "stripe-verification=f1e0852092ff90300fdcc180864ba044b04cb485605abeb2ead0a4b2e768f078",
      "facebook-domain-verification=d610r60v1y48jvfs0grtgo59ueh1db",
      "tollbit-domain-verification=98375727b42ff3176aa408092bfa1854563221fa6f0d64891e62db111763b9a0",
      "zendeskverification.moz.com=283dd8e30cab7c30",
      "stripe-verification=f1dc55fec68a82a87b55c1d1d96e1d927f0508547932e52ee2a2d136c39ba227",
      "google-site-verification=Ojzzpw0y5g5RLxGnkVSHkA3pYUu76XonzxpbVVnS47g",
      "pendo-domain-verification=f9a24257-9d80-423d-81a9-fbd3c65cf433",
      "stripe-verification=51BEF67C3B1EF40AC20D9413296F7414370646A39E58673F790CA9D173A95E93",
      "canva-site-verification=BlqjLmS_JEvEk5kuYiJNkg",
      "miro-verification=2c6e56ff03a0434678621253eb6bc4b02772a446",
      "airtable-verification=ca0889850dbeee47cedc12537e59438f",
      "google-site-verification=0dVASzy6Ecn6zMkNRgUbgd4AO6EbbmY1R_bjz2ni4ns",
      "stripe-verification=1D2B2A9419F443824C62198552C6C5EDB1075E786353169FD8446EFA655A80CE",
      "workplace-domain-verification=aX6fdWT1pAZx9PNAPPUNKdc2UHBkPP",
      "adobe-idp-site-verification=cd8dab640ab786a9457c8757f4188cd682dd687a694d1d9c251e9ef54140a0ec",
      "google-site-verification=wnDxq7QQUdAAzCwmzR96eARzyv26_h0K9rd7TEYVRbY",
      "onetrust-domain-verification=2cab83837fea449daed73c76571b4987",
      "google-site-verification=OOIlmzCB32MZxONvYaHhVz1mQZ9Vxi5GpsH79-DJ3wg",
      "anthropic-domain-verification-rdmxkk=fa3qnDuce9wR9UQdaP8HIBJJC",
      "segment-site-verification=Vta003Ip8NYORFgGkNzPqLg5f2qNZzFD",
      "stripe-verification=970b0b83f1523e0f3e137e0f833aa3ce62a396b82bfff081a14225e48bfb49d5"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:088836b424@rua.easydmarc.us;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=moz.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 11 03:43:20 2026 GMT",
    "notAfter": "Dec 10 04:43:17 2026 GMT",
    "san": [
      "moz.com",
      "*.moz.com"
    ],
    "days_left": 75,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.16.64.25",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "Moz - SEO Software for Smarter Marketing"
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "moz.com",
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
      "origin": "https://sub.moz.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://moz.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 308
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 24.8,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
