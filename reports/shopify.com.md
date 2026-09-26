# Security Audit Report — shopify.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://shopify.com/ |
| Bug bounty program | Shopify |
| Listed scope domain | shopify.com |
| Test date | 2026-09-25 10:14 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 3, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 23.227.38.33:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 23.227.38.33:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "shopify.com",
  "dns": {
    "a": [
      "23.227.38.33"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "gold.foundationdns.com.",
      "gold.foundationdns.net.",
      "gold.foundationdns.org."
    ],
    "spf": [
      "ca3-86f15a314f3342baac2abe7a8849163c",
      "openai-domain-verification=dv-SSeJm7iAiW11oexpj9ZCqdil",
      "klaviyo-site-verification=UfTdFX",
      "apple-domain-verification=eMDCoIZdcJThX3yQ",
      "google-site-verification=96L28-MtSBLeQmyYR04q9iKI_Ib5qZd0YzVL8s1_gD0",
      "openai-domain-verification=dv-3UNPEg4DuUI5Ace0uw1hzLq3",
      "atlassian-domain-verification=aakXh8UjEwy75X6ck4l8jTIJDWHQ9CIunnUsE00mRgxM8IUzaJGlIt8zIINLFALR",
      "globalsign-domain-verification=lfM-pzwumuFWKV-wNEGq7a3KtsmRLJKsDxZzQaMjkw",
      "klaviyo-site-verification=VbLhyy",
      "yahoo-verification-key=9t6XYs7YEajKycpYmHz742ZV/lm84njkfUfGUldOtZM=",
      "google-site-verification=a4GkGdS7vBnkI284VSCo4bfYDNg-8OcEyjz8PR8ZhDM",
      "qqmail-site-verification=bc0dd9aa889c6a66d9a58b31e496873cc7ae214ca8f",
      "zapier-domain-verification-challenge=506c545d-443f-4439-8d84-64648211b1f1",
      "openai-domain-verification=dv-2etxemuOx7cXQDQ5EjEWGZ9A",
      "autodesk-domain-verification=e9Nbi4FUDsS7clWU8iNj",
      "klaviyo-site-verification=UBeZ6P",
      "klaviyo-site-verification=VrspSg",
      "stripe-verification=61e8fb112f5e7ac2708127ea93fd0369d6a4f768bd498fd0d928c206a6240bd7",
      "lucidlink-verification=7VB3ACRNY28GWP54ZC3YXN7QWR",
      "klaviyo-site-verification=Y2Hvrx",
      "twilio-domain-verification=ebc01f01cee0f1aea3f4c069b8865de9",
      "teamviewer-sso-verification=85d99b4ff4b64f03a469d0c42c1eee61",
      "globalsign-domain-verification=Cpw4zOAIT5WSnINjnI4gafPgxsCJlEF4Ac_70Xm93I",
      "MS=ms27001972",
      "linear-domain-verification=3xuktyudsdny",
      "facebook-domain-verification=u17rffysxyek688vqh4s02307suaza",
      "drift-domain-verification=9b23e1f43b57171c988b4510e75a686bda241639096f7eaabe8ff3d72ac63476",
      "v=spf1 include:_spf.google.com include:mail.zendesk.com include:sendgrid.net ~all",
      "docusign=de9614db-a0fa-4060-a1fa-2c444429ed9a",
      "ca3-fc9272b0aba34ba6991c0a62bc1998a0",
      "adobe-idp-site-verification=45576d365ff5492a15bc403c11382aad83403810324300fd62c5f196ce9e9063",
      "mongodb-site-verification=vBP464dSOK9bgg6FWBthUMqVjYfqnjuY",
      "google-site-verification=0nU18bxQue6doDAWZDptfd66kTIqHqW00fDhfJSd9es",
      "00078847",
      "0lc931fl5ld2dpl15vx2flfkdwyvrrzx",
      "mailru-verification: a6784d11ca5a5f7b",
      "liveramp-site-verification=N48gDNFN3IB2NKIf75Fl46_sUzjxAbY3c1mfWs5pIKM",
      "_globalsign-domain-verification=_PJNYsq_1XyZleC1yx45rb_EUgbgkaJU36yk3CK0tk",
      "rfs0f736s88q7ml97jw9qhg1yy2wmdy5",
      "klaviyo-site-verification=XxDdwy",
      "google-site-verification=knwYi_vDES4v7XUl8OOtP4gu4qhwAzIBbeB2ou2jx8Y",
      "_globalsign-domain-verification=1x11a1Wg3i08rScgK7aAMUJm_fdzKxH4whkWxr1bbg",
      "klaviyo-site-verification=RcWeYn",
      "klaviyo-site-verification=SuEeFy",
      "klaviyo-site-verification=SA72ug",
      "google-site-verification=Vm4475oXq82Dl_WCtZcmlaW3xrpB-6fyQXboHBjzzPY",
      "klaviyo-site-verification=YA4hNy",
      "bitrise-verification=990e159e8448fcb6-hCIxnrabFeH9",
      "google-site-verification=vEpSvWK6hOKDBrCrJ4uUeCliFPV0nyP9m_UCOEjJv1Q",
      "amazonses:CxAO0EM1odef6TrFP0hDQh/2R7RoZYy8YlHYktk2Frk=",
      "protonmail-verification=c7bd7e61072d9855cfcab2f08804404f639439f9",
      "dtm-domain-verification=LhGwRr1DLWJoF6bVodh035n_BRj4Xu8PaEZ6bvvgd2Y",
      "rzp-site-verification=0c152e27933f70c5c7df025be3319f65"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc-aggregate@shopify.com;ruf=mailto:dmarc-reports@shopify.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=shopify.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 10 18:38:02 2026 GMT",
    "notAfter": "Nov  8 19:37:54 2026 GMT",
    "san": [
      "shopify.com",
      "*.shopify.com"
    ],
    "days_left": 44,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.227.38.33",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.shopify.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.shopify.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 20.6,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
