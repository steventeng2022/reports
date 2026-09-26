# Security Audit Report — calendly.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://calendly.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | calendly.com |
| Test date | 2026-09-25 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 11 | low | CORS1 | CORS: subdomain origin origin accepted with credentials | CWE-942 |
| 12 | info | CT1 | 49 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 13 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.175:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.41.175:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 11. [LOW] CORS: subdomain origin origin accepted with credentials (`CORS1`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.calendly.com -> Access-Control-Allow-Origin: https://sub.calendly.com, Allow-Credentials: true.
- **Context:** https response, /
- **Recommendation:** Validate origins and avoid echoing arbitrary origins with credentials.

### 12. [INFO] 49 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: ai-compute-staging.staging.calendly.com, ai-staging.staging.calendly.com, api.s-staging.calendly.com, api.s.calendly.com, careers.calendly.com, ci-transcription.mi-recall.staging1.staging.calendly.com, dev.calendly.com, gke-hello.j-test2.dev1.dev.calendly.com, gke-hello.jason-r5rmr.staging4.staging.calendly.com, gke-hello.jason-test-spfcc.dev1.dev.calendly.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 13. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: ai-compute-staging.staging.calendly.com, ai-staging.staging.calendly.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "calendly.com",
  "dns": {
    "a": [
      "104.18.41.175",
      "172.64.146.81"
    ],
    "aaaa": [
      "2606:4700:440d::6812:29af",
      "2606:4700:4403::ac40:9251"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "hope.ns.cloudflare.com.",
      "roan.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=cDMxTqEGKRREjpULRkV3kxo9fUh9AAOy68UKi-sWFDA",
      "carta-domain-verification-p6kprv=Hf8pYNQgbK7i64r9SjTorb0sB",
      "zoom-domain-verification = afd6de76-b579-11ee-a506-0242ac120002",
      "citrix-verification-code=ecbbb3b7-9c8c-4b46-81a7-ecd2c6ff42b9",
      "slack-domain-verification=025CLyam48F5ppYztUuMl2Ue4prf01SVmyM06BYy",
      "jetbrains-domain-verification=1k4crjxnjx7wtlhja236t8jcn",
      "onetrust-domain-verification=0bf92d345265462eb0a4ad38c7b55188",
      "google-site-verification=fnhE2QNlMBUWS8UBhCtO4N2xU1Hv5Baq_nAGRKrDOS8",
      "pardot906932=62a94517bea65a4a146e19a380714f589e54114888b639e208605e1b6b445f47",
      "google-site-verification=CT9vkalOAxTSSlMkSYuif3PPR9IfW9wOMDYCpHV8-pQ",
      "pendo-domain-verification=4dace321-4517-49a6-b51a-ec3478a24002",
      "MS=ms75363840",
      "google-site-verification=l9ghJl2k5pCmyzxgB-u7zk1WdLHRxZ8Gev7eo7j6tlw",
      "MS=ms75932089",
      "jamf-site-verification=iYyCRUNw7_AXFUC7zaLiFw",
      "doit-verify295235",
      "pardot906932=d83df604fb40dd187d6c3def3b29591478a195def3dd9223df3d64f3fbabfd0c",
      "google-site-verification=D6kljg6Ozbxz7wkQHTu9bBD58dH48qXc8jbrSvdix20",
      "google-site-verification=A_dMlj5RIS-42bZbR1vzM__GBhqE_l-CNAt4kHL39K8",
      "google-site-verification=spiNl55E3iYMilE9lM2OB67FTeyJVzNJdYsr8YreMiE",
      "box-domain-verification=a9f4a950cfdfd3b9cea802a96528ccffbff61184fbb8363037b8cb9eeb1e454c",
      "atlassian-domain-verification=HeV4orUbu8ZU/Et3BdlguiFnoc5TqgI5owEFFTeBLYX6Lc6BZK4D0ru001VnnLBk",
      "qase-ca7eb2da8082aef5bed402accf262d2bca41fd30",
      "openai-domain-verification=dv-60PIOwHK0eRDfc2VpmSJ3XY3",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:_spf.google.com include:mktomail.com ~all",
      "google-site-verification=4IlbzuraJEuEWHXSF1ealAXGwgl-01bcFI9b6KiPrzw",
      "postman-domain-verification=987281567d45964ffbd83330939d1731ef9199ac6408ad6a641d49813877d64f73114ad25d917bbe3babf4cf554437d1034afcd089f0faf69bbd9c6d9473df5b",
      "hubspot-developer-verification=MDZjM2Q5Y2QtYjIxOS00ZTllLWIzYzEtMzI2YzYwZTQxY2My",
      "uber-domain-verification=7898f9ad-15df-4820-b779-92b2bec7858b",
      "adobe-idp-site-verification=db378e2b6b1fbb203e2fa8efb4daacdd0b5837d143bd0020257d69866acc6b55",
      "google-site-verification=0W2XISvsFG0b1de6rAJqnGOZpeyHioDOc0fCPpkcga0",
      "pardot986361=84e628bbfec0a11d5baf3b0d9631a46a0e5f6801076cfc694ca8631fc86ee0b2",
      "apple-domain-verification=eAu2dlDrzmPvVHPg",
      "google-site-verification=vvI2V5xXtswv19eoBHMvUfLriiS1W3uTeOrHdusW3AI",
      "stripe-verification=7708116a2a258908ad3dde9ebc9ab342c43b7000f582962f69a7fdcab307abab",
      "06FB0F4CCD",
      "docusign=26d57faa-4bf8-45cd-866b-a36fdf86e214",
      "parallels-domain-verification=25c15af2f44f426fa520c0f140c5f3b884327a61390a439495a1e7fa2ee9cf92",
      "facebook-domain-verification=oiiy3kxhh6i3mzo3tecoolwkzpsqos",
      "logmein-verification-code=b644b816-e7f4-45df-8215-6ba8db765fe9",
      "loom-site-verification=dfbd3882de7e42d39aa63ac12d8f403e",
      "ePwEbxX6T8GLeUY2",
      "h1-domain-verification=jcUKHuDrikH5HZfj3S3op6kzWDJLgLg3d7pmxsKGupBKUPm1",
      "TAILSCALE-nNYYC0vC9TISAvboCaQA",
      "calendly-site-verification=JLJojO5SGco45xeUJrgD30rJACtPP9JsvM1TDRUSa",
      "cursor-domain-verification-tdtnd4=i4bl9JEOFE1VOQbkiMkpIfGQZ",
      "MS=ms26783193",
      "pardot906932=75d30f44d6d6e89f6ea5ce36bff2d547056f93c17f7034160851f23f09a2448a",
      "miro-verification=c546481c526d7d0fca4b0def39a0700eeb64f077"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=calendly.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep  4 14:05:28 2026 GMT",
    "notAfter": "Dec  3 14:05:27 2026 GMT",
    "san": [
      "*.calendly.com",
      "ablink.e.calendly.com",
      "ablink.send.calendly.com",
      "calendly.com"
    ],
    "days_left": 68,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.41.175",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Meeting Scheduling Software and AI Meeting Tools | Calendly"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "samesite": "strict"
    },
    {
      "samesite": "strict"
    },
    {
      "samesite": "lax"
    },
    {
      "domain": "calendly.com",
      "samesite": "none"
    },
    {
      "domain": "calendly.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.calendly.com",
      "acao": "https://sub.calendly.com",
      "acac": "true"
    }
  ],
  "http": {
    "status": 301,
    "location": "https://calendly.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 49,
    "notable": [
      "ai-compute-staging.staging.calendly.com",
      "ai-staging.staging.calendly.com",
      "api.s-staging.calendly.com",
      "api.s.calendly.com",
      "careers.calendly.com",
      "ci-transcription.mi-recall.staging1.staging.calendly.com",
      "dev.calendly.com",
      "gke-hello.j-test2.dev1.dev.calendly.com",
      "gke-hello.jason-r5rmr.staging4.staging.calendly.com",
      "gke-hello.jason-test-spfcc.dev1.dev.calendly.com",
      "gke-hello.np-upgrade2.dev1.dev.calendly.com",
      "gke-hello.og-pub.dev1.dev.calendly.com",
      "gke-hello.pub-nonat4.dev1.dev.calendly.com",
      "gke-hello.quota-test.dev1.dev.calendly.com",
      "gke-hello.reg-test.dev1.dev.calendly.com"
    ],
    "sample": [
      "ablink.e.calendly.com",
      "ablink.send.calendly.com",
      "ai-compute-staging.staging.calendly.com",
      "ai-compute.production.calendly.com",
      "ai-staging.staging.calendly.com",
      "api.s-staging.calendly.com",
      "api.s.calendly.com",
      "calendly.com",
      "careers.calendly.com",
      "ci-transcription.mi-recall.staging1.staging.calendly.com",
      "ci-transcription.mi-recall.us1.production.calendly.com",
      "clm-test.calendly.com",
      "community.calendly.com",
      "dev.calendly.com",
      "dfp.calendly.com",
      "dse-test.calendly.com",
      "evs.s-staging.calendly.com",
      "evs.s.calendly.com",
      "gke-hello.j-test2.dev1.dev.calendly.com",
      "gke-hello.jason-r5rmr.staging4.staging.calendly.com"
    ],
    "dangling": [
      "ai-compute-staging.staging.calendly.com",
      "ai-staging.staging.calendly.com"
    ]
  },
  "elapsed_s": 16.9,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
