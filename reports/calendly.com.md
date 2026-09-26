# Security Audit Report — calendly.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://calendly.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | calendly.com |
| Test date | 2026-09-26 23:20 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **25** (High: 0, Medium: 0, Low: 5, Info: 20)

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
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 17 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 18 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 19 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 20 | info | ERR1 | Error-page technology fingerprint | CWE-200 |
| 21 | info | WK1 | App-association / digital-asset-links surface published | CWE-200 |
| 22 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 23 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 24 | info | CT1 | 49 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 25 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.146.81:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.146.81:8443 succeeded (state-only check, no payload sent).
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

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: miro-verification=c546481c526d7d0fca4b0def39a0700eeb64f077; cursor-domain-verification-tdtnd4=i4bl9JEOFE1VOQbkiMkpIfGQZ; parallels-domain-verification=25c15af2f44f426fa520c0f140c5f3b884327a61390a439495
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of calendly.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'CALENDLY_AUTHENTICATED_USER_STATUS' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 17. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 5 disallow path(s), e.g. /abuse_reports/new, /*?*, /app/, /, /
- **Recommendation:** Review disallowed paths; robots is not access control.

### 18. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '__cf_bm' set on calendly.com indicates Cloudflare bot-management cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 19. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '_cfuvid' set on calendly.com indicates Cloudflare visitor cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 20. [INFO] Error-page technology fingerprint (`ERR1`)

- **CWE:** CWE-200
- **Detail:** GET /xkc6tdeew5ez4i.html -> 404; error page/headers match: CloudFront, Cloudflare.
- **Recommendation:** Trim error-page banners/headers so stack details are not disclosed on error responses.

### 21. [INFO] App-association / digital-asset-links surface published (`WK1`)

- **CWE:** CWE-200
- **Detail:** Live JSON at /.well-known/apple-app-site-association and /.well-known/assetlinks.json on calendly.com; a mobile app or web-bridge is tied to this domain and its association configuration is public.
- **Recommendation:** Review the published association (URL teams, assets) for stale entries; watch for subdomain-takeover misuse.

### 22. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of calendly.com embeds 1 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-W3RGHP8; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 23. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on calendly.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 24. [INFO] 49 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: ai-compute-staging.staging.calendly.com, ai-staging.staging.calendly.com, api.s-staging.calendly.com, api.s.calendly.com, careers.calendly.com, ci-transcription.mi-recall.staging1.staging.calendly.com, dev.calendly.com, gke-hello.j-test2.dev1.dev.calendly.com, gke-hello.jason-r5rmr.staging4.staging.calendly.com, gke-hello.jason-test-spfcc.dev1.dev.calendly.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 25. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: ai-compute-staging.staging.calendly.com, ai-staging.staging.calendly.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "calendly.com",
  "dns": {
    "a": [
      "172.64.146.81",
      "104.18.41.175"
    ],
    "aaaa": [
      "2606:4700:4403::ac40:9251",
      "2606:4700:440d::6812:29af"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt2.aspmx.l.google.com (pref 20)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "roan.ns.cloudflare.com.",
      "hope.ns.cloudflare.com."
    ],
    "caa": [
      "0 issuewild \"ssl.com\"",
      "0 issue \"digicert.com; cansignhttpexchanges=yes\"",
      "0 issuewild \"amazon.com\"",
      "0 issuewild \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"amazon.com\"",
      "0 issue \"sectigo.com\"",
      "0 issuewild \"godaddy.com\"",
      "0 issue \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issue \"godaddy.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issuewild \"comodoca.com\"",
      "0 issue \"ssl.com\"",
      "0 issuewild \"digicert.com; cansignhttpexchanges=yes\"",
      "0 iodef \"mailto:platform@calendly.com\"",
      "0 issuewild \"sectigo.com\"",
      "0 issue \"comodoca.com\""
    ],
    "spf": [
      "miro-verification=c546481c526d7d0fca4b0def39a0700eeb64f077",
      "cursor-domain-verification-tdtnd4=i4bl9JEOFE1VOQbkiMkpIfGQZ",
      "parallels-domain-verification=25c15af2f44f426fa520c0f140c5f3b884327a61390a439495a1e7fa2ee9cf92",
      "google-site-verification=4IlbzuraJEuEWHXSF1ealAXGwgl-01bcFI9b6KiPrzw",
      "google-site-verification=l9ghJl2k5pCmyzxgB-u7zk1WdLHRxZ8Gev7eo7j6tlw",
      "calendly-site-verification=JLJojO5SGco45xeUJrgD30rJACtPP9JsvM1TDRUSa",
      "jetbrains-domain-verification=1k4crjxnjx7wtlhja236t8jcn",
      "logmein-verification-code=b644b816-e7f4-45df-8215-6ba8db765fe9",
      "google-site-verification=vvI2V5xXtswv19eoBHMvUfLriiS1W3uTeOrHdusW3AI",
      "stripe-verification=7708116a2a258908ad3dde9ebc9ab342c43b7000f582962f69a7fdcab307abab",
      "google-site-verification=fnhE2QNlMBUWS8UBhCtO4N2xU1Hv5Baq_nAGRKrDOS8",
      "ePwEbxX6T8GLeUY2",
      "zoom-domain-verification = afd6de76-b579-11ee-a506-0242ac120002",
      "loom-site-verification=dfbd3882de7e42d39aa63ac12d8f403e",
      "slack-domain-verification=025CLyam48F5ppYztUuMl2Ue4prf01SVmyM06BYy",
      "doit-verify295235",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:_spf.google.com include:mktomail.com ~all",
      "docusign=26d57faa-4bf8-45cd-866b-a36fdf86e214",
      "apple-domain-verification=eAu2dlDrzmPvVHPg",
      "carta-domain-verification-p6kprv=Hf8pYNQgbK7i64r9SjTorb0sB",
      "pendo-domain-verification=4dace321-4517-49a6-b51a-ec3478a24002",
      "jamf-site-verification=iYyCRUNw7_AXFUC7zaLiFw",
      "facebook-domain-verification=oiiy3kxhh6i3mzo3tecoolwkzpsqos",
      "hubspot-developer-verification=MDZjM2Q5Y2QtYjIxOS00ZTllLWIzYzEtMzI2YzYwZTQxY2My",
      "openai-domain-verification=dv-60PIOwHK0eRDfc2VpmSJ3XY3",
      "google-site-verification=A_dMlj5RIS-42bZbR1vzM__GBhqE_l-CNAt4kHL39K8",
      "google-site-verification=CT9vkalOAxTSSlMkSYuif3PPR9IfW9wOMDYCpHV8-pQ",
      "pardot906932=62a94517bea65a4a146e19a380714f589e54114888b639e208605e1b6b445f47",
      "google-site-verification=spiNl55E3iYMilE9lM2OB67FTeyJVzNJdYsr8YreMiE",
      "google-site-verification=cDMxTqEGKRREjpULRkV3kxo9fUh9AAOy68UKi-sWFDA",
      "box-domain-verification=a9f4a950cfdfd3b9cea802a96528ccffbff61184fbb8363037b8cb9eeb1e454c",
      "citrix-verification-code=ecbbb3b7-9c8c-4b46-81a7-ecd2c6ff42b9",
      "postman-domain-verification=987281567d45964ffbd83330939d1731ef9199ac6408ad6a641d49813877d64f73114ad25d917bbe3babf4cf554437d1034afcd089f0faf69bbd9c6d9473df5b",
      "pardot986361=84e628bbfec0a11d5baf3b0d9631a46a0e5f6801076cfc694ca8631fc86ee0b2",
      "qase-ca7eb2da8082aef5bed402accf262d2bca41fd30",
      "06FB0F4CCD",
      "MS=ms26783193",
      "h1-domain-verification=jcUKHuDrikH5HZfj3S3op6kzWDJLgLg3d7pmxsKGupBKUPm1",
      "google-site-verification=D6kljg6Ozbxz7wkQHTu9bBD58dH48qXc8jbrSvdix20",
      "TAILSCALE-nNYYC0vC9TISAvboCaQA",
      "MS=ms75363840",
      "pardot906932=75d30f44d6d6e89f6ea5ce36bff2d547056f93c17f7034160851f23f09a2448a",
      "MS=ms75932089",
      "google-site-verification=0W2XISvsFG0b1de6rAJqnGOZpeyHioDOc0fCPpkcga0",
      "atlassian-domain-verification=HeV4orUbu8ZU/Et3BdlguiFnoc5TqgI5owEFFTeBLYX6Lc6BZK4D0ru001VnnLBk",
      "pardot906932=d83df604fb40dd187d6c3def3b29591478a195def3dd9223df3d64f3fbabfd0c",
      "onetrust-domain-verification=0bf92d345265462eb0a4ad38c7b55188",
      "uber-domain-verification=7898f9ad-15df-4820-b779-92b2bec7858b",
      "adobe-idp-site-verification=db378e2b6b1fbb203e2fa8efb4daacdd0b5837d143bd0020257d69866acc6b55"
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
    "days_left": 67,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.146.81",
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
  "apex_txt": [
    "miro-verification=c546481c526d7d0fca4b0def39a0700eeb64f077",
    "cursor-domain-verification-tdtnd4=i4bl9JEOFE1VOQbkiMkpIfGQZ",
    "parallels-domain-verification=25c15af2f44f426fa520c0f140c5f3b884327a61390a439495",
    "google-site-verification=4IlbzuraJEuEWHXSF1ealAXGwgl-01bcFI9b6KiPrzw",
    "google-site-verification=l9ghJl2k5pCmyzxgB-u7zk1WdLHRxZ8Gev7eo7j6tlw"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "serial": 503770168442218987564414495344280708007915,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://ye1.c.lencr.org/108.crl"
      ],
      "subject_dn": "311530130603550403130c63616c656e646c792e636f6d",
      "issuer_dn": "310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594531",
      "not_before": "20260904140528",
      "not_after": "20261203140527"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/abuse_reports/new",
      "/*?*",
      "/app/",
      "/",
      "/"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 301,
    "p404_status": 404,
    "wellknown": [
      "/.well-known/apple-app-site-association",
      "/.well-known/assetlinks.json"
    ],
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "hsts": "max-age=31536000; includeSubDomains; preload",
    "security_txt": "/.well-known/security.txt",
    "crl": {
      "url": "http://ye1.c.lencr.org/108.crl",
      "status": 200
    }
  },
  "elapsed_s": 14.8,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
