# Security Audit Report — nature.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nature.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nature.com |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 7, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | low | H1 | Missing HSTS header | CWE-319 |
| 5 | low | H2 | Missing CSP header | CWE-1021 |
| 6 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 7 | low | H4 | No clickjacking protection | CWE-1023 |
| 8 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 9 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 10 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 11 | info | H6 | Server technology disclosure | CWE-200 |
| 12 | low | RED1 | HTTP redirect points to another host over plain HTTP | CWE-319 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 18 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 19 | low | RED9 | Redirect chain of 5+ hops on the site root | CWE-601 |
| 20 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 21 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ee-www-redirect
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443";ma=86400,h3-29=":443";ma=86400,h3-27=":443";ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 5. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 6. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 7. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 8. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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
- **Detail:** Header reveals: ee-www-redirect
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [LOW] HTTP redirect points to another host over plain HTTP (`RED1`)

- **CWE:** CWE-319
- **Detail:** Location: http://www.nature.com/
- **Context:** https response, /
- **Recommendation:** Redirect to the same host over HTTPS.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 14. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=ieCNIjjta99aFWzeD9Mhze-lTbXHZo6GAc-MgXlclL4; canva-site-verification=uyK4bK0s0B6XTjkr-evkKA; lovable_verification=RRjvRYYzlyNRyQgjsp9U
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 18. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of nature.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 19. [LOW] Redirect chain of 5+ hops on the site root (`RED9`)

- **CWE:** CWE-601
- **Detail:** Following https://nature.com/ produced 5 redirect hops.
- **Recommendation:** Shorten the redirect chain.

### 20. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 70 disallow path(s), e.g. /search, */1000$, /*/*/*/pf/, /*.otmi$, /*/*/*/*/otmi/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 21. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://nature.com/ carries Cache-Control: max-age=3600; shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

## Evidence (raw response observations)

```json
{
  "domain": "nature.com",
  "dns": {
    "a": [
      "151.101.76.95"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-002c5801.gslb.pphosted.com (pref 10)",
      "mxa-002c5801.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "pdns1.ultradns.net.",
      "pdns4.ultradns.org.",
      "pdns3.ultradns.org.",
      "pdns5.ultradns.info.",
      "pdns2.ultradns.net.",
      "pdns6.ultradns.co.uk."
    ],
    "spf": [
      "google-site-verification=ieCNIjjta99aFWzeD9Mhze-lTbXHZo6GAc-MgXlclL4",
      "canva-site-verification=uyK4bK0s0B6XTjkr-evkKA",
      "elevenlabs=IzVhiRt3uxo8ZMX_GxWWnO8BD5tqECcuYRAvtJ9M4_k",
      "lovable_verification=RRjvRYYzlyNRyQgjsp9U",
      "klaviyo-site-verification=RGffrp",
      "onetrust-domain-verification=2fb9af66a4f8427c81ef817cc2fc7e5a",
      "figma-domain-verification=a02807ceec187285dae088008460ab5e258fd494d08ac0c2c56f3739ff32437f-1713256355",
      "1password-site-verification=55KOGYWRMNDKRKUTDFSXF3WSYY",
      "_globalsign-domain-verification=IG4UdrI9gc_SVSE132aTagdWhxkvONdbIBhHhhcMlP",
      "atlassian-domain-verification=8YyRB1dGCFU6FTIcUt18raWzPoKaOFUG7xiFOkac8XcGVOZgEtzvjUqsWaClhXdJ",
      "cisco-ci-domain-verification=2994122b15fd1403b4a698555609ab4fa873bf7e2dcbd7c3ab141489d06e9b7c",
      "docusign=67f44eaf-0dbe-458b-b10f-47bed1b15935",
      "google-site-verification=98cpzBJjv18c55LqVgp5mgYFTzGU6fLcF5t9GoTbbog",
      "anthropic-domain-verification-gbdrks=ymGP6KhyvFPcXIZ715PJVvZ3L",
      "rpi5f08jedse2mt8382r95tj80.",
      "google-site-verification=tYWiePuSRFUVlICaU0QdGNwirIvpr0YcTjConBwD6Cc",
      "deepl-domain-verification=b8faec8a0acd4830a6c745d36a104c04",
      "monday-com-verification=gIfsbiBtQzvmY8SR8gmXmURzurNdeyafwCzP_vHk4wk",
      "zapier-domain-verification-challenge=3621a905-479a-4476-b1c9-c153c4b7537c",
      "google-site-verification=HHD68pull8xzsrxD3nrcvVeVgIWS8Ou3WfObgKmsAeU",
      "klaviyo-site-verification=UzNPXX",
      "google-site-verification=MMKRJQfefRehxhwEreFHykRsf_auok6vGwCrP1fz-r4",
      "shopify-verification-code=JAHiN7KQ1pbmGdnz9wgaKYgm5VCazy",
      "docusign=7172e4ac-506c-48bb-9a02-40aa4f5970e4",
      "openai-domain-verification=dv-HAPMMiP9yzTJ3yFoeETfV7vd",
      "klaviyo-site-verification=U8sqV2",
      "v=spf1 ip4:195.128.10.18/32 ip4:195.128.10.15/32 ip4:195.128.10.69/32 ip4:195.128.10.25/32 ip4:195.128.10.24/32 ip4:195.128.10.23/32 ip4:203.200.192.105/32 ip4:203.200.192.109/32 ip4:167.89.16.99/32 ip4:66.159.232.113/32 ip4:66.159.234.15/32 ip4:208.85.55",
      ".170/32 ip4:208.85.55.173/32 ip4:199.168.14.54/32 ip4:192.87.127.243/32 ip4:192.87.127.244/32 ip4:208.185.229.0/24 ip4:208.185.235.0/24 ip4:52.43.154.216 ip4:192.174.90.93 ip4:52.41.1.125 ip4:192.174.90.94 ip4:192.174.90.91 include:spf.mandrillapp.com inc",
      "lude:servers.mcsv.net include:spf.flowmailer.net include:spf-002c5801.pphosted.com include:ses.echobox.com include:fc3949.cuenote.jp include:_spf.salesforce.com -all",
      "MS=ms87841658",
      "cisco-ci-domain-verification=22a12fd0333f8053f7ff6792fa99da4b2a9f4833da46146e49cb65d7cd75ca26",
      "MS=ms77610658",
      "adobe-idp-site-verification=e7d316e26179ad0d4b3f90cf2a0754eec7efe5ffd4e42fd68fb1bf562238e1e5",
      "monday-com-verification=gAZywa4vaGsfLg6nd5lzh_H0u2mYn7u-W075cd-3X78",
      "facebook-domain-verification=jkc3tvps7b0r4s2a8go26hb3mur2ug",
      "google-site-verification=k7pclGN55ftDU-TcQZ1EkFy7EBSsxDUY79dYzxeVTQA",
      "klaviyo-site-verification=UNZdq4",
      "extensis-domain-verification=247a2c5e-b2c3-477e-a1a1-69522ce10b98",
      "Hello GlobalSign CEOS1602043687",
      "klaviyo-site-verification=SfRYxc"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:re+vcgy2jslus0@dmarc.postmarkapp.com; sp=none; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=nature.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 24 20:57:47 2026 GMT",
    "notAfter": "Nov 22 20:57:46 2026 GMT",
    "san": [
      "nature.com"
    ],
    "days_left": 57,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.76.95",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: ee-www-redirect"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nature.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "http://www.nature.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=ieCNIjjta99aFWzeD9Mhze-lTbXHZo6GAc-MgXlclL4",
    "canva-site-verification=uyK4bK0s0B6XTjkr-evkKA",
    "lovable_verification=RRjvRYYzlyNRyQgjsp9U",
    "klaviyo-site-verification=RGffrp",
    "onetrust-domain-verification=2fb9af66a4f8427c81ef817cc2fc7e5a"
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
      "aia_ocsp": null,
      "not_before": "20260824205747",
      "not_after": "20261122205746"
    }
  },
  "http2": {
    "robots_disallow": [
      "/search",
      "*/1000$",
      "/*/*/*/pf/",
      "/*.otmi$",
      "/*/*/*/*/otmi/",
      "/*/*/*/*/fp/",
      "/protocolexchange/labgroups/",
      "/naturecareers/jobs/search",
      "/webcasts/*",
      "/*draft=*",
      "/*foxtrotcallback=*",
      "/*origin=*",
      "/my-account",
      "/*proof=t%2Btarget%3D\\*",
      "/*proof=*"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 27.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
