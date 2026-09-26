# Security Audit Report — nature.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nature.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nature.com |
| Test date | 2026-09-25 17:54 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

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
      "mxa-002c5801.gslb.pphosted.com (pref 10)",
      "mxb-002c5801.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "pdns2.ultradns.net.",
      "pdns1.ultradns.net.",
      "pdns6.ultradns.co.uk.",
      "pdns5.ultradns.info.",
      "pdns3.ultradns.org.",
      "pdns4.ultradns.org."
    ],
    "spf": [
      "google-site-verification=ieCNIjjta99aFWzeD9Mhze-lTbXHZo6GAc-MgXlclL4",
      "facebook-domain-verification=jkc3tvps7b0r4s2a8go26hb3mur2ug",
      "monday-com-verification=gIfsbiBtQzvmY8SR8gmXmURzurNdeyafwCzP_vHk4wk",
      "cisco-ci-domain-verification=2994122b15fd1403b4a698555609ab4fa873bf7e2dcbd7c3ab141489d06e9b7c",
      "deepl-domain-verification=b8faec8a0acd4830a6c745d36a104c04",
      "google-site-verification=HHD68pull8xzsrxD3nrcvVeVgIWS8Ou3WfObgKmsAeU",
      "1password-site-verification=55KOGYWRMNDKRKUTDFSXF3WSYY",
      "MS=ms87841658",
      "rpi5f08jedse2mt8382r95tj80.",
      "klaviyo-site-verification=U8sqV2",
      "shopify-verification-code=JAHiN7KQ1pbmGdnz9wgaKYgm5VCazy",
      "openai-domain-verification=dv-HAPMMiP9yzTJ3yFoeETfV7vd",
      "lovable_verification=RRjvRYYzlyNRyQgjsp9U",
      "onetrust-domain-verification=2fb9af66a4f8427c81ef817cc2fc7e5a",
      "canva-site-verification=uyK4bK0s0B6XTjkr-evkKA",
      "_globalsign-domain-verification=IG4UdrI9gc_SVSE132aTagdWhxkvONdbIBhHhhcMlP",
      "klaviyo-site-verification=UzNPXX",
      "Hello GlobalSign CEOS1602043687",
      "klaviyo-site-verification=SfRYxc",
      "cisco-ci-domain-verification=22a12fd0333f8053f7ff6792fa99da4b2a9f4833da46146e49cb65d7cd75ca26",
      "extensis-domain-verification=247a2c5e-b2c3-477e-a1a1-69522ce10b98",
      "google-site-verification=tYWiePuSRFUVlICaU0QdGNwirIvpr0YcTjConBwD6Cc",
      "anthropic-domain-verification-gbdrks=ymGP6KhyvFPcXIZ715PJVvZ3L",
      "v=spf1 ip4:195.128.10.18/32 ip4:195.128.10.15/32 ip4:195.128.10.69/32 ip4:195.128.10.25/32 ip4:195.128.10.24/32 ip4:195.128.10.23/32 ip4:203.200.192.105/32 ip4:203.200.192.109/32 ip4:167.89.16.99/32 ip4:66.159.232.113/32 ip4:66.159.234.15/32 ip4:208.85.55",
      ".170/32 ip4:208.85.55.173/32 ip4:199.168.14.54/32 ip4:192.87.127.243/32 ip4:192.87.127.244/32 ip4:208.185.229.0/24 ip4:208.185.235.0/24 ip4:52.43.154.216 ip4:192.174.90.93 ip4:52.41.1.125 ip4:192.174.90.94 ip4:192.174.90.91 include:spf.mandrillapp.com inc",
      "lude:servers.mcsv.net include:spf.flowmailer.net include:spf-002c5801.pphosted.com include:ses.echobox.com include:fc3949.cuenote.jp include:_spf.salesforce.com -all",
      "atlassian-domain-verification=8YyRB1dGCFU6FTIcUt18raWzPoKaOFUG7xiFOkac8XcGVOZgEtzvjUqsWaClhXdJ",
      "elevenlabs=IzVhiRt3uxo8ZMX_GxWWnO8BD5tqECcuYRAvtJ9M4_k",
      "adobe-idp-site-verification=e7d316e26179ad0d4b3f90cf2a0754eec7efe5ffd4e42fd68fb1bf562238e1e5",
      "google-site-verification=MMKRJQfefRehxhwEreFHykRsf_auok6vGwCrP1fz-r4",
      "google-site-verification=98cpzBJjv18c55LqVgp5mgYFTzGU6fLcF5t9GoTbbog",
      "figma-domain-verification=a02807ceec187285dae088008460ab5e258fd494d08ac0c2c56f3739ff32437f-1713256355",
      "monday-com-verification=gAZywa4vaGsfLg6nd5lzh_H0u2mYn7u-W075cd-3X78",
      "klaviyo-site-verification=UNZdq4",
      "MS=ms77610658",
      "docusign=7172e4ac-506c-48bb-9a02-40aa4f5970e4",
      "zapier-domain-verification-challenge=3621a905-479a-4476-b1c9-c153c4b7537c",
      "docusign=67f44eaf-0dbe-458b-b10f-47bed1b15935",
      "klaviyo-site-verification=RGffrp",
      "google-site-verification=k7pclGN55ftDU-TcQZ1EkFy7EBSsxDUY79dYzxeVTQA"
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
    "days_left": 58,
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
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 7.5,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
