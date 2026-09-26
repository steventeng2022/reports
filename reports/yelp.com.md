# Security Audit Report — yelp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://yelp.com/ |
| Bug bounty program | Yelp |
| Listed scope domain | yelp.com |
| Test date | 2026-09-25 10:29 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

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
| 12 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Varnish
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
- **Detail:** Header reveals: Varnish
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "yelp.com",
  "dns": {
    "a": [
      "140.248.128.116"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns02.midtowndoornailns.com.",
      "dns1.p06.nsone.net.",
      "dns3.p06.nsone.net.",
      "ns04.midtowndoornailns.com.",
      "dns4.p06.nsone.net.",
      "dns2.p06.nsone.net.",
      "ns01.midtowndoornailns.com.",
      "ns03.midtowndoornailns.com."
    ],
    "spf": [
      "gm36n17d8y8544hg7s3n5ptcjgzfb17f",
      "status-page-domain-verification=z80f59yz1jkt",
      "atlassian-domain-verification=45ozypIxFMV4A0xxbgkqTjhHaKzj8CrbxzUxbakhomBdkM6bzr117OBkfPJJlbAX",
      "aline-domain-verification-d4fg3g=dSnUs4LT4OucL5MIUWA1pqjnF",
      "google-site-verification=-LX_luQh_Kq5PPMW-YLBGAr22sLmB9uXTZDZYwWdWcc",
      "apple-domain-verification=qa3GTY5z2ELxESie",
      "_globalsign-domain-verification=_64UG15h1zSn86m51pRb3vaFMDTtUCsP2RBUJ7DAAM",
      "cursor-domain-verification-bybp9b=u4Ql3DroYKAYNKZO7GMmm7CN6",
      "status-page-domain-verification=560td8k1wdsc",
      "atlassian-sending-domain-verification=b8aeb8b2-f866-4573-9468-2b248ab4d392",
      "adobe-idp-site-verification=9ac7165b0af2483ec7767a476cdba5d35ebf9581d5696dc420fb058f9a7372af",
      "stripe-verification=6CB8483E931BB30A9798D497914DB00B6CD935BC954C67CB31EC582361636F3F",
      "sending_domain1084122=a5612a391e2e2b3d3cc46238b2e038b211048e6e45cc04d0947989d5e4f8833c",
      "google-site-verification=NOSls2JfXI55tW5qFU89NY93kA8LB6YTHGBzCFz3cy8",
      "status-page-domain-verification=kl0pq45qyb3d",
      "v=spf1 include:everbridge.net include:yelp.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "google-site-verification=3lJN-zw-10jb4bLfmXsqFizDALMsnlhqZ-TPG-AjHWU",
      "_46ivs5dmhmqu8fah0jyafidcgnb16m8",
      "google-site-verification=-Y773kzVn1DQlVG-Ugprk7qDuZdki_5cqljezw1daiU",
      "dtm-domain-verification=jLI9ztu7vQd32GYHfJfjNbjuGdSdJk7jzYeLmaZKEHs",
      "google-site-verification=GRQLNPjWLxGr_Ka6phLFqBXooCAZt35ZZz2ZV5JNsDQ",
      "_globalsign-domain-verification=PO95qR5HARP3zbvcQ1WFBVyLGBUvgjmgc16ENjCtmy",
      "pardot813133=a90e85640d4bb5a429d171325168640bb9463489071367d9615ebc73919f1bbb",
      "onetrust-domain-verification=53afac8ba50845c3b7c8ba137d2349c0",
      "facebook-domain-verification=mdu6515tt8odq7akwzr4a036q6w3cz",
      "apple-domain-verification=7xkVWehEYAdxIGR18-iBcC-263XTlJE3Xh4KZcgF_1o",
      "status-page-domain-verification=f3txhd81xn94",
      "zoho-verification=zb51277094.zmverify.zoho.com",
      "wrike-verification=NDA1MDgyNTpiMDcyYWNmMjgyYmEzOWFhNDE3NzA1YTE1NGFmYmYzYmU0Y2IxNGQwNTA5YzNkMDIyNWVkYmNhZDMwZmQ5ZTM1",
      "mixpanel-domain-verify=277018fd-af0f-4112-bc98-ec0aa09c9e62",
      "0jw2h0bjphcxmg3snr0fjg270ysc0wgk",
      "jamf-site-verification=LcGrLBerA2Rm4ZTuGWhAQw",
      "cloudflare_dashboard_sso=9d6accac4ddd9be2d5930b92acfdb0a5",
      "notion-domain-verification=WDNH0Y6wClSmazu1ox2mB6gcdkjd6MA3er4OAerRCUt",
      "profound-domain-verification-98wkep=o4E7iCuctO9gpJqyfkrCLFqXp",
      "zapier-domain-verification-challenge=6da7ad16-5f37-4d23-a121-259dae5492de",
      "atlassian-domain-verification=k//LP2aSAEPqGqlbOWy3YhbF21wtfSXibOk0vz6Dx1BV3du/Ub/Fyiv3C55m2vkS",
      "have-i-been-pwned-verification=dweb_7pqrwg9nyaw5qzccmdpbh43e",
      "openai-domain-verification=dv-fJLMFcavOatIU9F5VNTB4uzC",
      "google-site-verification=4OznISzbxHzmhzRM-NtpUcP1P6nIfsanNZdNI1G_EU8",
      "citrix-verification-code=1dee59ff-c292-47a1-8faf-a0c7803c742a",
      "datadome-domain-verify=XwAuoddrKPKQX4hiaY3MmiM7bnaIFuJv"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email,mailto:dmarc@yelp.com; ruf=mailto:dmarc_fr@yelp.com; ri=14400"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Yelp Inc., commonName=yelp.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Dec 16 00:00:00 2025 GMT",
    "notAfter": "Dec  5 23:59:59 2026 GMT",
    "san": [
      "yelp.com",
      "*.admin.yelp.com",
      "*.biz.yelp.com",
      "*.m.yelp.com",
      "*.yelp.com",
      "admin.yelp.com"
    ],
    "days_left": 71,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "140.248.128.116",
    "open": []
  },
  "https": {
    "status": 403,
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
      "origin": "https://sub.yelp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403,
    "location": "https://yelp.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 403",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 403",
    "/url?url=https://evil-auditor.example/x -> 403"
  ],
  "paths": {
    "/robots.txt": 403,
    "/sitemap.xml": 403,
    "/.well-known/security.txt": 403,
    "/security.txt": 403,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 403,
    "/api/": 403
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 53.0,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
