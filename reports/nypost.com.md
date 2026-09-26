# Security Audit Report — nypost.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nypost.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nypost.com |
| Test date | 2026-09-26 14:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **8** (High: 0, Medium: 0, Low: 1, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P11 | WordPress login page exposed | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | CT1 | 48 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx; X-Powered-By: WordPress VIP <https://wpvip.com>
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] 48 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: careers.nypost.com, my.nypost.com, shop.nypost.com, store.nypost.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "nypost.com",
  "dns": {
    "a": [
      "192.0.66.32"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-00596a01.gslb.pphosted.com (pref 10)",
      "mxa-00596a01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-670.awsdns-19.net.",
      "ns-1469.awsdns-55.org.",
      "ns-1696.awsdns-20.co.uk.",
      "ns-112.awsdns-14.com."
    ],
    "spf": [
      "openai-domain-verification=dv-zTDjYaeUtH0Z7a6WRNHJHPNH",
      "onetrust-domain-verification=e7aaac6a2eba4af5831f665fd4355b18",
      "yahoo-verification-key=ZGc2aNHEalcpUmqoYUCKock6uR7n971BQPyq+avH5js=",
      "facebook-domain-verification=a5ak341y6mn6scu375wpuvy5h38u0",
      "ValidationTokenValue=be3a705a-0d8d-4c88-91dc-0ebe1d8e2f6d",
      "profound-domain-verification-f8v9td=J1enbUIBGr8ls69bKh4sLheZC",
      "tollbit-domain-verification=80476469dd961d48a2f36d45785f7b4bf6823867c0b612c475a6b073c762576c",
      "google-site-verification=PN2Qi9bdkJ4SDeGCzwK6mosjk_cdEPkd-epRWHrqs7M",
      "google-site-verification=rqQNsAZmdVyYCBkD6XaUsf_6Aq8knJPcJ_AJm_15mSM",
      "atlassian-domain-verification=uNoIhBXurxzVlQa0FvK2t9Yld5byfvXbFRQaMToGvrieKjBdylMs8jcSXRKQKqao",
      "ZOOM_verify_GgmxWj_4QZCCMGFMQbCp5Q",
      "globalsign-domain-verification=DC5FAF3AEB5DC469953A669244E3DABD",
      "google-site-verification=pkTc123LIT1uBNNTg9WvGeJjxI0rCnCzmcVYSeFyLFU",
      "google-site-verification=5uYHzCPszHHLF2QyFiup1p177WJxzsWoUNaUCs_fhkQ",
      "apple-domain-verification=37Qe0gDvvRCGgED6VegwSRnviuX7KRbEhaVgN8IGXpQ",
      "figma-domain-verification=b411f1d2852c2c7e057a2d6d70fb22896f37ccc1412d1e1bb4f9da14e2b78ad9-1769000244",
      "gc-ai-domain-verification-pqnv2r=6l7d3qRIy8sKfMz0EsSBxqr80",
      "pinterest-site-verification=8ee9ddd73c0b33e9c9606a95d1763cc7",
      "google-site-verification=43S5hR4E09EYHuJ0EddR08WUtCjmPb3zJDOY1qaqieg",
      "apple-domain-verification=lPyM98oF1jmNh7Ts",
      "v=spf1 ip4:205.203.130.22 ip4:205.203.130.101 ip4:205.203.130.102 ip4:205.203.136.101 ip4:205.203.136.102 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "amazonses:nZi4yMmejKgD3iT0h5S+LGrgaQGq6NVUPnD4v+R9htc=",
      "knowbe4-site-verification=0694ce74005828dc4bb8b7299bfb6f61",
      "globalsign-domain-verification=015A85DB506CC703E147E2E1A8234FFA",
      "globalsign-domain-verification=E1A5DBF2B0DE3B53A5674C61CAB23AD2",
      "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiTxvTgpRaUPa3Zsawin7pRP+CPIij6s1io0EsxRAfrCox6uw/QdKyEiozMHKz14AWPx6gLqb09Om7xmN9Snb5tcnWQdD46XFld1rm+DVwP1UezK/VagJDp6aMhabY1T1hBpK4R/YBnQ70R1AivL6Km7TfNgRU6UMSx2TtQnkFawIDAQAB",
      "64392d9425e042418ac52d053c1ecb2f",
      "amazonses:C+fSBo78zXZisXWUUbHRXRXY19xolN+ug+xevTtXL+k=",
      "globalsign-domain-verification=14BE65E00D7267440AC2843EDFF82780",
      "google-site-verification=TfuBznU2bqij21_J2S6N2IDNQta9zajEFCIxJuh033J",
      "adobe-idp-site-verification=7ef638bb68822798685f96e436bfc87a6f79319dd86369e447b84bb8ea9c6f68",
      "google-site-verification=Ut_6-La1_H3SIW8cw3Jxn5gBHjCOb1mEm5wEciI90j8",
      "google-site-verification=S57vRF8jMqWVb1wbslt1vZqTKLBQPRLeihUQGU4LQL4",
      "ZOOM_verify_59WiJX6USMK92Hbu6-iuEg"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; sp=quarantine; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=nypost.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE2",
    "notBefore": "Aug 11 00:41:43 2026 GMT",
    "notAfter": "Nov  9 00:41:42 2026 GMT",
    "san": [
      "nypost.com",
      "www.nypost.com"
    ],
    "days_left": 43,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.32",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=UTF-8",
    "title": "New York Post – Breaking News, Top Headlines, Photos & Videos"
  },
  "mixed_content": [
    "href=\"http://"
  ],
  "tech": [
    "Server: nginx",
    "X-Powered-By: WordPress VIP <https://wpvip.com>"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nypost.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://nypost.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 403",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 48,
    "notable": [
      "careers.nypost.com",
      "my.nypost.com",
      "shop.nypost.com",
      "store.nypost.com"
    ],
    "sample": [
      "ads.nypost.com",
      "advertising.nypost.com",
      "ai-develop.nypost.com",
      "ai-preprod.nypost.com",
      "ai.nypost.com",
      "ascend.nypost.com",
      "bytes.nypost.com",
      "cancel.nypost.com",
      "careers.nypost.com",
      "chp.nypost.com",
      "embeds-develop.nypost.com",
      "embeds-preprod.nypost.com",
      "embeds-sandbox.nypost.com",
      "embeds.nypost.com",
      "events.nypost.com",
      "guide.nypost.com",
      "hamilton-benchmark.nypost.com",
      "hamilton-benchmark.stag.nypost.com",
      "links.nypost.com",
      "my.nypost.com"
    ]
  },
  "elapsed_s": 22.7,
  "rechecked": "2026-09-26 14:53 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
