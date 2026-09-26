# Security Audit Report — hp.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://hp.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | hp.com |
| Test date | 2026-09-25 09:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: CloudFront
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: CloudFront
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "hp.com",
  "dns": {
    "a": [
      "13.249.165.75",
      "13.249.165.48",
      "13.249.165.6",
      "13.249.165.52"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns1.hp.com.",
      "ns6.hp.com.",
      "ns2.hp.com.",
      "ns3.hp.com.",
      "ns5.hp.com.",
      "ns4.hp.com."
    ],
    "spf": [
      "SFMC-f7skz24QEr_YzGdBqMHR3sC2xGZPNQ3mZdXDFFow",
      "google-site-verification:2kiyv1SjebKUcEmaJ4QtapQe2EcbqPcYmhiJ-XJMZsY",
      "atlassian-domain-verification=mjss59VLEmjHpiASn3FUy/Hfb/9QbLAAOR9fiqjavAJ6O1uCyNnChSTbNAxo7IIS",
      "atlassian-domain-verification=cbeZ9ZZ8XZI9vcf3e6CYWsA3pQ/6Xfc2mSUGdHuK5bWhjzVD0ksLTbFdabq//Sd5",
      "google-site-verification=ajtjung8rHe1-msfHMrttoZdDlZeeoWJNpQ5jNZcqfo",
      "bv-domain-verification=ca416dec3e1078035e8f94141e8542a1207d3415febb81cdecc6f69d491ee03c",
      "C6ekla14kZc9ySs2tWLx5+qoT3uFAcPKfM9z8SnOjKPxduvwIiHCJI75yVt8cOynDwTRpNGAoAu7WBKTky3QhQ==",
      "google-site-verification=ior6EHEPCvMGbBIF1Cfzg3-yTDw30PaIbETytGrl1zY",
      "02.14.2024",
      "google-site-verification=SYstg4r0qao99bYV9-4uWYGTHLSIL3Py60GZvR_OJ1c",
      "SFMC-VXyPhU37JRfzHa1B_-XfXzHjl2WKI7af1rdKH-wR",
      "teamviewer-sso-verification=9a8bdacd256d426aadef7c9435cc05f7",
      "MS=ms38857149",
      "SFMC-TkI3rEvFMq3uO7c3713TrP-cg1S7j0K0iKyNVXIY",
      "SFMC-z90jhAqnCFzmMAy46Qo1vy13u6YlOQ4afVWEPZmS",
      "7155-7871-A6E8-AEB1-5764-4DE3-D4DD-6680",
      "SFMC-Gj1r4WT7h7LuH9CgR-ATrs4dQiyHzeRW5mkk_qg9",
      "SFMC-aJMC0Gi9MPXTz-l4Iv3LtRXfhaeOB0OCsGwNXkzM",
      "facebook-domain-verification=1f6jis8ngyl6xhtopb196nk2jzb6wm",
      "IQI2xT+r6hj2PuJ171J02xOMMXSUHl4I2VJ5a4CB2OsyfPJkfHXHbmJ5e2Ee6kbNjJQsERvcm3d4IeS2e7xPPQ==",
      "docker-verification=ad83199a-7103-4f01-8acf-41979b12ba00",
      "SFMC-gC-INJ9awb38orE0daCKtYQOdTzA26V3zBYVruOP",
      "canva-site-verification=phuz1k47EJb7b9wGXtCeYw",
      "google-site-verification=N-C2RScU5fi3a4_9J7hYoQhoL9H566pkx6gM8PI6Jqo",
      "Dynatrace-site-verification=fb0772f5-465e-4c26-9c6e-de883a321a31__ko3f16m3vui8oi46qls2l305im",
      "liveramp-site-verification=LpuGIkdkGN7Dr495prdDxPoD0K4Y8zox5B40KiQVq08",
      "fastly-domain-delegation-ndopinwe32-10142022",
      "paloaltonetworks-site-verification=1490b1ee9f50f41d487a017ed98225cd2f0bcbed857fa5841aa276a5a009b604",
      "teamviewer-sso-verification=14e16276afc843e58d056742e9f89d26",
      "_t0t2hodeyznakvwlx7hkbim4oojp151",
      "google-site-verification=7CCNFPK5u6aSDkOkTOxz_yOePZI8_thHJnaJl6EtSwk",
      "pendo-domain-verification=f79d1d3d-277a-4a70-982c-677c77a2f011",
      "gem-domain-verification=BTTGt2-RR8Zy86kgA6dRzh",
      "launchdarkly-domain-verification=c190690f-6cf2-4084-9ea4-ddbeebcebc80",
      "google-site-verification=lf2HoI19pw29dSNCWe1ex0zlgiGiMSUZjRWjW61SLXk",
      "mongodb-site-verification=NNt4TMRanOtPk2qCvhWpTMXpY8SOb7BO",
      "hpe-greenlake-domain-verification=7151716b744d3467684e427773486a5244794c3172676333326e753537787941",
      "airtable-verification=fd35e3a14eafa013a4ef8ec307159c57",
      "tiktok-domain-verification=c31cb3ab1359c3755fc548a1a60875056dff634430d936d99b825643f08293c4",
      "google-site-verification=ZKYzB8FoSfCdYZzesihRSd5OsBfrtDOvG6zrqYcMcd0",
      "google-site-verification=GdVvq6F-s2Vr-eD8eeZeo11J1HXnWdA2ZNM_M_IivjY",
      "shopify-verification-code=U5Mvz3J5IScCrDvvcy49c7chv8Iwxp",
      "adobe-sign-verification=8d7c98c65d9a78aa4fe83e40ac618269",
      "hcp-domain-verification=d172505ee1cb87d71e2f402ab1e6123f01c858917022925ee9fe25ce1ea6a398",
      "v=spf1 mx include:_spf.hp.com include:_spf.salesforce.com include:us._netblocks.mimecast.com",
      " include:spf.protection.outlook.com include:standardregisterSPF.smtp.com ip4:205.219.85.237 ip4:74.209.251.23 ip4:198.245.88.159 ip4:198.245.88.160 ip4:198.245.88.161 ip4:198.245.88.162 ~all",
      "SFMC-ZWQ1KX6NcnbWgSDBdMcM5hev9zt7KIW2ujakv25u",
      "_ndgc16081saphv6ayms33rbsvl6rj68",
      "SFMC-MNg49ZTRiJXS6s5M39xVpTy1s_E-1IHXs9eMp9TV",
      "perplexity-ai-domain-verification-9026ms=pYLmCXhTHCODhZSFIiyoguCNL",
      "SFMC-CrddN9mLDmj3nCgVdj6F1xvJWHcDiUha4ypozOYM",
      "asv=3ac585f916271e3615c45c5cc1c446af",
      "",
      "google-site-verification=iBm5BtEQIPx_1KICdm-iKrhED8pwZmS12JcztEGkEEw\"\"\"",
      "google-site-verification=K295XYTk_JOny2cGYgQiv5OBkqX-vsPbflRWCajmZmQ",
      "goodnotes-verification=08e7496e-47ad-4e16-8b9a-12c40efbe0f9",
      "atlassian-domain-verification=aD0fVXowmsHVk7AN3xQWoTk3fWQjFOAolW1g5Ae492aMfXofVIdEeASIKtjKtOjn",
      "perplexity-ai-domain-verification-9026ms=OwUIgCvAepDBJvWzS6xNO3zPX"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=none; pct=100; fo=1; rua=mailto:l1rcsnp0@ag.dmarcian.com; ruf=mailto:l1rcsnp0@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Palo Alto, organizationName=HP Inc, commonName=hpcom-pro-domain-cloudfront-13.hpcloud.hp.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jul 16 00:00:00 2026 GMT",
    "notAfter": "Jan 30 23:59:59 2027 GMT",
    "san": [
      "hpcom-pro-domain-cloudfront-13.hpcloud.hp.com",
      "wirelesscolorprinters.com",
      "www3hp.com",
      "www.wirelesscolorprinters.com",
      "webprintsmart.com",
      "wwwhpdirect.com",
      "www.webprintsmart.com",
      "www.wwwhpdirect.com",
      "wwwhp.com",
      "www.twitterhp.com",
      "wwwhpshopping.com",
      "www.www3hp.com",
      "www.wwwhp.com",
      "www.touchsmartprinter.com",
      "twitterhp.com",
      "www.touchsmartprinters.com",
      "touchsmartprinters.com",
      "www.wwwhpshopping.com",
      "touchsmartprinter.com",
      "www.hp.ca",
      "hp.be",
      "hp.com.nf",
      "www.hp.co.ke",
      "hp.co.th",
      "www.hp.co.kr",
      "hp.co.cr",
      "www.hp.cl",
      "www.hp.com.kn",
      "www.hp.co",
      "hp.co.kr",
      "hp.com.jm",
      "www.hp.cg",
      "www.hp.com.my",
      "www.hp.co.je",
      "hp.co.il",
      "h30167.www3.hp.com",
      "www.hp.co.ve",
      "hp.co.uk",
      "www.hp.co.mz",
      "www.hp.co.at",
      "www.hp.com.mx",
      "hp.co.id",
      "www.hp.com.mu",
      "www.www8-hp.com",
      "hp.com.my",
      "hp.com.mx",
      "www.hp.co.nz",
      "h20545.www2.hp.com",
      "www.hp.com.jm",
      "hp.com.mu",
      "hp.co.ug",
      "hp.co.tz",
      "www.hp.com.nf",
      "hp.am",
      "www.hp.be",
      "www.hp.co.rs",
      "www.hp.co.uk",
      "hp.com.pk",
      "hp.co.rs",
      "hp.com.pe",
      "www.hp.co.id",
      "www.hp.com.hn",
      "hp.com.pa",
      "www.hp.com.hr",
      "www.hp.com.lv",
      "hp.co.je",
      "www.hp.co.ug",
      "hp.co.mz",
      "hp.com.hr",
      "hp.com.lv",
      "www.hp.co.za",
      "www8-hp.com",
      "hp.co.ve",
      "hp.com.hn",
      "hp.co.at",
      "www.hp.am",
      "hp.co.za",
      "hp.com.hk",
      "www.hp.co.il",
      "hp.cl",
      "hp.cg",
      "www.hp.com.pa",
      "hp.ca",
      "www.hp.co.cr",
      "www.hp.co.th",
      "hp.co.ke",
      "hp.co.nz",
      "www.hp.co.tz",
      "www.hp.com.hk",
      "hp.com.kn",
      "www.hp.com.pe",
      "www.hp.com.pk",
      "hp.co",
      "hp.com",
      "www.hp.com",
      "123.hp.com",
      "www.123.hp.com"
    ],
    "days_left": 127,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "13.249.165.75",
    "open": []
  },
  "https": {
    "status": 302,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: CloudFront"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.hp.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://hp.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 41.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
