# Security Audit Report — marriott.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://marriott.com/ |
| Bug bounty program | Marriott |
| Listed scope domain | marriott.com |
| Test date | 2026-09-25 10:01 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 4, Info: 7)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AkamaiGHost
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=86400 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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

### 9. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 10. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AkamaiGHost
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "marriott.com",
  "dns": {
    "a": [
      "23.209.216.125"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "marriott-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "use4.akam.net.",
      "eur4.akam.net.",
      "usc2.akam.net.",
      "usc1.akam.net.",
      "ns1-7.akam.net.",
      "ns1-22.akam.net.",
      "eur3.akam.net.",
      "eur1.akam.net."
    ],
    "spf": [
      "docusign=b47573dd-01c3-49a8-9014-26e813e1c8d2",
      "cursor-domain-verification-1fjpt7=Pu1dYBwqsDofgAhFP0N6ME9YW",
      "amazonses:TdaQ33Ma34JA3mbWth3J30gcPqfDoCkl/gpcDpdk1hM=",
      "Dynatrace-site-verification=b018e42d-1bf3-4214-a55d-b6d11d472484__dkbokapmaohqnqf6rjt4vc75d1",
      "e2ma-verification=5eigb",
      "e2ma-verification=zhe3",
      "e2ma-verification=i7b3",
      "amazonses:T+PiZncc85hp45Hh5rxnadRc3PqQCxeWhb2Iulxh+HI=",
      "google-site-verification=Op26MVqGm5ezgYeMJ0t_6ZCjHTtBehaS43CpvlTFkPg",
      "liveramp-site-verification=dphz_fboDvNf-L04XjGWSNpfcEjqykIGaOetpgtRFrY",
      "amazonses:dRwYaeqcRYgOr0nfuNpgfwcye7qC/+W7j9+4l95WmfA=",
      "e2ma-verification=puqeb",
      "smartsheet-site-validation=PYWle4OQif7gvVJpZX6Xo3bdBYQQX8Vu",
      "e2ma-verification=pzchb",
      "_vo9fuuxfwrimz2thuq6vane5ixcrnre",
      "docusign=a75f5992-a1f4-42fb-b1fb-36850d8e976a",
      "anthropic-domain-verification-m96n5v=HAYrymWgY4PChnGI984pVkay5",
      "bv-domain-verification=0d66f71c181efe6f149b1afc3bf7494520986eddfd13915969aa53da25a4a5f5",
      "9ea2de8a-d4af-4255-86f8-22e6410e7a3a",
      "DocuSign-JAS-3f8670aa-a7b3-4c80-b87c-c4009cf24fef",
      "e2ma-verification=5nbgb",
      "facebook-domain-verification=7yktss7qob13nc0gahxo6028udc8ti",
      "e2ma-verification=r4qcb",
      "infoblox-domain-mastery=078e97082eaa5be71d1011466d456249102dd95393572d0c23d7652a65d4dec5cf",
      "h1-domain-verification=3bPxkTRBe4uck7trDLA9BEguQdHUTpEsbin4kgsAepgHSnsi",
      "e2ma-verification=8oreb",
      "e2ma-verification=9ntgb",
      "e2ma-verification=qohib",
      "e2ma-verification=2m0fb",
      "NhJc80JClTwLvKuJzmJzVRWhiX7JEubBi8Tegyp1MyGbRSn0bMKddsgokifhxw2JuZ76PZ8qFHYEW9Aa8ykiwQ==",
      "e2ma-verification=rohib",
      "e2ma-verification=eqqgb",
      "e2ma-verification=g23cb",
      "cisco-ci-domain-verification=510f4042252171cd62c2992306c3623499318270fcef3f0266e4bc2bc4df9053",
      "MS=ms72490600",
      "onetrust-domain-verification=c8419e55a9f44fd3a2aea1086589b47c",
      "flexera-domain-verification-jbnluuhrebvugcmr",
      "e2ma-verification=hsbcb",
      "atlassian-domain-verification=zzbKNynGXmBVVjHMpHdfFpEwzGxKV5plDTgGo00mBnx6f3sEd30UmA/w/TPcy9Ai",
      "EMMA-VALIDATION2-22-21",
      "google-site-verification=vGWnWWqZZS-wOwob2dGmMK44ncOOD3s3Vy7mkUR2CQk",
      "v=spf1 include:spf.marriott.com include:spf.givex.com include:mail.zendesk.com a:c.spf.service-now.com include:spf.protection.outlook.com",
      " ip4:65.221.12.128 ip4:65.221.12.148 ip4:70.42.227.151 ip4:70.42.227.152 ip4:68.233.76.14 ip4:68.233.76.20 ip4:68.233.76.41 ip4:216.34.69.5 ip4:34.194.251.20",
      " ip4:41.138.70.80/29 ip4:52.86.138.215 ip4:23.251.231.176/28 ip4:23.251.231.192/28 -all",
      "e2ma-verification=rzicb",
      "postman-domain-verification=f50031b67f277c87b8d1fc380cdab9ae7c24fd70fe60547b6d37cb0f78bc3573949498c86dd8ca48648b3f2c4c225df73ee99f2dacae3513358a8911124ad0eb",
      "meltwater_sso_20250515",
      "amazonses:ycQqj6K4JaTXJZHZIcYKm+rZk3kf0+CDo58LI2UwkR0=",
      "canva-site-verification=jksL3Zvuljo2ex9weFenew",
      "adobe-idp-site-verification=b58a812cb8a67904b7b89c5ba71e21242157d93cc4609f572f4d63398d2f1c95",
      "figma-domain-verification=92316758906766ace0ee6271ca4f1ccf3795fce0f1925f846f4a5ee4c3dd0cfb-1732030374",
      "e2ma-verification=g83fb",
      "apple-domain-verification=0BpDQkck5deFVztA",
      "e2ma-verification=t4xeb"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:ts2wfbhi@ag.dmarcian.com; ruf=mailto:ts2wfbhi@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Maryland, organizationName=Marriott International Inc., commonName=www.marriott.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA OV R40",
    "notBefore": "Feb  5 00:00:00 2026 GMT",
    "notAfter": "Feb  5 23:59:59 2027 GMT",
    "san": [
      "www.marriott.com",
      "arabic.marriott.com",
      "arabic.reservations.bulgarihotels.com",
      "auth.marriott.com",
      "cache.marriott.com",
      "cache.marriott.com.cn",
      "channel-portal.homes-and-villas.marriott.com",
      "ci-propertyconversionportal.marriott.com",
      "clean.marriott.com",
      "cwp.marriott.com",
      "empower-enrollment.marriott.com.cn",
      "espanol.marriott.com",
      "gaylordnationaltickets.com",
      "gaylordpalmstickets.com",
      "gaylordtexantickets.com",
      "getgaylordtickets.com",
      "homes-and-villas.marriott.com",
      "journey.ritzcarlton.com",
      "learningcontent.marriott.com",
      "marriott.co.jp",
      "marriott.co.kr",
      "marriott.co.uk",
      "marriott.com",
      "marriott.com.au",
      "marriott.com.br",
      "marriott.com.cn",
      "marriott.com.tr",
      "marriott.de",
      "marriott.fr",
      "marriott.it",
      "marriott.pt",
      "news.marriott.com",
      "oci-prod-integration-mipaasiaasservices-dlz.marriott.com",
      "oci-prod-integration-mipaasiaasservices-hireright.marriott.com",
      "oci-prod-integration-mipaasiaasservices-iam.marriott.com",
      "prod-mipaasiaasservices.marriott.com",
      "qrcode.marriott.com",
      "reservations.bulgarihotel.com.cn",
      "reservations.bulgarihotels.co.kr",
      "reservations.bulgarihotels.com",
      "reservations.bulgarihotels.fr",
      "reservations.bulgarihotels.it",
      "reservations.bulgarihotels.jp",
      "reservations.gaylordnational.gaylordhotels.com",
      "reservations.gaylordpalms.gaylordhotels.com",
      "reservations.ritzcarlton.cn",
      "reservations.ritzcarlton.com",
      "reservations.ritzcarlton.jp",
      "reservations.texas.gaylordhotels.com",
      "rewards.ritzcarlton.cn",
      "rewards.ritzcarlton.com",
      "rewards.ritzcarlton.jp",
      "ritzcarlton.com",
      "webhook.hvmi.marriott.com",
      "wechat.api.marriott.com.cn",
      "whattoexpect.marriott.com",
      "www.arabic.marriott.com",
      "www.auth.marriott.com",
      "www.deltahotels.com",
      "www.engage.marriott.com",
      "www.engagecris.marriott.com",
      "www.engageproperty.marriott.com",
      "www.espanol.marriott.com",
      "www.gaylordnationaltickets.com",
      "www.gaylordpalmstickets.com",
      "www.gaylordtexantickets.com",
      "www.getgaylordtickets.com",
      "www.grouppartners.marriott.com",
      "www.homes-and-villas.marriott.com",
      "www.journey.ritzcarlton.com",
      "www.marriott.bh",
      "www.marriott.co.jp",
      "www.marriott.co.kr",
      "www.marriott.co.uk",
      "www.marriott.com.au",
      "www.marriott.com.br",
      "www.marriott.com.cn",
      "www.marriott.com.qa",
      "www.marriott.com.tr",
      "www.marriott.com.tw",
      "www.marriott.de",
      "www.marriott.fr",
      "www.marriott.it",
      "www.marriott.om",
      "www.marriott.pl",
      "www.marriott.pt",
      "www.marriott.sa",
      "www.ritzcarlton.com",
      "www.travelagents.marriott.com"
    ],
    "days_left": 133,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "23.209.216.125",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: AkamaiGHost"
  ],
  "cookies": [
    {},
    {},
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.marriott.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 403
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
  "elapsed_s": 24.0,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
