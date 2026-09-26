# Security Audit Report — dropbox.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dropbox.com/ |
| Bug bounty program | DropBox |
| Listed scope domain | dropbox.com |
| Test date | 2026-09-25 09:24 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
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

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 19 days (notAfter Oct 14 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: envoy
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 4. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

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
- **Detail:** Header reveals: envoy
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
  "domain": "dropbox.com",
  "dns": {
    "a": [
      "162.125.248.18"
    ],
    "aaaa": [
      "2620:100:6040:18::a27d:f812"
    ],
    "cname": null,
    "mx": [
      "mxa-001ed902.gslb.pphosted.com (pref 10)",
      "mxb-001ed902.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-564.awsdns-06.net.",
      "ns-1162.awsdns-17.org.",
      "ns-315.awsdns-39.com.",
      "ns-1949.awsdns-51.co.uk."
    ],
    "spf": [
      "atlassian-domain-verification=yjrZDQ/hCS3k4pk87lelfsKb7+aOLpQPPgowWw/RHEwDCvNo8zH2iNCjFjZZtPvT",
      "google-site-verification=leXlkd4GKqaMP-t93sX2D_mNej1qyME73hyCvyjkbmA",
      "google-site-verification=2ZBxb1JI0xc_p5crqO_FHyV6OO3iYuvryuZj4nUNCEc",
      "stripe-verification=abd8d702e1361e583deb9f1085ca164782f13f205b1b8b04225f9bac41c3f744",
      "google-site-verification=E9R8qj0pQvUF7rQ3x0s0m5Oh8FGBiO-7CQt-hiPQtFs",
      "infoblox-domain-mastery=d893f536feb426f7bcef35610e78c319a79a9585e03a3cbf753c589e58db5dbfae",
      "google-site-verification=2_3MpLNP3RT2WDZTWn2VErDq0zTl7-IOZMviotkEhEQ",
      "MS=ms91256510",
      "docusign=c18a935e-b7a7-4ca5-a401-9f7cac288c0b",
      "citrix-verification-code=b29deae6-12fa-4939-a5b1-9585f5fc82ba",
      "miro-verification=06f0d83f07b5b7c1936df29f6dc8a6a11cf82d08",
      "jamf-site-verification=EecmGLwXK6l4sJLtg1ckwQ",
      "stripe-verification=58A24CAFE9E3D2B5BC1B57D90B3271230384E4A98B997D269F6E93357C043DF9",
      "slack-domain-verification=1qkjOc6gwuxLaFmX90NDKDiQVw0k4aNHyeT15kdt",
      "notion-domain-verification=enHWmn6FFlHvaUid8AdXGKPkDn7j1VVAKudIomtvw0z",
      "apple-domain-verification=6wGFrdfZ2TC4HlEk",
      "google-site-verification=u07OaGer3GQQDKmGdXvEnVDA7hVQJZ3nVglkGqTxnqI",
      "google-site-verification=dvbnC9kulo9yolnth_U5l7fMneacmwsmc7T-amaztiY",
      "aws-domain-control-verification=fa66314d-b786-43ac-ba00-a2fc8c8da6c2",
      "stripe-verification=5A1286A45D18E28C4909AD9CAA70017D493E1A09417FB572992366CEC23DE9D3",
      "parallels-domain-verification=c22a91cd65da42ee92515d4d96940a8caed8b947d0ed4a37b1fa8cf8dbdd64b5",
      "liveramp-site-verification=l9GQet4bxvwWtgD1svh_74N5vOes7buz_drCyiY-dV4",
      "mixpanel-domain-verify=c8f954c8-17fc-42a3-925c-6ea23ee3b534",
      "stripe-verification=ADB471381BCF8F6CF5635864612A5C41B09F3AD2E69F0BC675D96AB24CCCD5FC",
      "mgverify=32a6a13661e86bff81acaf247c1dd6c5991bccc6a77dbe49f078deef4d61979c",
      "google-site-verification=cPTvnO7zyyCEASSqXGDlzGgEECA-hWG7k_drsp-f9RA",
      "1e6de3584eb44e3e9fde429fb262995bb3f6422cab16daeff7cba598948242b8",
      "anthropic-domain-verification-jk1bd4=WXuV479YDJRmIn8CJaIpZaW4S",
      "hcp-domain-verification=70f13e6db06700814cb6a41bc0b14c0b02d972a58a16bc566918d50ecff3e2f7",
      "google-site-verification=vPdXnwB_snnJ8dqzD0OFEhiy3Vjq2l7qhXA-rnWR1lk",
      "stripe-verification=fc5d818b64666e2f2da6e857d432a8278df3bcadcb7dce142103841f6045a54f",
      "google-site-verification=eL_MhPPeLDIVMzQmUh8cQlm1zzdyZRZs7a5aVqrTPKc",
      "cloudflare_dashboard_sso=4da1dd6908c0c13a852ab394101eafe2",
      "adobe-idp-site-verification=4977108a-46c6-4763-a3cc-b23b3d87e5cc",
      "stripe-verification=7f4c0115f99ee7bc4ed67beff4365dd6b29ec5e4cfca03b874d2de54fb1730a3",
      "hubspot-domain-verification=Y2NiYzY0YjktYzI1MC00NDg5LWI5ZTYtZWY4ZWQ1ZDEwNjdh",
      "google-site-verification=8NWlYGBCOsGGZoWB62V0z-I1v92RPDYt5e2MIcIlKOk",
      "zapier-domain-verification-challenge=2d9f161a-cc7a-4780-862d-04aa31320698",
      "hubspot-developer-verification=YTQ0MmYzMzItYjhhOC00YzhlLTg3ZDYtMjU3NWQ4OWY4MDNk",
      "docusign=a3cf77c9-f563-4c9b-8cbb-73c5322feb8e",
      "v=spf1 ip4:45.58.64.0/20 ip4:185.45.8.0/22 ip4:162.125.0.0/16 ip4:199.47.216.0/22 ip4:108.160.160.0/20 ip4:205.189.0.0/24 ip4:160.34.15.16/28 ip4:52.5.134.202/32 ip4:205.220.162.87/32 ip4:205.220.174.83/32 ip4:167.89.98.146/32 ip4:167.89.89.46/32",
      " ip4:167.89.96.134/32 ip4:159.183.109.97/32 ip4:149.72.220.85/32 ip4:159.183.15.144/32 ip4:159.183.2.51/32 ip4:159.183.2.58/32 ip6:2620:c6:8000::/48 include:amazonses.com include:_spf.google.com include:mail.zendesk.com include:mktomail.com",
      " include:rp.oracleemaildelivery.com exists:%{i}._spf.mta.salesforce.com ~all",
      "decagon-domain-verification-v0ye0x=hK1f8wt5pCP112ZomGdWacypL",
      "aws-domain-control-verification=295d3c77-d647-4042-a10b-17bc6cf2a81c",
      "cursor-domain-verification-me5gdt=FG4EqpnCbcfCNcVW9qV0OYu9R",
      "lovable_verification=oimC5YnefHVCMkPlojvq",
      "openai-domain-verification=dv-taySZvuNYfU5nkRTfwxixP7F",
      "google-site-verification=rGECt1BQW-vtsJ-FgNwFpxTiTMc2DdQ9ZxAwT8nmbTE",
      "docker-verification=215c893f-0bb3-4887-87a2-152ae8636422",
      "google-site-verification=6Gs0C-CwJui707tVZirEFGKvKfGtwwZf2Snzz0-2nUQ",
      "stripe-verification=d0a25558a690907c8476879165000a457c5521640f0be53b0d1acf5f4c311978"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;pct=100;rua=mailto:c7xrs-8253@rua.dmarc.emailanalyst.com,mailto:dmarc@dropbox.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Dropbox, Inc, commonName=*.app.dropbox.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Aug 19 00:00:00 2026 GMT",
    "notAfter": "Oct 14 23:59:59 2026 GMT",
    "san": [
      "*.app.dropbox.com",
      "*.dropbox.com",
      "dropbox.com"
    ],
    "days_left": 19,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "162.125.248.18",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: envoy"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.dropbox.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dropbox.com/"
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
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 120.2,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
