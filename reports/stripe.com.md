# Security Audit Report — stripe.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stripe.com/ |
| Bug bounty program | Stripe |
| Listed scope domain | stripe.com |
| Test date | 2026-09-25 10:19 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **4** (High: 0, Medium: 0, Low: 0, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H6 | Server technology disclosure | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

## Evidence (raw response observations)

```json
{
  "domain": "stripe.com",
  "dns": {
    "a": [
      "198.202.176.41",
      "198.137.150.41"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)"
    ],
    "ns": [
      "ns-1087.awsdns-07.org.",
      "ns-423.awsdns-52.com.",
      "ns-705.awsdns-24.net.",
      "ns-1882.awsdns-43.co.uk."
    ],
    "spf": [
      "neat-pulse-domain-verification-8GMn8nv=36eba03d-345e-421a-a823-d6d1f28938a4",
      "_c2ygqoyhcuwjjnqk7h1mcm0x144rm1z",
      "liveramp-site-verification=7gyFkTwGYsvgd7IUQwyAOfImETwR06wgKjKiXq90KEY",
      "_2m7hdcar6jar33f5vyr8h0xaru6rvrn",
      "VISA=38A3D7A1AA5D71E43525144DD886F6B8",
      "anthropic-domain-verification-zk7x9c=QfN52ECybLPUWh51R9pKF0QO3",
      "asv=8de0c1a866b958297e22a36216e594a6",
      "z4mthhzk10l6qc0rg4211mnnppkh2y5b",
      "00D50000000JV6w=1TBTQ0000000CIv;00DDn000000HWol=1TBVY00000002Hx;00D4x000003vxGL=1TBPQ00000008Tp;00Dfn00000BUlWD=1TBan0000000LPR",
      "linear-domain-verification=prudk75mtrrj",
      "cursor-domain-verification-vncvvm=D0NzeIDbQa8PPgIf1ukp9UPiu",
      "vercel-domain-verification-n462w8=JRePwTQbccpon6VAqYhidisHw",
      "docker-verification=ccde1a0d-8d2c-44b5-9d20-6c4e19113fc9",
      "h1-domain-verification=KhpNX9YNAc7bX95agGvFsPPKbYTVe1KC6xj7P1zKZrRzxcuS",
      "atlassian-domain-verification=upLp21qQgja1aHG2gnAb1AmXRqb/zG0UK1a0n3zTSXZg5DgOSttR3i5uzA3T9Cdk",
      "google-site-verification=ZgGi2-xDdfnaWxdfjn5AqtUS11jKWqSXAV_EHODFzdE",
      "vercel-domain-verification-0x8270=XezzJjJYrYZwY6CahDneh2ruB",
      "google-site-verification=PrlpJHdk11CIkPsiXoHEAJevWHAk39JRFAqVSe9l7n0",
      "google-site-verification=hPfjsDwiisKJ4RP1ExOst9gAOD_0P8Q7-kxdcKUvEcc",
      "MS=ms80697640",
      "google-site-verification=qjP3OAiraClha_40cX9Z9FrG5q3O_0InXSamXOswY-s",
      "facebook-domain-verification=m7id9rt8ehlgcg9tt2yggbsi6gro7i",
      "docusign=4c9f5602-1c19-4e4c-bde7-77dc4b9ea8a0",
      "google-site-verification=pmz8ueKvWMPxNlwUDcVroF91-tq6I9VM6wSO_0i7-wc",
      "fastly-domain-delegation-3c9tdnjzdwy7wfffvyyy-786084-2024-07-08",
      "vercel-domain-verification-d2ks5d=rkbS4OdBoLxPogGq2IhBN1OZV",
      "v=spf1 ip4:198.2.180.60/32 ip4:13.111.2.227/32 include:spf1.stripe.com include:greenhouse-outbound-mail.stripe.com include:_spf.qualtrics.com ~all",
      "edcbf4c7-b604-457b-870e-1b05f655e769",
      "openai-domain-verification=dv-9tiBE20GDN0Td9lCfVtA3DwG",
      "whimsical=253112f9add9790f3a27b9d9893626451fc4cda1",
      "apple-domain-verification=8kIS0gmJTvILWQuI",
      "elevenlabs=NpcIkVJW_8Vyd2gLKzPviuaU1g5rz83KiWQQ3sWKGtI",
      "canva-site-verification=xLypn0D9XANRy-lbwcMfHA",
      "v=MCPv1; k=ed25519; p=WMeka0C1fIH9HQLMtsSM9DD9cM6Bz6Wz34mHnK86UcM=",
      "vercel-domain-verification-9rcztj=vE2uCkG0lJyU17dOW1DamoD7v",
      "postman-domain-verification=c3b168067b16085c452b04b643ae1000079b095e383b53d1074e409b0e600b6265e1c7963beca1ca87cc63c381dcea332544c92c919651e4cda69f9a6303079c",
      "stripe-verification=82ce82470fb8324e19fa65abdb6fd370da5a8f90bba09712f259760f625d0790",
      "google-site-verification=NLkFgZLHeVMVYlR3t1UZC9_1LzmqCAefJyNDs6ZQqBA",
      "docusign=4a93db58-af07-4632-a881-b569d41a6c57"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc-reports@stripe.com; ruf=mailto:dmarc-forensics@stripe.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "jurisdictionCountryName=US, jurisdictionStateOrProvinceName=Delaware, businessCategory=Private Organization, serialNumber=4675506, countryName=US, stateOrProvinceName=California, localityName=South San Francisco, organizationName=Stripe, LLC, commonName=stripe.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "notBefore": "Aug 17 00:00:00 2026 GMT",
    "notAfter": "Nov 12 23:59:59 2026 GMT",
    "san": [
      "stripe.com",
      "www.stripe.com"
    ],
    "days_left": 48,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "198.202.176.41",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Stripe | Financial Infrastructure to Grow Your Revenue"
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.stripe.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://stripe.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 200,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 28.1,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
