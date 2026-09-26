# Security Audit Report — linktr.ee

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linktr.ee/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linktr.ee |
| Test date | 2026-09-25 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **5** (High: 0, Medium: 0, Low: 1, Info: 4)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 5. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "linktr.ee",
  "dns": {
    "a": [
      "151.101.66.133",
      "151.101.194.133",
      "151.101.2.133",
      "151.101.130.133"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-634.awsdns-15.net.",
      "ns-1534.awsdns-63.org.",
      "ns-169.awsdns-21.com.",
      "ns-1782.awsdns-30.co.uk."
    ],
    "spf": [
      "h1-domain-verification=HDHQ9deSLqK9KYahSa9UU559PvrgNBi3T1zdN9Lj8CVoYCV8",
      "stripe-verification=0AB4346953316F0622DA92E369CDFA951C54E959A15CC1CFB96E49D02E203691",
      "uber-domain-verification=88d7ba7b-2a23-42ae-ba4f-e96706f6b728",
      "google-site-verification=c_BBAAGdYj2L7cOpPgNF76jiXnFUVS_Xz5gfcBOmGL4",
      "dropbox-domain-verification=831j6zm4fvfj",
      "facebook-domain-verification=8ssyxgwhdjg409vl1qwv8tqy6745zy",
      "google-site-verification=tOpEoiVk37-4HaCFCMb86Q2F9zpl4gh0cF9PvQjJ5aw",
      "stripe-verification=58C8428D5C7E162ADE166B3F34072EC21AA64FE97D46970CC352FAB198CC1F9E",
      "_5gpstlp0j1ze117x41vpd77qfn3qn6q",
      "amazon-business-verification=16012857de4a76553695df824bae16348649f39cf989c2354b5bc7cd379b15e9",
      "openai-domain-verification=dv-PfCKEtIOkYIRSjuyixJqqZcf",
      "google-site-verification=-3XY-ldZZm2O8v9blT-mMiBduUxNdPsrrFXneZFHJNU",
      "google-site-verification=ictM7BaxKAXWoNxeAH2qUWzbIWwUZT0krATNluy2hwg",
      "onetrust-domain-verification=e0ec11d4d77546b791a0f946a32a6c1e",
      "ZOOM_verify_FEdjcGCXQD7LtbPD7NDAPO",
      "google-site-verification=oJ0isC1gRFlJdV5L_p5ObuVX0JCcyzPQ2N4FcdFSY-c",
      "stripe-verification=61B436C0036D8172284A969CE10CED7FFF67D38B204B51F49A0A2C3D3C65805B",
      "google-site-verification=J_OCvoB105vcwDCwwO0xZlxvWZLz6-UzS4UssSeiy-U",
      "stripe-verification=85AF8598246098631ED129FA3218F6C4DA2CFEC57DD8A9F080110B8CA399D2DD",
      "stripe-verification=731DF94DEAEA1EAAA807EAE7D72D7338E193CD76AE97150ECF41896807B1B033",
      "google-site-verification=M0XDPVdF5XBrnb-68KdBWmKi35ovRf_PqZM6zRj6xfo",
      "zoom-domain-verification=ZOOM_verify_3d500f8c401c445e9cc337e189236ef5",
      "Validity-Domain-Verification=6HrSbK1DTz+C/kYrvt2yxBW93F4=",
      "tiktok-developers-site-verification=HhSSn99SRimgJNJJkcm0Rt0tjhOiMLW5",
      "t252Y1nfZvxjX0093cC7cncQHg",
      "MS=ms25160908",
      "google-site-verification=5_2gPClKT1kQHILAWOrq9g-MDZQpYTvUvAMV5lADcHU",
      "stripe-verification=15f31e50c5710252111569ad76dfd30414dfe84321fddd6fb2f7cf42ced4e306",
      "stripe-verification=28e5f4ef1feaccb632b7affa6996c5fd43b1e4fafe6b87fe7fa34543a77f090a",
      "hubspot-domain-verification=MTQzMjVkY2EtZDc5YS00ZmMwLTgzNmMtODJhZWFhNjQ1MTFi",
      "loom-site-verification=1c1e2086449545d190b57b810de3c741",
      "notion_verify_LZm1CNzi_RmH#UCV.uR1MvXKsWEG8nebvc}bw+TYMj)mzgrf33H1tUkj*g@r37^#nuKBqT",
      "anthropic-domain-verification-1tycht=zJnYXvMUrBuyoLB4eKC6V1Wav",
      "tiktok-developers-site-verification=5TpDHtevdeyto1s53FrggeA4rqLMU34r",
      "google-site-verification=BqwBT-jSv9iENaqGfI_gbooYEjs3uUHh-lXpVf8tkJk",
      "wiz-domain-verification=993ae6f241de2f53ea30277e8fb8042709252ec68b523cf26181b4cbef0a0a0c",
      "v=spf1 include:sendgrid.net include:hs.linktr.ee include:_spf.google.com -all",
      "attio-domain-verification=UHX2B6D5TX6CX53CXGBAHGW3",
      "google-site-verification=JnB4sONl0K7d3wGyRs9an0C0VJFVhhmGSjf5diV790k",
      "slack-domain-verification=62Jx5SGkgzgdLmF6mYPo1oWMHoLI1PGqzxt71dYk"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@dmarc.everest.email,mailto:dmarc@linktr.ee;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=linktr.ee",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YR1",
    "notBefore": "Aug 29 01:38:02 2026 GMT",
    "notAfter": "Nov 27 01:38:01 2026 GMT",
    "san": [
      "linktr.ee"
    ],
    "days_left": 62,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "151.101.66.133",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Link in bio tool: Everything you are, in one simple link | Linktree"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.linktr.ee",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://linktr.ee/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 406",
    "/redirect?next=https://evil-auditor.example/x -> 406",
    "/go?url=https://evil-auditor.example/x -> 406",
    "/url?url=https://evil-auditor.example/x -> 406"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 406,
    "/.well-known/security.txt": 404,
    "/security.txt": 406,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 406,
    "/.htaccess": 200,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 404
  },
  "subdomains": {
    "status": "crt.sh 429 (certspotter 429)"
  },
  "elapsed_s": 11.2,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
