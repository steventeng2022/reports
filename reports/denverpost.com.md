# Security Audit Report — denverpost.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://denverpost.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | denverpost.com |
| Test date | 2026-09-25 09:13 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **10** (High: 0, Medium: 0, Low: 2, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | H6 | Server technology disclosure | CWE-200 |
| 9 | info | P11 | WordPress login page exposed | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 9. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "denverpost.com",
  "dns": {
    "a": [
      "192.0.66.2"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-1220.awsdns-24.org.",
      "ns-503.awsdns-62.com.",
      "ns-1019.awsdns-63.net.",
      "ns-1679.awsdns-17.co.uk."
    ],
    "spf": [
      "k0710qvbmi4c1pu6fp5fpvq3h",
      "36ailchom7s11o20nu6uqgo69o",
      "_globalsign-domain-verification=_OUsAbDOaFYPYWOgAjdN9k-kV76av1Rf5Pg4XHx3dL",
      "_globalsign-domain-verification=gctAD22GIK3YS4qVlothF9J8N9P35BDNYtltbRXnnM",
      "specops-verification-code=700c2dff-5af8-4409-a777-25df1fb770e6",
      "globalsign-domain-verification=wdsjy5b1d3sGjlpf2ZSfdpjPcsNrXC_iOKH4GEnR0_",
      "e3fltk8am78ee4uept7hiqftu0",
      "_globalsign-domain-verification=qu9bswx7_efyr0AnoYMkd0ZmvFdZNxur1nGSq55P5P",
      "knowbe4-site-verification=a9ce6449edf2d51c41eed1f3517d26f9",
      "_globalsign-domain-verification=SGSNuVFXgku36Q1g39h5zCWUAutWLDNr2xISH37_-n",
      "1lhc1bmucsjp7q8b91t87nhm01",
      "sl4nmnrb1rno4slakgbovshcs0",
      "google-site-verification=2bKNvyyGh6DUlOvH1PYsmKN4KRlb-0ZI7TvFtuKLeAc",
      "IP26DG603F9M48358IST7R5L3I",
      "MS=ms42763989",
      "84CEACD71A34A37DDA18007FD39FA913473B8C85",
      "google-site-verification=f0YC07m4ehdn8TAFlPwmgd6cUL2ne-J8HSQ4XjVwXzk",
      "_globalsign-domain-verification=B57sRQpmte4G4w-gavZbVNmmNsMxGp5kcL19UP2599",
      "_globalsign-domain-verification=nx5U56FiDUqhsckpguh1BWVo8oJVRsFtwCfGxdBN4e",
      "aslt820givt06ua5qjmkutdm4b",
      "v=spf1 include:_spf.google.com include:_spf.salesforce.com include:_spf.mnginteractive.com include:sendgrid.net include:amazonses.com include:outboundmail.blackbaud.net include:mmsend.com ip4:52.6.112.187  ip4:63.87.106.0/23 ip4:68.232.128.0/19 -all",
      "bw=o2AhWgmJR//LI2rv8ZuBaKChD0Ub6rd1lZ53Dg9MG4fp",
      "google-site-verification=d2473NFa5jCbg_yQ0m3ZZyA4fO_q5Bnt7C2XNlx9JRk",
      "llib6qvjasng0m5c7562bvdl78",
      "7bsbnac1nf7c1tfrv8c7gamjrf",
      "4pj8eagm2vmptskd6g1hk0gm5t",
      "1lhc1bmucsjp7q8b91t87nhm01.",
      "_globalsign-domain-verification=0TyIZcbLmgSwoVohQ9GWaLbZq22eAkpviTlcN7JXo3",
      "MS=63BE0B5C6D28D2CE1C330D9F740E9E25038D5DB2",
      "3mmibbsavpv6o2hkq39uqhsr49",
      "facebook-domain-verification=1yiyurr8k1l0cfwvgyjk5w823lm9ua",
      "00D6A000000u2db=1TBRP00000001SL",
      "tollbit-domain-verification=d3cc43d6a25115e73321be2cb765b25a1cc2c7ec945ec934dde6bbc20dcef9f9",
      "ega5pobqtumor93gg1fighan98"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@dmarc.everest.email; fo=1; pct=100; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=denverpost.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep  5 17:11:49 2026 GMT",
    "notAfter": "Dec  4 17:11:48 2026 GMT",
    "san": [
      "denverpost.com",
      "www.denverpost.com"
    ],
    "days_left": 70,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "192.0.66.2",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.denverpost.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://denverpost.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 301,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 301,
    "/security.txt": 301,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 100.7,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
