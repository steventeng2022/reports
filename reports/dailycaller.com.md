# Security Audit Report — dailycaller.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://dailycaller.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | dailycaller.com |
| Test date | 2026-09-25 17:50 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 4, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P11 | WordPress login page exposed | CWE-200 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |
| 16 | info | CT1 | 34 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.6.240:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.20.6.240:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; X-Powered-By: Express; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 8. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 9. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 10. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 11. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 12. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 13. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 14. [INFO] WordPress login page exposed (`P11`)

- **CWE:** CWE-200
- **Detail:** /wp-login.php returns 200.
- **Recommendation:** Restrict or rate-limit the WordPress login endpoint.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 16. [INFO] 34 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: git.dailycaller.com, push.cms.dailycaller.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "dailycaller.com",
  "dns": {
    "a": [
      "104.20.6.240",
      "104.20.7.240"
    ],
    "aaaa": [
      "2606:4700:10::6814:6f0",
      "2606:4700:10::6814:7f0"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 40)",
      "alt2.aspmx.l.google.com (pref 30)",
      "aspmx3.googlemail.com (pref 50)",
      "aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "nile.ns.cloudflare.com.",
      "cortney.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=4AD9l3jnq_7mC91UBXtTJ2SVAQF65R2NqW2SzB0fyWY",
      "hiryanfromdisqus",
      "google-site-verification=R_HWsuGY5D2jhyrsiBYoNdou3xQM7mfMvmLNRIf5uNk",
      "google-site-verification=MMCR7ys_IcnzoxvIgPvkIZqhaPjcnoD1xv6MX13EoGs",
      "notion-domain-verification=wlPIL0HDvUMkeXcyPQiHB1EnfOwwhQ1vxpmiCcLY9w3",
      "yandex-verification: a8cb98c870b639cc",
      "google-site-verification=aDLIgzpZsWhltTo0byY4JIrXErh2FSZC7gTNA-pcado",
      "v=spf1 mx ip4:74.203.48.0/23 ip4:74.203.57.0/24 ip4:174.46.206.0/23 include:amazonses.com include:spf.mandrillapp.com include:sendgrid.net include:_spf.genoomail.com include:spf.mtasv.net include:_spf.google.com ~all",
      "pinterest-site-verification=b357bf035fef44e634ab43bf435d2592",
      "facebook-domain-verification=cu97te0w4snsvnklnozd4wdzpmdusx",
      "brave-ledger-verification=e8997655e682114364452598541e771c9848cc4a344ed9c9381f3c95c1caf5fd",
      "google-site-verification=2rfEL1JNH_PfDnvN8sg2Mv121z8XI-0UrVGGBiaL3NM",
      "google-site-verification=JdrtZ9wr1Q1g22ntrYqNUiKtYX5TMbcrERLij2gcw6g",
      "klaviyo-site-verification=VymSM6",
      "anthropic-domain-verification-7vzw58=TbcPUP7giRsFaeMjcj5Le3Y0y",
      "dailymotion-domain-verification=dmz0onmsz1bovllha"
    ],
    "dmarc": [
      "v=DMARC1; p=none"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=dailycaller.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  4 20:15:31 2026 GMT",
    "notAfter": "Dec  3 21:15:10 2026 GMT",
    "san": [
      "dailycaller.com",
      "meta-feed.dailycaller.com"
    ],
    "days_left": 69,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.20.6.240",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "The Daily Caller"
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "X-Powered-By: Express",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.dailycaller.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://dailycaller.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 404,
    "/server-status": 302,
    "/api/": 404
  },
  "subdomains": {
    "source": "certspotter",
    "count": 34,
    "notable": [
      "git.dailycaller.com",
      "push.cms.dailycaller.com"
    ],
    "sample": [
      "americansquatter.dailycaller.com",
      "blackfriday.dailycaller.com",
      "cartelvillefree.dailycaller.com",
      "charliekirk.dailycaller.com",
      "ci.dailycaller.com",
      "codetestfunnel.dailycaller.com",
      "compliance.dailycaller.com",
      "dailycaller.com",
      "damaged.dailycaller.com",
      "editorsbrief.dailycaller.com",
      "epsteinpetition.dailycaller.com",
      "epsteinpoll.dailycaller.com",
      "freeenterpriselive.dailycaller.com",
      "games.dailycaller.com",
      "git.dailycaller.com",
      "hamericansquatter.dailycaller.com",
      "hsellingsex.dailycaller.com",
      "insidececot.dailycaller.com",
      "lawlessfree.dailycaller.com",
      "liveevents.dailycaller.com"
    ]
  },
  "elapsed_s": 11.3,
  "rechecked": "2026-09-25 17:50 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
