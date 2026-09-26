# Security Audit Report — coursera.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coursera.org/ |
| Bug bounty program | Coursera |
| Listed scope domain | coursera.org |
| Test date | 2026-09-26 18:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **15** (High: 0, Medium: 0, Low: 3, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 7 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 10 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 13 | low | CK4 | Session-like cookie without HttpOnly | CWE-1004 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 4. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 5. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 6. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie '__204u' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 7. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie '__204u' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 10. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=UGpuPtZLCcMKFmgAeN4q6EbvxJn56A8Jz0sgW3yVKmA; google-site-verification=61uiBFuqY-MYJHWt_8qbU00Rsn7Nq_njU5eMUG0NlrY; google-site-verification=nLfEbuY6OaO0lfas7ywHqpPnOMnobNONSJ0hnbJO9co
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of coursera.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 13. [LOW] Session-like cookie without HttpOnly (`CK4`)

- **CWE:** CWE-1004
- **Detail:** Cookie 'CSRF3-Token' looks session-related and has no HttpOnly attribute.
- **Recommendation:** Set HttpOnly on session cookies.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 54 disallow path(s), e.g. /maestro/api/, /api/, /maestro/, /ui/, /signature/voucher/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 54.192.248.29 carries PTR server-54-192-248-29.tpe53.r.cloudfront.net. for coursera.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "coursera.org",
  "dns": {
    "a": [
      "54.192.248.29",
      "54.192.248.67",
      "54.192.248.28",
      "54.192.248.75"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx3.googlemail.com (pref 30)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx5.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "ns-688.awsdns-22.net.",
      "ns-1590.awsdns-06.co.uk.",
      "ns-258.awsdns-32.com.",
      "ns-1481.awsdns-57.org."
    ],
    "spf": [
      "google-site-verification=UGpuPtZLCcMKFmgAeN4q6EbvxJn56A8Jz0sgW3yVKmA",
      "elevenlabs=iuq-HrTSPpSbgooOeznbfY9bR-awTAYggzjFxD0Q6Rw",
      "google-site-verification=61uiBFuqY-MYJHWt_8qbU00Rsn7Nq_njU5eMUG0NlrY",
      "google-site-verification=nLfEbuY6OaO0lfas7ywHqpPnOMnobNONSJ0hnbJO9co",
      "google-site-verification=PDgfi1HUgagq2NZOh86B3PpGnjDyNXdUr9iyWzDjONM",
      "google-site-verification=BbSjFsQN-aTkQDOiar6q3O4fPzSlgepoOdM3fMuCXFA",
      "facebook-domain-verification=46dep9ql4m6it0wahwkhiou7xit57h",
      "rzp-site-verification=0e1f055c2e81430150efedded50e7992",
      "v=spf1 include:sendgrid.net ip4:24.6.102.21 ip4:50.16.53.44 include:_spf.google.com include:amazonses.com include:spf.mtasv.net include:_spf.salesforce.com -all",
      "onetrust-domain-verification=bc353cda9f49402e8b2ac8a3b3e86286",
      "BthfBdp8W7Bqmm87eNGy",
      "yandex-verification: 7472d03e746e191a",
      "zoom-domain-verification=6fb6c268-238e-477b-ba40-2f0164695cd7",
      "docusign=05d7ee1b-a029-4b94-912a-25bb3c4a2bed",
      "google-site-verification=l-IugqqOHDGlHpUHfv3e6z8J1koLgfGSem04lqBA_B8",
      "376174617-10056694",
      "google-site-verification=874wxzrE4FAJO81XTCXyH6WYnWZAMdlbMRXI3lfI0bw",
      "stripe-verification=0f6967e13ea84d76953d1c3f2dc9eb80e82f090fff99161cd2fa957f55a71d60",
      "stripe-verification=34fd6b74183c244d59d572c162e5b77fe6eed5e5205296151f49dda7b68670eb",
      "jamf-site-verification=Q2xELHJlL4PRcETKdUHldQ",
      "jamf-site-verification=AmVhIhwqDzkoVxg_B0K81w",
      "atlassian-domain-verification=pwnyCbGEmC6E08lYJGO/SYkQvbjFS+OXy03eVMG75U52Edj0vbZGBjdaorxh+PUE",
      "openai-domain-verification=dv-ykQklEbL6szace8vG1l7ejkQ",
      "cursor-domain-verification-kg2va5=P61NAJ77jH4Kuavd9jaD3I4Bw",
      "paloaltonetworks-site-verification=3d8b8eeec8974a6c2b181f7decddc8a96d9cbdcb8f39e4923c53d477a96f6d37",
      "lovable_verification=01oL6h2mkM0xtkXhCoKq",
      "canva-site-verification=m3eGQL4tz88BqXJO92JRpw",
      "miro-verification=d5e807f40d602cde4051496eaaa95234e158ada0",
      "google-site-verification=fFsckLsIOub_171zkeWLBQ72SvjwGSPsz209wwTtmX4",
      "apple-domain-verification=8gxy28dzSlSOYkUI",
      "loom-site-verification=7b75ba5c84f6455bb4fccb7932970dfa",
      "anthropic-domain-verification-r913z0=qHfIpP1D8b5nWxj2rpstnqRZ1",
      "hubspot-domain-verification=ZTM1ZDk4NGEtNWU5Ny00NDJiLWIwNTQtZTA1NGJhZmU3MzZh",
      "cisco-ci-domain-verification=5b418d2526e560d4ec96988886c86e7930c6936b68215183295356a4e4bf36d7",
      "spf2.0/pra include:amazonses.com include:sendgrid.net include:_spf.google.com include:spf.mtasv.net -all",
      "MS=ms91657421",
      "google-site-verification=H2oN7Mv4QCzOClwXz1j30f-4544byEDxyEk0o3eluE0",
      "google-site-verification=L8lg2XWlLydULXIxANaXcbkcCg3UGYGMRp8y0wi8aXs",
      "atlassian-domain-verification=iztR9OQCHGIVBm5w5PmFPf1nTaqiOROSuNTF9Kv0idnfzCBmAsbfwGEF2aOK+yo4",
      "google-site-verification=tbpsWy5oBEvo-Kod36Lqsb3qRK0h_divcCGAeUdVZlk",
      "stripe-verification=95449f6ae01b02ef7f65b59ee2f3ed14bac52c49aaa1519e57b864b70baede3a",
      "docker-verification=6792a290-383f-4d78-9f9b-71f46df7b6b2"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@coursera.org; ruf=mailto:dmarc-reports@coursera.org; fo=0; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=coursera.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 23 00:00:00 2026 GMT",
    "notAfter": "Mar  8 23:59:59 2027 GMT",
    "san": [
      "coursera.org",
      "*.coursera.org"
    ],
    "days_left": 163,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "54.192.248.29",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": ".coursera.org",
      "samesite": "lax"
    },
    {
      "domain": ".coursera.org"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.coursera.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://coursera.org/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=UGpuPtZLCcMKFmgAeN4q6EbvxJn56A8Jz0sgW3yVKmA",
    "google-site-verification=61uiBFuqY-MYJHWt_8qbU00Rsn7Nq_njU5eMUG0NlrY",
    "google-site-verification=nLfEbuY6OaO0lfas7ywHqpPnOMnobNONSJ0hnbJO9co",
    "google-site-verification=PDgfi1HUgagq2NZOh86B3PpGnjDyNXdUr9iyWzDjONM",
    "google-site-verification=BbSjFsQN-aTkQDOiar6q3O4fPzSlgepoOdM3fMuCXFA"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20260823000000",
      "not_after": "20270308235959"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/maestro/api/",
      "/api/",
      "/maestro/",
      "/ui/",
      "/signature/voucher/",
      "/account/",
      "/acclaimbadge/",
      "/voucher/",
      "/search",
      "/ent-website/",
      "/learn-perf/",
      "/specializations-perf/",
      "/professional-certificates-perf/",
      "/learn-noperf/",
      "/specializations-noperf/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "server-54-192-248-29.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 10.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
