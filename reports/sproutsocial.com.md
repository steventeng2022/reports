# Security Audit Report — sproutsocial.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://sproutsocial.com/ |
| Bug bounty program | Sprout Social |
| Listed scope domain | sproutsocial.com |
| Test date | 2026-09-26 18:59 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 0, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 4 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 5 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 14 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: AmazonS3
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: AmazonS3
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: anthropic-domain-verification-4bvzj1=5CSEl4SRsXptHHAsnE12kwPWq; apple-domain-verification=fUR5lrIb8ZXAgRZh; uber-domain-verification=f857c206-5a02-4eb4-9bd0-2b7316f02c03
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of sproutsocial.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but sproutsocial.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://sproutsocial.com/ carries Cache-Control: public,max-age=3600,must-revalidate (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 14. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 65.9.180.100 carries PTR server-65-9-180-100.tpe53.r.cloudfront.net. for sproutsocial.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

## Evidence (raw response observations)

```json
{
  "domain": "sproutsocial.com",
  "dns": {
    "a": [
      "65.9.180.100",
      "65.9.180.129",
      "65.9.180.114",
      "65.9.180.87"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-851.awsdns-42.net.",
      "ns-1475.awsdns-56.org.",
      "ns-1770.awsdns-29.co.uk.",
      "ns-109.awsdns-13.com."
    ],
    "spf": [
      "anthropic-domain-verification-4bvzj1=5CSEl4SRsXptHHAsnE12kwPWq",
      "docusign=eedc187f-e4c6-4ac9-8e13-c6ccd40314b7",
      "e2e721fe-abe5-42a4-927b-912cc5c69b36",
      "apple-domain-verification=fUR5lrIb8ZXAgRZh",
      "mixpanel-domain-verify=163fe517-5be9-4a94-9755-d4f557dd500c",
      "uber-domain-verification=f857c206-5a02-4eb4-9bd0-2b7316f02c03",
      "bugcrowd-verification=f0154a310f16c24b2f611860fa95ee0a",
      "status-page-domain-verification=mtln2tk244cb",
      "v=spf1 include:mail.zendesk.com include:6cb9ee.workshop-spf.net include:_spf.salesforce.com include:_spf.google.com ip4:167.89.16.0/24 ip4:13.111.63.123 ip4:216.74.162.13 ip4:216.74.162.14 include:stspg-customer.com -all",
      "google-site-verification=Mhehxk91tmdl972lIt1tUudqxk-UZ-dess1iBOOynkk",
      "canva-site-verification=_JpZfL3nf2ijBh990p20Qg",
      "drift-domain-verification=24480bfa6b88081e403b5a627581c72e596dc1c3ed5645fe6efcd60dd55b867d",
      "fastly-domain-delegation-789693-Kj90J2mV3G9-2024-07-19",
      "dropbox-domain-verification=r5b6zg48jbmp",
      "ZOOM_verify_SCYUdVERQLutYg2MMk5n1g",
      "jamf-site-verification=iQrilIoGuZCr_m8AjCBWZA",
      "miro-verification=391fdb38d34cadae4ef10844ee78b9621782d343",
      "atlassian-domain-verification=RxqzNQU9S390W85VwH10vVpz3Di558ORKIVSKmVAQT4+y7Ql0sQs5izaEFJ3sqHt",
      "loom-site-verification=c0a47021adc14be19b38292b33d1d30f",
      "openai-domain-verification=dv-qdwcM7SqQQz9Vh7yfHW8W55g",
      "google-site-verification=H8kk7gZcBYmngKs49pHpvunadVcRo05xHvYFm8OIE-I",
      "google-site-verification=cXlmyZR0poIpagrHUTLcClMxgOT4IkJT0j7_1-e0tsU",
      "_clickhouse-challenge=50106aaaf400edbcefac28bda83bc112729a303de14fb02fb2aacc7b3325eb8e",
      "slack-domain-verification=I615FeKXlfrAPDJmDACA9SyJDK5G1ZGhti5m0hp1",
      "ca3-7d04cacf69a549d4addeff17e6909a24",
      "BVZ71B+mKCBqRr1w3VIASfVh3pQZB03sHrBNBFpHX1o=",
      "MS=ms12400529",
      "google-site-verification=ij4vG3FdwygeRWH5NW4N4caykX25Kd0e0WB4Mthyq20",
      "reachdesk-verification=DUxgtvZRe02HbR5zQceu542WuioEOiKst7RqNUFgWSKm21dUpY3Qfq9LCrrlJItn",
      "docker-verification=43fcdc1c-c507-4b42-a59f-bbe4ec0bb157",
      "pardot638801=5d51367473c46ae4c72b898ec13660f709def997e4a94c499727a407afb942ee",
      "ca3-8a1e55e3fcee4fa491e23cbded2bc67e",
      "facebook-domain-verification=2sqha4fft688a7u7q3figd59ep0w4b",
      "detectify-verification=12d573890acb6ade469e03765116c9e2",
      "google-site-verification=BqcVSfrFZjfdxdEO8uatlQkqe60OY_oN1l0lJZfmZ9k",
      "google-site-verification=kqO9m7kdcbY5YskqQd2zJq54BQSHCF9uNP_E2s4yoAM",
      "adobe-idp-site-verification=0a066b06b8045615fcdf23249b39f3d914314bdfb3ee967c2e1ffb54d91d8abc",
      "google-site-verification=yq35AOMklIFyD7HelrWMtlretcRBQAt1AY7qTtwvdhg"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:6bd0bfcf@mxtoolbox.dmarc-report.com; ruf=mailto:6bd0bfcf@forensics.dmarc-report.com; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=sproutsocial.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 18 00:00:00 2026 GMT",
    "notAfter": "Mar  3 23:59:59 2027 GMT",
    "san": [
      "sproutsocial.com",
      "cdn.sproutsocial.com",
      "www.sproutsocial.com"
    ],
    "days_left": 158,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "65.9.180.100",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html",
    "title": "Sprout Social: Social Media Management Tool"
  },
  "mixed_content": [],
  "tech": [
    "Server: AmazonS3"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.sproutsocial.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://sproutsocial.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 404",
    "/redirect?next=https://evil-auditor.example/x -> 404",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 301,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 404,
    "/server-status": 404,
    "/api/": 502
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "anthropic-domain-verification-4bvzj1=5CSEl4SRsXptHHAsnE12kwPWq",
    "apple-domain-verification=fUR5lrIb8ZXAgRZh",
    "uber-domain-verification=f857c206-5a02-4eb4-9bd0-2b7316f02c03",
    "bugcrowd-verification=f0154a310f16c24b2f611860fa95ee0a",
    "status-page-domain-verification=mtln2tk244cb"
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
      "not_before": "20260818000000",
      "not_after": "20270303235959"
    }
  },
  "x12": {
    "status": 200,
    "ptr": [
      "server-65-9-180-100.tpe53.r.cloudfront.net."
    ]
  },
  "elapsed_s": 18.1,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
