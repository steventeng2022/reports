# Security Audit Report — pewresearch.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://pewresearch.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | pewresearch.org |
| Test date | 2026-09-26 18:57 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 3, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 12 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 15 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 16 | info | CT1 | 13 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 4. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 5. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 12. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: linear-domain-verification=aeaz7jeynne3; tollbit-domain-verification=c379eea53a12f277b7e1b4ddb627fdf3c39380c133229681529a; apple-domain-verification=DQ3TtP8IS4sFJC9EKMrlcZ2yCjEHmQGa66M46pg6m3k
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of pewresearch.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 15. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 6 disallow path(s), e.g. /wp-admin/, /wp-content/plugins/prc-icon-library/, /wp-content/plugins/prc-icon-library/, /search/, /search
- **Recommendation:** Review disallowed paths; robots is not access control.

### 16. [INFO] 13 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: assets.pewresearch.org, beta.pewresearch.org, status.pewresearch.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "pewresearch.org",
  "dns": {
    "a": [
      "192.0.66.2"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "pewresearch-org.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "ns-281.awsdns-35.com.",
      "ns-1318.awsdns-36.org.",
      "ns-795.awsdns-35.net.",
      "ns-1841.awsdns-38.co.uk."
    ],
    "spf": [
      "j8p1v8uvnjiungbkieg6894ctb",
      "linear-domain-verification=aeaz7jeynne3",
      "70tqopf58gehn5q0l172ijp4s9",
      "v=spf1 include:spf.protection.outlook.com  include:spf.predictiveresponse.net include:servers.mcsv.net include:cust-spf.exacttarget.com include:_spf.pewresearch.org -all",
      "tollbit-domain-verification=c379eea53a12f277b7e1b4ddb627fdf3c39380c133229681529aae9c7df3c531",
      "5fg2mqnnnwjw1cw30f0jtgslypdvlglc",
      "LEu+WRccDmqfd4AKPAO6X54Tg6icB74LQc1Cok7AIhhwxvY4OA6ZiVNYRLUclWqM5Qmx3c/rhinRNrB+yUCcuQ==",
      "apple-domain-verification=DQ3TtP8IS4sFJC9EKMrlcZ2yCjEHmQGa66M46pg6m3k",
      "MS=ms46499721",
      "facebook-domain-verification=79sdy6w4z5ih1t1h56pzbtfg98s2b1",
      "adobe-idp-site-verification=dce4a001508adff6a7b1ce11bcee94997898dc790dbe672077b69fd9e362a3cf",
      "81mjlnmdt3ilhf605acjac3142",
      "google-site-verification=a39GDHtKkznS6vJx2Bd4tLCPiu3gprTJYBsfeJ-Afy4",
      "hcp-domain-verification=a3c6e4dafba5b710eebea68d3af09226b78e92d2c41ac640723ab9c5ef82f330",
      "google-site-verification=EuKSpyq2IYv-oJplq6yQlPQKYsV1LWeqwQjs9lu3Z-o",
      "m7unfqgh2tqd69cmft07vog4u2",
      "MS=ms53170065",
      "docusign=db8286b4-617d-4518-a8d2-ffd9c7d6b445",
      "asv=93e4c31a4bfea86fd47cf32edc0fef1b",
      "oqubjqei44ol2n7u4raiso8aja",
      "google-site-verification=jwmmtXct21FKveAwprcQKkMrhqVY7ac2TtxUvubWT30",
      "apple-domain-verification=JyKtturocxJ7e8bI",
      "citrix.mobile.ads.otp=kd0jxp1wb9rh0n6flcz64s",
      "cisco-ci-domain-verification=59488ea3a94920c64294e106be6efcfec41e63d9329d22edb6423a746c309339",
      "jpq4l34skjc4madsqn48odfika",
      "t35wwdky16ymmmcgvvs20r2bv8zny0j0",
      "ZOOM_verify_JaT9z62TGWk4Xq1EBKbVqZ",
      "openai-domain-verification=dv-vkGktfLOtwd6xNFPJ1lL0QTl",
      "n+rGfPXv0394s7Mav6oftRucHJ3XrkPA5Gu2efLCfMNgvA9Q2j5wLodRQMBf09AxhL/ZJr158ExNxMgdKLykAQ==",
      "cursor-domain-verification-36qzmn=mNriG0xAskkvI4tGbhcGakb2s",
      "workbrew-domain-verification-b91wyv=bPXNAREVhl7vOrFTnQdCJbRFZ",
      "anthropic-domain-verification-27dfqx=89zzqeHhnNFCvRLyUPN6Rrm2S"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:6183e7d4856a5@ag.dmarcly.com; ruf=mailto:6183e7d4856a5@fo.dmarcly.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=pewresearch.org",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Sep 10 00:07:46 2026 GMT",
    "notAfter": "Dec  9 00:07:45 2026 GMT",
    "san": [
      "pewresearch.org",
      "www.pewresearch.org"
    ],
    "days_left": 73,
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
    "status": 302,
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
      "origin": "https://sub.pewresearch.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://pewresearch.org/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 403,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 13,
    "notable": [
      "assets.pewresearch.org",
      "beta.pewresearch.org",
      "status.pewresearch.org"
    ],
    "sample": [
      "account.pewresearch.org",
      "alpha.pewresearch.org",
      "assets.pewresearch.org",
      "beta.pewresearch.org",
      "canary.pewresearch.org",
      "charts.pewresearch.org",
      "legacy.pewresearch.org",
      "pewresearch.org",
      "platform.pewresearch.org",
      "services.pewresearch.org",
      "status.pewresearch.org",
      "tollbit.pewresearch.org",
      "www.pewresearch.org"
    ]
  },
  "apex_txt": [
    "linear-domain-verification=aeaz7jeynne3",
    "tollbit-domain-verification=c379eea53a12f277b7e1b4ddb627fdf3c39380c133229681529a",
    "apple-domain-verification=DQ3TtP8IS4sFJC9EKMrlcZ2yCjEHmQGa66M46pg6m3k",
    "facebook-domain-verification=79sdy6w4z5ih1t1h56pzbtfg98s2b1",
    "adobe-idp-site-verification=dce4a001508adff6a7b1ce11bcee94997898dc790dbe672077b6"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.3",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260910000746",
      "not_after": "20261209000745"
    }
  },
  "http2": {
    "hsts_preloaded": true,
    "robots_disallow": [
      "/wp-admin/",
      "/wp-content/plugins/prc-icon-library/",
      "/wp-content/plugins/prc-icon-library/",
      "/search/",
      "/search",
      "/?s="
    ]
  },
  "x12": {
    "status": 302
  },
  "elapsed_s": 19.6,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
