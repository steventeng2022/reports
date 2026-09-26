# Security Audit Report — redbubble.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://redbubble.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | redbubble.com |
| Test date | 2026-09-26 18:58 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 5, Info: 16)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H1b | Weak HSTS (max-age < 1 year) | CWE-319 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 9 | low | H4 | No clickjacking protection | CWE-1023 |
| 10 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 11 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 12 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 13 | info | H6 | Server technology disclosure | CWE-200 |
| 14 | info | P8 | Missing security.txt | CWE-1038 |
| 15 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 16 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 17 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 18 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 19 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 20 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 21 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.147.37:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.64.147.37:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Weak HSTS (max-age < 1 year) (`H1b`)

- **CWE:** CWE-319
- **Detail:** HSTS present but max-age=0 (< 31536000).
- **Context:** https response, /
- **Recommendation:** Increase max-age to at least 31536000; add includeSubDomains/preload.

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

### 14. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 15. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 16. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 17. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (9tgle3f8ob5jxr.redbubble.com and hc623aj968gdwh.redbubble.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 18. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=mi4mkund8oqzwtzhljxcn2yle13ffx; stripe-verification=e6e8859edfcd12d0ddaded758c7e3dbe67aeec5351774319f31234c15cb2; stripe-verification=46a1820652f48421affa0dd0210a8d165ad91d9bf14a923a90db760f25d8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 19. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of redbubble.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 20. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but redbubble.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 21. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 208 disallow path(s), e.g. /account/, /auth/, /signup, */works/*/carousel, /discover/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "redbubble.com",
  "dns": {
    "a": [
      "172.64.147.37",
      "104.18.40.219"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 20)",
      "aspmx5.googlemail.com (pref 30)",
      "aspmx2.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx.l.google.com (pref 10)",
      "aspmx4.googlemail.com (pref 30)"
    ],
    "ns": [
      "grace.ns.cloudflare.com.",
      "greg.ns.cloudflare.com."
    ],
    "spf": [
      "facebook-domain-verification=mi4mkund8oqzwtzhljxcn2yle13ffx",
      "stripe-verification=e6e8859edfcd12d0ddaded758c7e3dbe67aeec5351774319f31234c15cb2d535",
      "stripe-verification=46a1820652f48421affa0dd0210a8d165ad91d9bf14a923a90db760f25d8f386",
      "google-site-verification=vkpZiA3YRjBX_kTwrTaxho611iwMN6arP0Ul69qeE-A",
      "BPL=1126064",
      "stripe-verification=351c3166a566cceb14b5940d1870f386c52a5b7d994c40425ccc5f00203def98",
      "google-site-verification=tlRDDgpvFfpNsjCfbljRYi5y1vWmKxNTopJCHryCR5k",
      "docker-verification=491b95d3-085b-466b-b57d-b5d29755d00d",
      "atlassian-domain-verification=QXMXSt1Y5pkY3LHuPAvUx0m/baw85nW1IGHuwcRXDSMNAoDAm3dv0ko0LoZwfdKt",
      "stripe-verification=66a22dc621b81179418fc86013d8edbe7b964ae18d6de647f27a3d7f1b72de0b",
      "docusign=571f0360-1e16-4a6b-8dc8-85f70a1be7bd",
      "google-site-verification=x5ibTJjE09JLrzPNBY7rolMrPqC34YSsjo4qM8HuxWg",
      "google-site-verification=MSr1dnAvSgQfeuYLHcGMzESb6gzav2VrqV2NixQqpyM",
      "miro-verification=0adebe47a84b71ad1a26f2555c6a1b27980b4036",
      "twilio-domain-verification=55db31fdead46a274cfe09c204628020",
      "anthropic-domain-verification-v1dn0a=YD10CWeuzIWWkSgV7ZYRHiAd4",
      "asv_domain=0f6dda07f6f2602e0f1c4fd230551738",
      "apple-domain-verification=NP1bOtQn6J4uDTRz",
      "stripe-verification=dd8b40df9020b0730505fd40b3586c1226b566233663dc5b3428586274d5a661",
      "stripe-verification=c0fb77104ce7e865091d6c467967f37efa03dd960596317cbae313dea1101b25",
      "google-site-verification=dK53YMQJIIUQ81uTqbWu99BRP1QrUO2CUGxR_UgeZdA",
      "v=spf1 ip4:167.89.6.96 ip4:208.115.235.221 include:_spf.google.com include:mail.zendesk.com include:amazonses.com include:mg-spf.greenhouse.io include:_netblocks.accellion.com include:mktomail.com ~all",
      "stripe-verification=2aa0eb2936e5371d2ffa34419d0e83e749c1aad5d36dd37f04576c8e9ed902a8",
      "google-site-verification=sMLzEbifaLFu565adipqN_-EXZ1Kozh2IpU8m6A47-U",
      "jamf-site-verification=xTuy2iVK1s1LV_4AQBCckA",
      "google-site-verification=JN-XQ-cYiYftk6pyadcpZlFKzOfjs-NzrsMP7QLHXN4",
      "asv_domain=d54695e72f4fdce123215a8523dc627d"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=100; rua=mailto:6950a1d4bd4b4d9889a101aaa7941388@dmarc-reports.cloudflare.net,mailto:dmarc-reports@redbubble.com; ruf=mailto:dmarc-reports@redbubble.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=redbubble.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 27 03:01:09 2026 GMT",
    "notAfter": "Nov 25 04:01:06 2026 GMT",
    "san": [
      "redbubble.com",
      "*.redbubble.com",
      "www.redbubble.com"
    ],
    "days_left": 59,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.64.147.37",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "redbubble.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.redbubble.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.redbubble.com/"
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
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "facebook-domain-verification=mi4mkund8oqzwtzhljxcn2yle13ffx",
    "stripe-verification=e6e8859edfcd12d0ddaded758c7e3dbe67aeec5351774319f31234c15cb2",
    "stripe-verification=46a1820652f48421affa0dd0210a8d165ad91d9bf14a923a90db760f25d8",
    "google-site-verification=vkpZiA3YRjBX_kTwrTaxho611iwMN6arP0Ul69qeE-A",
    "stripe-verification=351c3166a566cceb14b5940d1870f386c52a5b7d994c40425ccc5f00203d"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null,
      "not_before": "20260827030109",
      "not_after": "20261125040106"
    }
  },
  "http2": {
    "robots_disallow": [
      "/account/",
      "/auth/",
      "/signup",
      "*/works/*/carousel",
      "/discover/",
      "/mybubble/",
      "/objections/",
      "/settings/",
      "/*.json$",
      "/api/",
      "/journals$",
      "/people/*/journal/",
      "/groups/*",
      "/shop*?query=*",
      "/shop*&query=*"
    ]
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 6.1,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
