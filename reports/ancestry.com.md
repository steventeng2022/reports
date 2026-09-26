# Security Audit Report — ancestry.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://ancestry.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | ancestry.com |
| Test date | 2026-09-26 18:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **17** (High: 0, Medium: 0, Low: 3, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | CT1 | 50 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 17 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.0.50:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.0.50:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 13. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 14. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=IhnfKIdiEJloKVWygvyOX-OXEqYvnNW3a36zIqvI7s8; atlassian-domain-verification=w3rz7z0y8xvagZiMhu44qJQUXTISEt1vlB5JLH44YwEGaJu1oJ; apple-domain-verification=H7sVwFfpXAjrg5cjwMiD04RqrUPw-yk8nws1ZQLX0OE
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of ancestry.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] 50 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: careers.ancestry.com, media.nbc.ancestry.com, vpn.ancestry.com, vpn.l1-pci.ancestry.com, wiki.ancestry.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 17. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: vpn.l1-pci.ancestry.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "ancestry.com",
  "dns": {
    "a": [
      "104.18.0.50",
      "104.18.1.50"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-002f8e01.gslb.pphosted.com (pref 10)",
      "mxb-002f8e01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-415.awsdns-51.com.",
      "ns-1996.awsdns-57.co.uk.",
      "ns-1429.awsdns-50.org.",
      "ns-737.awsdns-28.net."
    ],
    "spf": [
      "v=spf1 ip4:148.163.143.216 ip4:148.163.146.21 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/14 ip4:104.47.0.0/17 include:spfa1.ancestry.com include:spfa2.ancestry.com include:spfa3.ancestry.com include:spfa4.ancestry.com -all",
      "google-site-verification=IhnfKIdiEJloKVWygvyOX-OXEqYvnNW3a36zIqvI7s8",
      "atlassian-domain-verification=w3rz7z0y8xvagZiMhu44qJQUXTISEt1vlB5JLH44YwEGaJu1oJQweoaSPwzZwRDa",
      "apple-domain-verification=H7sVwFfpXAjrg5cjwMiD04RqrUPw-yk8nws1ZQLX0OE",
      "facebook-domain-verification=jyq4fxqp7asgs8a4uos7lv175smrw0",
      "Validity-Domain-Verification=ahh6a--ajdta71&akhdggS76SHKEUGkd",
      "jamf-site-verification=bKnm7mL8x9P7tTbBibqUnw",
      "ZOOM_verify_pUR3qD3KTUmjq_VepUKiNQ",
      "bw=V0nvzHI6aiJ+zDVV34NJIpjumOt94AbC2UVMYwNiV94K",
      "google-site-verification=7cbq4pQ7-mroQaqnQzd_NWlY6FnXHB5jXvaOBv9PvKE",
      "google-site-verification=-AzknqzfMwXyfxPvw1tFMWHQop_hZggmsBKQaxTtJ_Y",
      "workplace-domain-verification=8M7WF3aEGWMl1TYqg8a0WPoeU5nGzn",
      "ca3-5bb298b2372e4cd59aadef5eb8cdc5e2",
      "docusign=60713c36-f380-42c6-bc97-c0a2f7bb0288",
      "_globalsign-domain-verification=kXS4kgWQ9hbGjWDmISoLGlXLaOx8-EdTig6ux0WZ2x",
      "LfWMRqtDo2P6V4y6XUr/J+AhoqnLN10va/BBwWlFW2swSuUuJIy0H7InunZ5t1x11GbBXDUuPLFrNb9i6xtZJg==",
      "uber-domain-verification=bae1e0bc-36c1-4ddc-82cb-9df008237fbc",
      "apple-domain-verification=aRPuENZQPpkMdwYD",
      "1h8615NzQEFqgIY5PxudWlC6duCLMQfBMw+fv5fm3NA7wz2Sl7G2nXilA3HMfQdoU3YUwadBga5qJlKymzJUNg==",
      "google-site-verification=xzRJaI_84GE45yCfP1XGewPRGYGYtoKN2taBi0W1tvw",
      "cisco-ci-domain-verification=7e9f05a57120466147f6696af195ece74794ffcb865912d4841a6cfae29682fa",
      "es-domain-verification=572c7e4d-8a43-477d-a7c1-6ec480ca835e",
      "dtm-domain-verification=SC0ne4rDlm2aeoiu8c76XQPK2EThQ20Dlu700pGs87k",
      "atlassian-sending-domain-verification=84372097-817a-4816-8e7f-2c3b32ac6895",
      "ca3-8ace22ca65d242f287d5417e8f1ccd9b",
      "mixpanel-domain-verify=030ac2cc-dd22-46ab-abd2-ffe6a6e01dde",
      "adobe-idp-site-verification=1222e2336a518f7a8664dbdc6462f85d80c35afb4f46542ba5a329749a24a22a",
      "wiz-domain-verification=6f1d3544773aad264133bcc557338a5f84b607290582a33eb48cc6e768f48b95"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc_rua@emaildefense.proofpoint.com,mailto:dmarc_agg@dmarc.everest.email; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:dmarc_fr@dmarc.everest.email; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=ancestry.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep  2 04:27:00 2026 GMT",
    "notAfter": "Dec  1 05:26:54 2026 GMT",
    "san": [
      "ancestry.com",
      "*.ancestry.com",
      "*.ajax.ancestry.com"
    ],
    "days_left": 65,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.0.50",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
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
      "domain": "ancestry.com",
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
      "origin": "https://sub.ancestry.com",
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
    "source": "certspotter",
    "count": 50,
    "notable": [
      "careers.ancestry.com",
      "media.nbc.ancestry.com",
      "vpn.ancestry.com",
      "vpn.l1-pci.ancestry.com",
      "wiki.ancestry.com"
    ],
    "sample": [
      "ajax.ancestry.com",
      "ancboards.msn.ancestry.com",
      "ancestry.com",
      "aws-fs.ancestry.com",
      "awt.msn.ancestry.com",
      "blogs.ancestry.com",
      "c.ancestry.com",
      "careers.ancestry.com",
      "corporate.ancestry.com",
      "dam.ancestry.com",
      "data.gale.ancestry.com",
      "dnadeliveryservice-integration.ancestry.com",
      "dnadeliveryservice-validation.ancestry.com",
      "dnadeliveryservice.ancestry.com",
      "e0lrwkkp.emails.ancestry.com",
      "fs-ts.ancestry.com",
      "fs.ancestry.com",
      "fzf6qelt.emails.ancestry.com",
      "genomics.ancestry.com",
      "github.ancestry.com"
    ],
    "dangling": [
      "vpn.l1-pci.ancestry.com"
    ]
  },
  "apex_txt": [
    "google-site-verification=IhnfKIdiEJloKVWygvyOX-OXEqYvnNW3a36zIqvI7s8",
    "atlassian-domain-verification=w3rz7z0y8xvagZiMhu44qJQUXTISEt1vlB5JLH44YwEGaJu1oJ",
    "apple-domain-verification=H7sVwFfpXAjrg5cjwMiD04RqrUPw-yk8nws1ZQLX0OE",
    "facebook-domain-verification=jyq4fxqp7asgs8a4uos7lv175smrw0",
    "Validity-Domain-Verification=ahh6a--ajdta71&akhdggS76SHKEUGkd"
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
      "not_before": "20260902042700",
      "not_after": "20261201052654"
    }
  },
  "http2": {
    "hsts_preloaded": true
  },
  "x12": {
    "status": 403
  },
  "elapsed_s": 5.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
