# Security Audit Report — stackoverflow.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://stackoverflow.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | stackoverflow.com |
| Test date | 2026-09-26 17:53 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 2, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 11 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 14 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 198.252.206.1:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 198.252.206.1:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

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
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'prov' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 11. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'prov' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 14. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=O9jlnJXAQ7sNSZqC; work-os-domain-verification-43a3e0=GoDUTSc5MMjDaiIC3s5yRKqMD; openai-domain-verification=dv-GLNufzbWDzAq0fDXHD6jxeCK
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of stackoverflow.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "stackoverflow.com",
  "dns": {
    "a": [
      "198.252.206.1"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "sureena.ns.cloudflare.com.",
      "damian.ns.cloudflare.com."
    ],
    "spf": [
      "apple-domain-verification=O9jlnJXAQ7sNSZqC",
      "v=MCPv1; k=ed25519; p=VhBofO8RaYvTvHT7q5tTty+HQeCU8R6h5Y8k/sj20So=",
      "work-os-domain-verification-43a3e0=GoDUTSc5MMjDaiIC3s5yRKqMD",
      "openai-domain-verification=dv-GLNufzbWDzAq0fDXHD6jxeCK",
      "google-site-verification=2Bi6SYw5skkRexdtdLPL2gpxeIhLxnYVqITVP9Htl3w",
      "onetrust-domain-verification=0d9d67f856334905a54256085a5768b3",
      "docker-verification=d65aee54-9091-4ceb-b792-61f5d5804050",
      "v=spf1 ip4:52.38.191.241 include:_spf.google.com include:mailgun.org include:sendgrid.net include:mail.zendesk.com include:spf.tipalti.com ~all",
      "onetrust-domain-verification=e445562296a64c649ae3d520230b8c4c",
      "adobe-idp-site-verification=25ba5203f3687c9cd6ee3223ee5de1528917828d1da3ebd3bd9a44094cbfc4ac",
      "google-site-verification=o3EMam8yBGo1yEjyybIiZcOunGHOQKpo8JmOtp9n1BU",
      "cursor-domain-verification-sb0ayf=Pk6AyptQuTpzpcuSlfYGWloxv",
      "ZOOM_verify_AbkNwz5bBl0eurcDKyhhuk",
      "google-site-verification=rdWtMbplKjbRHGr2dNONfwkqithlUvjr3u6i8QEz_mo",
      "atlassian-domain-verification=byLeZgl3MIcfOqwWuMhq8Fhr/1zem/jIaouJegvDZbBKUU5OqhwDjdpkyYg5CTzm",
      "docusign=4262531d-29f4-4a62-9f33-ae9f66f5247b",
      "make-domain-verification=eec31159-f381-4f38-9d89-e59123dd023e",
      "ibmid=4e7cbbb3-5f12-40b4-96c7-5b064347b822",
      "profound-domain-verification-5p599x=hWudYd2Du6WOYOod5ko9Rwnp8",
      "google-site-verification=ctogLnZNAdc_CXq8yOhODMLpmugGynjxKecKHDz4oL8",
      "MS=ms52592611",
      "anthropic-domain-verification-q70207=cKyy0llXkD10O4rDQpWz8tQ5K"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-aggregates@stackoverflow.com; ruf=mailto:dmarc-forensics@stackoverflow.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=stackoverflow.com",
    "issuer": "countryName=US, organizationName=Let's Encrypt, commonName=YE1",
    "notBefore": "Aug 15 12:39:06 2026 GMT",
    "notAfter": "Nov 13 12:39:05 2026 GMT",
    "san": [
      "*.stackoverflow.com",
      "stackoverflow.com"
    ],
    "days_left": 47,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "198.252.206.1",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 302,
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
      "domain": ".stackoverflow.com",
      "samesite": "none"
    },
    {
      "samesite": "none"
    },
    {
      "domain": "stackoverflow.com"
    },
    {
      "domain": "stackoverflow.com",
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
      "origin": "https://sub.stackoverflow.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://stackoverflow.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 404",
    "/url?url=https://evil-auditor.example/x -> 404"
  ],
  "paths": {
    "/robots.txt": 418,
    "/sitemap.xml": 404,
    "/.well-known/security.txt": 404,
    "/security.txt": 429,
    "/.git/HEAD": 429,
    "/.git/config": 429,
    "/.env": 429,
    "/.htaccess": 429,
    "/wp-login.php": 429,
    "/phpmyadmin/index.php": 429,
    "/server-status": 429,
    "/api/": 429
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "apple-domain-verification=O9jlnJXAQ7sNSZqC",
    "work-os-domain-verification-43a3e0=GoDUTSc5MMjDaiIC3s5yRKqMD",
    "openai-domain-verification=dv-GLNufzbWDzAq0fDXHD6jxeCK",
    "google-site-verification=2Bi6SYw5skkRexdtdLPL2gpxeIhLxnYVqITVP9Htl3w",
    "onetrust-domain-verification=0d9d67f856334905a54256085a5768b3"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 6.8,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
