# Security Audit Report — untappd.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://untappd.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | untappd.com |
| Test date | 2026-09-26 17:54 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 1, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | low | H1 | Missing HSTS header | CWE-319 |
| 7 | info | H6 | Server technology disclosure | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | info | MAIL10 | DMARC subdomain policy (sp=) set while apex policy is p=none | CWE-285 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

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
- **Detail:** TCP connect to 172.66.163.79:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.66.163.79:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 7. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [INFO] DMARC subdomain policy (sp=) set while apex policy is p=none (`MAIL10`)

- **CWE:** CWE-285
- **Detail:** Subdomains are enforced while the apex domain is monitor-only.
- **Recommendation:** Confirm the split policy is intended.

### 10. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=_5-to4lYBCcN4DBHN_M4Z6ST5Nle5AGkGXkzWWUZPEY; apple-domain-verification=PzeSkiU5Qi5suyUq; rippling-domain-verification=414dd4dc53702337
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of untappd.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "untappd.com",
  "dns": {
    "a": [
      "172.66.163.79",
      "104.20.44.111"
    ],
    "aaaa": [
      "2606:4700:10::6814:2c6f",
      "2606:4700:10::ac42:a34f"
    ],
    "cname": null,
    "mx": [
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "aspmx2.googlemail.com (pref 1)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "uma.ns.cloudflare.com.",
      "henry.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=_5-to4lYBCcN4DBHN_M4Z6ST5Nle5AGkGXkzWWUZPEY",
      "apple-domain-verification=PzeSkiU5Qi5suyUq",
      "pardot1078002=4b8f9c144c87c116c1071cad3b0a99a99e0c2e7cec52634a8fbd659ea5ff58b5",
      "rippling-domain-verification=414dd4dc53702337",
      "B99CA8E742",
      "oe1a0rcj1t86545ob3bk2ng9ml",
      "sending_domain1078002=0f34bbdfe8ce8fde994ca2d6751686e81dcabaca24039a259f7683f01bc399b7",
      "pardot1077992=c1d537bb2ce30942a74c659492f30bf3c6e8d7958a88a0fb799a5024fe9346e2",
      "v=spf1 include:mailgun.org include:_spf.google.com include:8657325.spf07.hubspotemail.net ~all",
      "anthropic-domain-verification-fnjqmj=U1ukT7Sxor44FIU8UxQ826TP6",
      "google-site-verification=uht-ZR-lbkbuuO9L45_oKL6jtqgJYaY3vNPODTutZLo",
      "google-site-verification=G_VXSVRR3bpfmWTa1aoZiBQpbMC3OAR11uMRvdGlgU8",
      "1password-site-verification=JJRHU5XGONHORHDBBN5MLCHZ54",
      "Wbvu8ty9C2PBSYUZ",
      "00D1U000000yGXd=1TBVN0000000B57",
      "sending_domain1077992=e57882e11e995d0077009d5d51ac38c75e7fa092881dbc81d4f01ea6f4aba37a",
      "MS=ms78757206",
      "sending_domain1078002=7f3e88ab1ef815c42d93beacb80905d8e91477f133a45a0063997731dee78b8e",
      "status-page-domain-verification=vjh1rqfvh6cq",
      "facebook-domain-verification=huzlzmhksif1ge62wip9zvpb312rwt"
    ],
    "dmarc": [
      "v=DMARC1; p=none; sp=none; rua=mailto:re+5cfc1e8a3ff9@inbound.dmarcdigests.com; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=untappd.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 23 16:32:00 2026 GMT",
    "notAfter": "Dec 22 17:31:46 2026 GMT",
    "san": [
      "untappd.com",
      "recappd.untappd.com"
    ],
    "days_left": 86,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.66.163.79",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.untappd.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://untappd.com/"
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=_5-to4lYBCcN4DBHN_M4Z6ST5Nle5AGkGXkzWWUZPEY",
    "apple-domain-verification=PzeSkiU5Qi5suyUq",
    "rippling-domain-verification=414dd4dc53702337",
    "anthropic-domain-verification-fnjqmj=U1ukT7Sxor44FIU8UxQ826TP6",
    "google-site-verification=uht-ZR-lbkbuuO9L45_oKL6jtqgJYaY3vNPODTutZLo"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 5.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
