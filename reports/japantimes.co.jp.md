# Security Audit Report — japantimes.co.jp

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://japantimes.co.jp/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | japantimes.co.jp |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 2, Info: 11)

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
| 9 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
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
- **Detail:** TCP connect to 172.67.68.125:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.67.68.125:8443 succeeded (state-only check, no payload sent).
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

### 9. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=r8gah1byp39t4nahiwxnot4u53yqkq; google-site-verification=JNsW-oJ2eTFMcjLBuoEFm8uIDiIFV4HLfcn1qW2RVc4; facebook-domain-verification=5pcy0pvd7m24zu1w4ubtyeknqyfuje
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of japantimes.co.jp has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "japantimes.co.jp",
  "dns": {
    "a": [
      "172.67.68.125",
      "104.26.2.3",
      "104.26.3.3"
    ],
    "aaaa": [
      "2606:4700:20::ac43:447d",
      "2606:4700:20::681a:203",
      "2606:4700:20::681a:303"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 30)",
      "aspmx5.googlemail.com (pref 30)",
      "alt1.aspmx.l.google.com (pref 20)",
      "aspmx4.googlemail.com (pref 30)",
      "aspmx3.googlemail.com (pref 30)",
      "aspmx.l.google.com (pref 10)",
      "alt2.aspmx.l.google.com (pref 20)"
    ],
    "ns": [
      "jobs.ns.cloudflare.com.",
      "elly.ns.cloudflare.com."
    ],
    "spf": [
      "facebook-domain-verification=r8gah1byp39t4nahiwxnot4u53yqkq",
      "google-site-verification=JNsW-oJ2eTFMcjLBuoEFm8uIDiIFV4HLfcn1qW2RVc4",
      "v=spf1  +ip4:52.199.201.172 +ip4:54.65.41.140 +ip4:50.56.113.200 +ip4:52.192.48.178 +ip4:52.198.58.73 +ip4:54.92.1.143 +ip4:153.127.53.24 +ip4:54.150.202.78 +ip4:54.248.16.180 +ip4:54.238.200.210 +ip4:54.178.143.1 +ip4:210.158.219.147 include:_spf.google.",
      "com include:spf.japan",
      "times.co.jp ~all",
      "MS=ms30674565",
      "facebook-domain-verification=5pcy0pvd7m24zu1w4ubtyeknqyfuje",
      "google-site-verification=1215qpicd1-TYtNffu-BXSUiKYlcsFdF-Spoth0OrPo",
      "amazonses:qy3myq3Na6f6laO4ymQ6wTBbEeNbYwzl8OEZ/AQ7KvE=",
      "amazonses:Um3JNqgFvpbJ0RMzxm6MUYFQGggi7E1t8AMQnI9s2rg=",
      "google-site-verification=OVsEXNIYtD3q7DB4ONtD6aIgxQJxn1_iCfDUwvNUfKc",
      "seculio-domain-verification-code=cced926da9a967819c54899c6b1c1e9b767853dbb371fd25ceccef303a2f4a48",
      "amazonses:89wQUYQh+QnyoMv88QVXR9JAEsUpPhSpuVbRMSzQorc=",
      "amazonses:H0epEk/2RCbxjGx9LYL76J+SVsW3rElYTcoRKLqpEkk=",
      "google-site-verification=1FA9Fq43BnO-e1rRm5_NUzT0udJpr1FYuEkyMxgIhQ4"
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
    "subject": "commonName=japantimes.co.jp",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug  1 00:27:41 2026 GMT",
    "notAfter": "Oct 30 01:27:37 2026 GMT",
    "san": [
      "japantimes.co.jp",
      "*.japantimes.co.jp"
    ],
    "days_left": 33,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.67.68.125",
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
      "origin": "https://sub.japantimes.co.jp",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://japantimes.co.jp/"
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
    "facebook-domain-verification=r8gah1byp39t4nahiwxnot4u53yqkq",
    "google-site-verification=JNsW-oJ2eTFMcjLBuoEFm8uIDiIFV4HLfcn1qW2RVc4",
    "facebook-domain-verification=5pcy0pvd7m24zu1w4ubtyeknqyfuje",
    "google-site-verification=1215qpicd1-TYtNffu-BXSUiKYlcsFdF-Spoth0OrPo",
    "google-site-verification=OVsEXNIYtD3q7DB4ONtD6aIgxQJxn1_iCfDUwvNUfKc"
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
  "elapsed_s": 20.0,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
