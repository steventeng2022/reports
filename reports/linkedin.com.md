# Security Audit Report — linkedin.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://linkedin.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | linkedin.com |
| Test date | 2026-09-26 17:48 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 0, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H6 | Server technology disclosure | CWE-200 |
| 6 | info | CORS4 | CORS: wildcard Access-Control-Allow-Origin | CWE-942 |
| 7 | info | CORS2 | CORS: subdomain origin origin accepted (no credentials) | CWE-942 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 10 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 11 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: ESF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: ESF
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 6. [INFO] CORS: wildcard Access-Control-Allow-Origin (`CORS4`)

- **CWE:** CWE-942
- **Detail:** Access-Control-Allow-Origin: * is set for cross-origin requests.
- **Context:** https response, /
- **Recommendation:** Restrict the allowed origins if sensitive data is exposed via the API.

### 7. [INFO] CORS: subdomain origin origin accepted (no credentials) (`CORS2`)

- **CWE:** CWE-942
- **Detail:** Origin https://sub.linkedin.com was echoed in Access-Control-Allow-Origin.
- **Context:** https response, /
- **Recommendation:** Confirm whether arbitrary origin echoing is intended.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: liveramp-site-verification=yQ2nkwhqszpGRQg_J38S60KHInPVs-dclgyNRtRrlBA; vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459; apple-domain-verification=Hp7LihDNsREwfHX9
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 10. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of linkedin.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 11. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but linkedin.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

## Evidence (raw response observations)

```json
{
  "domain": "linkedin.com",
  "dns": {
    "a": [
      "130.211.32.14"
    ],
    "aaaa": [
      "2600:1901:0:d5ad::"
    ],
    "cname": null,
    "mx": [
      "mail-d.linkedin.com (pref 10)",
      "mail-c.linkedin.com (pref 10)",
      "mail.linkedin.com (pref 20)",
      "mail-a.linkedin.com (pref 10)"
    ],
    "ns": [
      "dns4.p09.nsone.net.",
      "ns3-42.azure-dns.org.",
      "dns3.p09.nsone.net.",
      "ns2-42.azure-dns.net.",
      "ns4-42.azure-dns.info.",
      "dns2.p09.nsone.net.",
      "dns1.p09.nsone.net.",
      "ns1-42.azure-dns.com."
    ],
    "spf": [
      "liveramp-site-verification=yQ2nkwhqszpGRQg_J38S60KHInPVs-dclgyNRtRrlBA",
      "vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459",
      "apple-domain-verification=Hp7LihDNsREwfHX9",
      "google-site-verification=vfmYHwjzUIFPzxFcyuwEToh_1kG9wvcpGgJnB-MhQn8",
      "448e0dc03e935ecf66d81f1ce3c26b2f2fea13756c031ffc4be91749107f3a79",
      "google-site-verification=anx3jpa6VKkTWRJKnglUIzm7UEn-ZCT2WqAfG7h-xOg",
      "google-site-verification=8LaIeBMwr6K8qWeaGa4CEmfPKiZDwaT38t5mIrtaroI",
      "google-site-verification=mMV_EnYaB52OhMo-jbNowf8QVIKcXV3WpXreynLFFEo",
      "google-site-verification=VE9BWhjbPPNmbr3ZJcwn5hLTsz7c5KPt3zXdYyaSnSQ",
      "docusign=11f01284-dffc-40f9-8d56-57e5261ede3f",
      "atlassian-domain-verification=juKdSE4GGphSmzPkhmnRJUNIn0ALdb0vsP7VSPM8TmTP7WgbgUQPLFdNicP7bF58",
      "bluebeam-verification=02px6k8snlrzd6gx3b3oqkeatbzawd",
      "bf5fl8sny79w4c70jxp6cp3crkqtr7qk",
      "_cthqqp5zj8g86qf3h97heqitg2zc32b",
      "google-site-verification=X0LoSQsAMzR-TK4o-ULrYAwLi_fyopfRLkm_C-4N4Ts",
      "AFDVALIDATION=LinkedIn",
      "google-site-verification=xAGz495k8RbGclhamQx1TkZSHDxOaEd95fOjc8xpbTA",
      "google-site-verification=oJFWbtlKRblXs4smNibcoJkTJqwT6gd3XMI80VjBihE",
      "atlassian-domain-verification=dDed2VFvlDajBX8X22w52Jx/W/YLHR81SxUuraa9zNdz4aLjDS/RpfN11w2bxpRc",
      "google-site-verification=0Vs9yf1V6RGkuzow85OzIXKEnjpRswpDkI6RgDVspMg",
      "v=spf1 ip4:199.101.162.0/25 ip4:108.174.3.0/24 ip4:108.174.6.0/24 ip4:108.174.0.0/24 ip6:2620:109:c00d:104::/64 ip6:2620:109:c006:104::/64 ip6:2620:109:c003:104::/64 ip6:2620:119:50c0:207::/64 ip4:199.101.161.130 mx mx:docusign.net ~all",
      "atlassian-sending-domain-verification=3bdb0597-814d-4e10-a552-5cf78f92ab3c",
      "elevenlabs=hRLt8nemUjAWJSL_xhBIsKFyK4yYV089AvwkOB0cxYY",
      "miro-verification=260f00146b6d2ad1bb70d6dc07a077b672badd28"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com,mailto:yfy3q-9359@rua.dmarc.emailanalyst.com; ruf=mailto:d@ruf.agari.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=Sunnyvale, organizationName=Linkedin Corporation, commonName=linkedin.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "May 20 00:00:00 2026 GMT",
    "notAfter": "Nov 20 23:59:59 2026 GMT",
    "san": [
      "linkedin.com"
    ],
    "days_left": 55,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "130.211.32.14",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Checking your browser - reCAPTCHA"
  },
  "mixed_content": [],
  "tech": [
    "Server: ESF"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "*",
      "acac": ""
    },
    {
      "origin": "https://sub.linkedin.com",
      "acao": "*",
      "acac": ""
    }
  ],
  "http": {
    "status": 200
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 200",
    "/url?url=https://evil-auditor.example/x -> 200"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 200,
    "/.git/config": 200,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 200,
    "/phpmyadmin/index.php": 200,
    "/server-status": 200,
    "/api/": 200
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "liveramp-site-verification=yQ2nkwhqszpGRQg_J38S60KHInPVs-dclgyNRtRrlBA",
    "vmware-cloud-verification-f4d7c1c7-ad66-450f-82fa-c17b9ee79459",
    "apple-domain-verification=Hp7LihDNsREwfHX9",
    "google-site-verification=vfmYHwjzUIFPzxFcyuwEToh_1kG9wvcpGgJnB-MhQn8",
    "google-site-verification=anx3jpa6VKkTWRJKnglUIzm7UEn-ZCT2WqAfG7h-xOg"
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
      "aia_ocsp": null
    }
  },
  "elapsed_s": 4.4,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
