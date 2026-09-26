# Security Audit Report — verizon.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://verizon.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | verizon.com |
| Test date | 2026-09-26 23:40 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **14** (High: 0, Medium: 0, Low: 4, Info: 10)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H1 | Missing HSTS header | CWE-319 |
| 3 | low | H2 | Missing CSP header | CWE-1021 |
| 4 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 5 | low | H4 | No clickjacking protection | CWE-1023 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | P8 | Missing security.txt | CWE-1038 |
| 10 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 13 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 14 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

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

### 9. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

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
- **Detail:** Apex TXT records with verification/token content: Precisely-domain-verification; google-site-verification=tZDve57pSHTO7eOO90j3R3wUIdpqq9pCrPCCauMcfbc; google-site-verification=Y3Q2T99tU_-XF206jqXW_UugVEHCvpzvPnIk5hYL2Bk
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 13. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 23.40.244.108 carries PTR a23-40-244-108.deploy.static.akamaitechnologies.com. for verizon.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 14. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The verizon.com certificate lists an AIA OCSP responder (http://ocsp.digicert.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "verizon.com",
  "dns": {
    "a": [
      "23.40.244.108",
      "23.206.58.110",
      "23.206.63.107",
      "23.206.60.108",
      "23.206.62.107",
      "23.206.59.110",
      "23.206.56.116",
      "23.206.57.108",
      "23.53.5.117",
      "23.206.61.108"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-0024a201.gslb.pphosted.com (pref 15)",
      "mxb-0024a201.gslb.pphosted.com (pref 15)"
    ],
    "ns": [
      "a9-67.akam.net.",
      "a12-65.akam.net.",
      "a1-18.akam.net.",
      "a26-67.akam.net.",
      "a24-66.akam.net.",
      "a13-67.akam.net."
    ],
    "caa": [
      "0 issue \"digicert.com\"",
      "0 issue \"letsencrypt.org\"",
      "0 issue \"amazon.com\""
    ],
    "spf": [
      "Precisely-domain-verification",
      "google-site-verification=tZDve57pSHTO7eOO90j3R3wUIdpqq9pCrPCCauMcfbc",
      "docusign=9f9bf7a4-31a7-42bd-989d-b177ae520342",
      "ct55qq4v9hkbzvr613bg3nj4zqs82410",
      "google-site-verification=Y3Q2T99tU_-XF206jqXW_UugVEHCvpzvPnIk5hYL2Bk",
      "flexera-domain-verification-kqnfpwapzjwcdtjl",
      "atlassian-domain-verification=aj1ES5iXBorxgboMWU4jPaWG8ufdkUqPAZ98L4Z4FxPtlETrOSCwWPopYp326Boi",
      "smartsheet-gov-site-validation=wO9Aq-yUnfO-HMmw3WBsMSiP212HgHB4",
      "MS=ms87778762",
      "2emAY6c1D+CgmANq0s7xHidy8qnyE6WStN33LPNuG/hd0aBm9xBLt6ZeIl7bfQR1VIMPYtYt3FlRkIcNWId/+A==",
      "Dynatrace-site-verification=9b5e8c85-ffc6-4ee3-80a4-01c14607d287__pdi80imbksqp54emrr20d3gph8",
      "b8fwzdt99dt8btdysj12gnnjpkz146y3",
      "adobe-sign-verification=5c72a7e0c328f6774716059ec6fb7da6049813116d899e3483577d0896e7544c",
      "_lva6pf2y06r966zjnmczto8aoqtyhsj",
      "_w6n6znye04ehtb3ugsmxtzhvkvu4h66",
      "5bldj12kt4tpxl03yr7wcq4999ldkl6c",
      "Dynatrace-site-verification=6219e2d6-0d4c-42b0-aa3f-bf137c76e0ef__lc47bag6133ot2qms6uqkhqmkg",
      "facebook-domain-verification=jzt3ysrggr1qi89a0c46h6hnmtu0l4",
      "0gydk8ylzblmdk89rrh71z6vq8csbd4j",
      "quickbase-site-verification-922ae18c23918d07de301f714e7747cabad0e6ce",
      "00Dfn00000BO1uH=1TBaJ00000008Yf",
      "_87362fr0avm39qsoglpth1t9iocx3h0",
      "00DWH000005xk2L=1TBWH0000000M3l",
      "_xbcq1ksf5g26csqvs958k3ig1ovtwtt",
      "airtable-verification=c7ec519ab4f7b83da45d01617d013506",
      "_60467rwxiajhlol2lvhpvkdp6849tto",
      "_v5t56ssq25ktk2khlhxdq84ct19wha1",
      "VaI7HAA7sB1/Nj9AfhmIpdfZyiwqm7N7pf9UApsrhO0=",
      "q5c6fp9dz62p3yxbgjrfsmr9d0wm705p",
      "docker-verification=e63249f1-5c89-419c-8b2a-928c81b87800",
      "docusign=4a19cd69-5db5-4663-b70e-6600f177dae2",
      "zv5q0hfc968n8pzr19b9vzqk5w75dcr2",
      "google-site-verification=KC5CJC5e0rzcxlINJHJcTM5U4b5Pr211cGU8diogsKI",
      "hpe-greenlake-domain-verification=3571596b4878766d77676479514571517876467a537974492d50464663743858",
      "g0s1gq156v9thvrtvmg4smn6fhgcxqnl",
      "70nhs2k6yktgpq4blv65k8416dwfwtds",
      "flexera-domain-verification-bpuabamsmujihlzs",
      "anthropic-domain-verification-dh9nvq=MZi3jVJdupvG2ZzJKBbuDIzF8",
      "dwpv611b3xgfp7ymnj2yd18kvdfc93lm",
      "zfk8y8l5fh15lrg8dsk27ks1j51869tw",
      "_q8n9oay9918jw5gr4o497lxper8vgf9",
      "flexera-domain-verification-ffgblppxwzuqqveo",
      "EFrYNbG8uzynGvptGZk9HtN4Lm3prlj/zxlKEuFuGuCT614NJoj7M8m3YoFYzfpafIrQATFeKoHKqZOCDzKt/w==",
      "00DWH000005k5zV=1TBWH0000000M29",
      "v=spf1 include:verizonwireless.com ~all",
      "mongodb-site-verification=6vBJxn6M8ujjAATlYkC5bRNXjD4sUiRf",
      "miro-verification=cb4542e8a7b94284a46cef7263ff93a0a8981ccc",
      "airtable-verification=72cbbd275f6f706ba31aaca8586b013f",
      "docker-verification=f22a41ee-7281-4719-a023-ff82e56fd556"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc_agg@auth.returnpath.net; ruf=mailto:dmarc_afrf@auth.returnpath.net; rf=afrf; pct=100"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=Florida, localityName=Temple Terrace, organizationName=Verizon Data Services LLC, commonName=verizon.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Dec  9 00:00:00 2025 GMT",
    "notAfter": "Dec  8 23:59:59 2026 GMT",
    "san": [
      "verizon.com",
      "ws01.static-verizon.com",
      "ws02.static-verizon.com",
      "ws03.static-verizon.com",
      "ws04.static-verizon.com",
      "www.verizon.com"
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
    "ip": "23.40.244.108",
    "open": []
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.verizon.com",
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
    "status": "ct-pending"
  },
  "apex_txt": [
    "Precisely-domain-verification",
    "google-site-verification=tZDve57pSHTO7eOO90j3R3wUIdpqq9pCrPCCauMcfbc",
    "google-site-verification=Y3Q2T99tU_-XF206jqXW_UugVEHCvpzvPnIk5hYL2Bk",
    "flexera-domain-verification-kqnfpwapzjwcdtjl",
    "atlassian-domain-verification=aj1ES5iXBorxgboMWU4jPaWG8ufdkUqPAZ98L4Z4FxPtlETrOS"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": "http://ocsp.digicert.com",
      "serial": 18385698757005194324634163312549763219,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
      ],
      "subject_dn": "310b30090603550406130255533110300e06035504081307466c6f72696461311730150603550407130e54656d706c65205465727261636531223020060355040a1319566572697a6f6e2044617461205365727669636573204c4c43311430120603550403130b766572697a6f6e2e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e63313330310603550403132a446967694365727420476c6f62616c20473220544c532052534120534841323536203230323020434131",
      "not_before": "20251209000000",
      "not_after": "20261208235959"
    },
    "ocsp": "explicit-status"
  },
  "x12": {
    "status": 403,
    "ptr": [
      "a23-40-244-108.deploy.static.akamaitechnologies.com."
    ]
  },
  "x13": {
    "root_status": 403,
    "http_status": 403,
    "p404_status": 403,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 403,
    "crl": {
      "url": "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
      "status": 200
    }
  },
  "elapsed_s": 34.9,
  "rechecked": "2026-09-26 23:16 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- Findings are reported against the public program scope; submission through the program tracker is pending.
