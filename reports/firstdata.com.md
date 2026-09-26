# Security Audit Report — firstdata.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://firstdata.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | firstdata.com |
| Test date | 2026-09-26 17:45 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 1, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 3 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 4 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 5 | info | P8 | Missing security.txt | CWE-1038 |
| 6 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 7 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 8 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 9 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 10 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 11 | info | CT1 | 149 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 12 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 3. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 4. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 5. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 6. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 7. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 8. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=UUQbbVvMvjF4/Haa4wZPYq9FxrYqfMLH3E6gI2ri2gGiM1YehJ; google-site-verification=26Qcgnci2XPHOXsfUzhn4urYuxuzAZoiD_V9JmsbwbA; google-site-verification=N6XdNnf_haEL8arPehDiAPoYLKH5SPbLr-_6-EGFvA8
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 9. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of firstdata.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 10. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but firstdata.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 11. [INFO] 149 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: cat-ause1.api.firstdata.com, cat.api.firstdata.com, cert-asns1.api.firstdata.com, cert-ause1.api.firstdata.com, cert-euw1.api.firstdata.com, cert-euw3.api.firstdata.com, cert-usc1.api.firstdata.com, cert-use4.api.firstdata.com, cert.api.firstdata.com, int-ause1.api.firstdata.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 12. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: cat-ause1.api.firstdata.com, cert-asns1.api.firstdata.com, cert-ause1.api.firstdata.com, cert-euw1.api.firstdata.com; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "firstdata.com",
  "dns": {
    "a": [
      "151.101.3.10",
      "151.101.195.10",
      "151.101.67.10",
      "151.101.131.10"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxa-00265f01.gslb.pphosted.com (pref 10)",
      "mxb-00265f01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "dns2.p07.nsone.net.",
      "ns2.p201.dns.oraclecloud.net.",
      "dns4.p07.nsone.net.",
      "ns1.p201.dns.oraclecloud.net."
    ],
    "spf": [
      "VISA=50A1277B5BDE5E4EFB009D04C1270052",
      "_2ronacfit0dlj82vq1smryoviyg476a",
      "atlassian-domain-verification=UUQbbVvMvjF4/Haa4wZPYq9FxrYqfMLH3E6gI2ri2gGiM1YehJSYASzKT5Kfz2hn",
      "google-site-verification=26Qcgnci2XPHOXsfUzhn4urYuxuzAZoiD_V9JmsbwbA",
      "VISA=BBA97F5F900D99EE7A70768DC4E6302B",
      "citrix.mobile.ads.otp=5iepmqqj2gwg4fki3uxoh81",
      "google-site-verification=N6XdNnf_haEL8arPehDiAPoYLKH5SPbLr-_6-EGFvA8",
      "flexera-domain-verification-fddzqvzijueazdba",
      "VISA=BB846B1356DBAEC50AABC2EAC27251C4",
      "status-page-domain-verification=qhcz5lpgpkhm",
      "MS=ms12481784",
      "_tmhwbqqay6pmvj46jbz8ygq4v1qdnbd",
      "VISA=B42E0A2235D43D9F1A30FCF136EFBBE1",
      "00DRL00000GkGyg=1TBRL0000000YOH",
      "VISA= 971F17AC7C2EA9F76D1B4399ACDD8AF8",
      "VISA= 8B44CCB91191FE803D19007A17C3D271",
      "MS=ABB1BE2F85FB33A30DEC1C7264489333E3C1200F",
      "0PvnqG+rTIOOb7OBR8TRrF3sAejgz0OAbJ9ijKq3T7BQ9Cp0OTN+U7Lov+lrTt/L8Kv/xiMPuV9vZwuOFwT3GA==",
      "VISA= 3AE81DAB19A78A9EF5F7BB7E5538ADA3",
      "VISA = E086293AA5EBACE091D6F079311621E3",
      "hcp-domain-verification=d7eeb26b7066067aabfb44e977a62f8629c2c4003e4b5ff27e8296a60e74b8d2",
      "00DA0000000Yhcv=1TBUJ0000000Fez",
      "VISA= QOHYOGX571VGUJW8RSJUP39HTRRTZITN",
      "VISA=0DF7ED8CA76B25E8E433992B7F0AEEA8",
      "VISA=2A880877BD3A4783B5D65152D0479BEA",
      "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all",
      "VISA=32A1FA0269CCD3FEB9497B54209C50ED",
      "MS=ms52820778",
      "VISA=58B7F8092117EFC2B048E1D063C7381B",
      "VISA=6647EA50224BACA094BAB45F9A1DD003",
      "VISA=875D6E9B71BCD2951AAAED28DEE8B317",
      "_k7wm3b9cqot77wpu829xdomkm0s1gbz",
      "VISA=E8C6EF412551A5ED20EFB7D270035456",
      "citrix-verification-code=b49394b7-fec3-45b1-9598-81f10a16746d",
      "_bqjvwc1revtk7b6umibs4dk66005gcc",
      "docusign=5335d3f2-83aa-4ed0-91a8-716365eb0641",
      "atlassian-domain-verification=bwfGSdfnH94uNI9lzvKPvl6Xx6BGuAMdPRwDp6G9XAfFReRFHBj398p8n4tJRp1u",
      "_gtyampd6jk2kk0vasl1zp2t4zwtc66i",
      "VISA= 2E83EF65759F5F147DBDFC1C423F1CF1",
      "VISA= 45376BBCD9B74696522F84B27AD772AA",
      "VISA= F09D890A2DAB504AAE78586229A231BB"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; fo=0; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "countryName=US, stateOrProvinceName=Wisconsin, localityName=Brookfield, organizationName=Fiserv, Inc., commonName=merchants.fiserv.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jan 14 00:00:00 2026 GMT",
    "notAfter": "Jan 20 23:59:59 2027 GMT",
    "san": [
      "merchants.fiserv.com",
      "www.firstdata.com",
      "firstdata.com",
      "GetAssistance.Telecheck.com",
      "TRSRecoveryServices.com",
      "www.TRSRecoveryServices.com",
      "Ignitepayments.ca",
      "www.Ignitepayments.ca",
      "www.telecheck.com",
      "telecheck.com",
      "carat.fiserv.com",
      "talent.clover.com",
      "www.ignitepayments.com",
      "ignitepayments.com",
      "talent.fiserv.com",
      "www.carat.fiserv.com",
      "franchise.fiserv.com",
      "www.cloverconnect.com",
      "www.cditechnology.com",
      "mex.clover.com",
      "www.mex.clover.com"
    ],
    "days_left": 116,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "151.101.3.10",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [
    {}
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.firstdata.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://firstdata.com/"
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
    "/.git/HEAD": 406,
    "/.git/config": 406,
    "/.env": 301,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 149,
    "notable": [
      "cat-ause1.api.firstdata.com",
      "cat.api.firstdata.com",
      "cert-asns1.api.firstdata.com",
      "cert-ause1.api.firstdata.com",
      "cert-euw1.api.firstdata.com",
      "cert-euw3.api.firstdata.com",
      "cert-usc1.api.firstdata.com",
      "cert-use4.api.firstdata.com",
      "cert.api.firstdata.com",
      "int-ause1.api.firstdata.com",
      "int-sae1.api.firstdata.com",
      "int.api.firstdata.com",
      "prod-asns1.api.firstdata.com",
      "prod-ause1.api.firstdata.com",
      "prod-euw1.api.firstdata.com"
    ],
    "sample": [
      "accounts.firstdata.com",
      "addiko-pindelivery-uat.firstdata.com",
      "addiko-pindelivery.firstdata.com",
      "addiko-pinnow-uat.firstdata.com",
      "addiko-pinnow.firstdata.com",
      "adetrb240dc.firstdata.com",
      "afs2.firstdata.com",
      "atsapi.firstdata.com",
      "atsmobileapi.firstdata.com",
      "automateddetrustbank1900240.firstdata.com",
      "br1-cognos-br-vip.firstdata.com",
      "br2-cognos-br-vip.firstdata.com",
      "cat-afs2.firstdata.com",
      "cat-ause1.api.firstdata.com",
      "cat-b2s.firstdata.com",
      "cat-plp-pl.firstdata.com",
      "cat-plp.firstdata.com",
      "cat.api.firstdata.com",
      "cert-asns1.api.firstdata.com",
      "cert-ause1.api.firstdata.com"
    ],
    "dangling": [
      "cat-ause1.api.firstdata.com",
      "cert-asns1.api.firstdata.com",
      "cert-ause1.api.firstdata.com",
      "cert-euw1.api.firstdata.com"
    ]
  },
  "apex_txt": [
    "atlassian-domain-verification=UUQbbVvMvjF4/Haa4wZPYq9FxrYqfMLH3E6gI2ri2gGiM1YehJ",
    "google-site-verification=26Qcgnci2XPHOXsfUzhn4urYuxuzAZoiD_V9JmsbwbA",
    "google-site-verification=N6XdNnf_haEL8arPehDiAPoYLKH5SPbLr-_6-EGFvA8",
    "flexera-domain-verification-fddzqvzijueazdba",
    "status-page-domain-verification=qhcz5lpgpkhm"
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
  "elapsed_s": 28.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
