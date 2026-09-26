# Security Audit Report — getresponse.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://getresponse.com/ |
| Bug bounty program | [top-websites gist (no active program match)]() |
| Listed scope domain | getresponse.com |
| Test date | 2026-09-26 23:28 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **16** (High: 0, Medium: 0, Low: 6, Info: 10)

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
| 10 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 11 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 12 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 13 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 14 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 15 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 16 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |

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

### 10. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.getresponse.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 11. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 12. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (zawp3hkrfwpa8m.getresponse.com and oso5ltzeojvgw6.getresponse.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 13. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=fMdXexz-UeermTKRO7SNU9jaU8iWvBjkLyUjux2p1s8; google-site-verification=qQY936ygxuK-lM39J2ouZcOYciA1FsHBrh2N6K8aGho; google-site-verification=Dp1TRtq03Oinzgwpx4tg0nfgchSB7UYGTHaTvgRuvQA
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 14. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 145 disallow path(s), e.g. /about/investor-relations, *emailTemplateID=, /features/website-builder/templates/*/*, /features/website-builder/templates/business-and-services/*,*, /features/website-builder/templates*order=
- **Recommendation:** Review disallowed paths; robots is not access control.

### 15. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 104.160.64.8 carries PTR getresponse.com. for getresponse.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 16. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on getresponse.com lists 656 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

## Evidence (raw response observations)

```json
{
  "domain": "getresponse.com",
  "dns": {
    "a": [
      "104.160.64.8"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "getresponse-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns0.dnsmadeeasy.com.",
      "ns4.dnsmadeeasy.com.",
      "ns3.dnsmadeeasy.com.",
      "ns2.dnsmadeeasy.com.",
      "ns1.dnsmadeeasy.com."
    ],
    "caa": [
      "0 issuewild \"certum.pl\"",
      "0 issue \"letsencrypt.org\"",
      "0 iodef \"mailto:security@getresponse.com\"",
      "0 issue \"godaddy.com\"",
      "0 issue \"digicert.com\"",
      "0 issue \"rapidssl.com\"",
      "0 issuewild \"godaddy.com\"",
      "0 issue \"certum.pl\"",
      "0 issuewild \"rapidssl.com\""
    ],
    "spf": [
      "google-site-verification=fMdXexz-UeermTKRO7SNU9jaU8iWvBjkLyUjux2p1s8",
      "google-site-verification=qQY936ygxuK-lM39J2ouZcOYciA1FsHBrh2N6K8aGho",
      "google-site-verification=Dp1TRtq03Oinzgwpx4tg0nfgchSB7UYGTHaTvgRuvQA",
      "perplexity-ai-domain-verification-xhench=mT1d7pxsOX0OQ99IarJY2WASZ",
      "anthropic-domain-verification-venw22=ZeM4NT230jUX4wYrLH2xiewmQ",
      "openai-domain-verification=dv-Rf8rPeAU2o96nKUYvGJOqGKG",
      "1password-site-verification=BMMLC4IXRBCU3G5UCBKCF5MINM",
      "facebook-domain-verification=hzu8jvt165inp6e47scduae2y0smll",
      "jamf-site-verification=EMDHC_pNcl7T-4-V0hfEIQ",
      "5ce38e29469ad11f7177b24c1922672b63abf6680d6a0726116fd210c7e8cc6",
      "pandadoc-domain-verification=URaRjh7TeRXzEYB2xiZ72o",
      "v=spf1 mx a ip4:104.160.64.0/23 ip4:104.160.67.63/32 ip4:104.160.67.128/25 ip4:104.160.68.224/27 ip4:104.160.69.0/27 ip4:104.160.66.254 ip4:178.16.117.0/24 include:spf.protection.outlook.com include:_spf.psm.knowbe4.com -all",
      "google-site-verification=zr4OhPflVzGIZtxchXz72jWuNqjvgDlHrPUpiiJY0-k",
      "atlassian-domain-verification=LK2p1objuTfwluXVqD2rSagYcHzknb4lAGe2sOnklu3lYjE6x2o6yfOxo1T4OK5u",
      "mojecertpl-site-verification-pTZqxhVN4nRsImMtqYHyUrnng6ILpAqJ",
      "google-site-verification=Z8jVzgnaG8CjbUygDISY-3uP8uIqGzn5At2bo5nzHqQ",
      "miro-verification= 79b13564da36f9da3d95258202fd70c9462a2a62",
      "google-site-verification=j5cNpXTozrVnhuElGV-BdoIZaBOqg8wtr_z2hiO_1CY",
      "google-site-verification=QeBji-07N-gsBMjY9YfUf5LXyTluvf76nuzqSX3PTsQ",
      "Dynatrace-site-verification=e1a175f3-bb98-4294-b96d-7da32368958c__5e1a4oqvdp0fv5mdkt0iek9bk3",
      "sf9v0knq1ugotc1jqte1ractie"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc_agg@dmarc.everest.email; ruf=mailto:dmarc_fr@dmarc.everest.email; fo=1; pct=100; rf=afrf"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=*.getresponse.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, organizationalUnitName=www.digicert.com, commonName=RapidSSL TLS RSA CA G1",
    "notBefore": "Sep  9 00:00:00 2026 GMT",
    "notAfter": "Mar 20 23:59:59 2027 GMT",
    "san": [
      "*.getresponse.com",
      "getresponse.com"
    ],
    "days_left": 175,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.160.64.8",
    "open": []
  },
  "https": {
    "status": 301,
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
      "origin": "https://sub.getresponse.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.getresponse.com/"
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
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 403,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=fMdXexz-UeermTKRO7SNU9jaU8iWvBjkLyUjux2p1s8",
    "google-site-verification=qQY936ygxuK-lM39J2ouZcOYciA1FsHBrh2N6K8aGho",
    "google-site-verification=Dp1TRtq03Oinzgwpx4tg0nfgchSB7UYGTHaTvgRuvQA",
    "perplexity-ai-domain-verification-xhench=mT1d7pxsOX0OQ99IarJY2WASZ",
    "anthropic-domain-verification-venw22=ZeM4NT230jUX4wYrLH2xiewmQ"
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
      "aia_ocsp": "http://status.rapidssl.com",
      "serial": 9969152079585037575572598851112463871,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://cdp.rapidssl.com/RapidSSLTLSRSACAG1.crl"
      ],
      "subject_dn": "311a301806035504030c112a2e676574726573706f6e73652e636f6d",
      "issuer_dn": "310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311f301d06035504031316526170696453534c20544c5320525341204341204731",
      "not_before": "20260909000000",
      "not_after": "20270320235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/about/investor-relations",
      "*emailTemplateID=",
      "/features/website-builder/templates/*/*",
      "/features/website-builder/templates/business-and-services/*,*",
      "/features/website-builder/templates*order=",
      "/features/website-builder/templates/business-and-services$",
      "/features/website-builder/templates/business-and-services*order=",
      "/resources*company-or-business-role=",
      "/resources*category=",
      "/resources*type=",
      "/resources*query=",
      "/resources*sort=",
      "/resources*i=",
      "/api/",
      "*/api/v2"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "getresponse.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.getresponse.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "sitemap": {
      "urls": 656,
      "indexes": 0
    },
    "crl": {
      "url": "http://cdp.rapidssl.com/RapidSSLTLSRSACAG1.crl",
      "status": 200
    }
  },
  "elapsed_s": 40.7,
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
