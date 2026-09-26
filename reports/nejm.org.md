# Security Audit Report — nejm.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nejm.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nejm.org |
| Test date | 2026-09-26 18:55 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 7, Info: 13)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | low | H1 | Missing HSTS header | CWE-319 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | RED2 | Soft redirect (302/303) for HTTP to HTTPS | CWE-319 |
| 12 | info | P8 | Missing security.txt | CWE-1038 |
| 13 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 14 | low | MAIL7 | SPF include: points to unresolvable domain(s) | CWE-285 |
| 15 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 16 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 17 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 18 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 19 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 20 | info | CT1 | 73 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: awselb/2.0
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 4. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 5. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 6. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 7. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

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
- **Detail:** Header reveals: awselb/2.0
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Soft redirect (302/303) for HTTP to HTTPS (`RED2`)

- **CWE:** CWE-319
- **Detail:** http:// root answered 302 -> https://nejm.org:443/.
- **Context:** https response, /
- **Recommendation:** Use 301/308 for permanent scheme upgrades.

### 12. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 13. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 14. [LOW] SPF include: points to unresolvable domain(s) (`MAIL7`)

- **CWE:** CWE-285
- **Detail:** Broken include(s): us. (no A/TXT record).
- **Recommendation:** Fix or remove the broken include directives.

### 15. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.nejm.org/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 16. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: atlassian-domain-verification=NNeumMyMPkAxVMrj7qq1zrhVVGl/5usz/MXkCgRheK8j05h3hD; adobe-idp-site-verification=55cac8ffb5b23b50c94d629752efc925f61ea92c1254d16d8bd6; openai-domain-verification=dv-8uyHnjMDd4ZJ1w1CapYvN7jZ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 17. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of nejm.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 18. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 35 disallow path(s), e.g. /action, /help, /search, /feedback, /rss
- **Recommendation:** Review disallowed paths; robots is not access control.

### 19. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 100.56.81.175 carries PTR ec2-100-56-81-175.compute-1.amazonaws.com. for nejm.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 20. [INFO] 73 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: staging.ad.nejm.org, staging.catalyst-drsite.nejm.org, staging.prod.nejm.org, staging.qa.nejm.org, staging.voices.nejm.org, store.nejm.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "nejm.org",
  "dns": {
    "a": [
      "100.56.81.175",
      "34.194.248.53",
      "3.81.128.132"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "us-smtp-inbound-1.mimecast.com (pref 10)",
      "us-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "ns-165.awsdns-20.com.",
      "ns-928.awsdns-52.net.",
      "ns-1559.awsdns-02.co.uk.",
      "ns-1284.awsdns-32.org."
    ],
    "spf": [
      "v=spf1 ip4:54.240.121.128/27 ip4:52.6.112.187 include:us._netblocks.mimecast.com include:spf.abila.info include:mail.zendesk.com ip4:74.220.145.8 ip4:74.203.48.0/23 ip4:74.203.57.0/24 ip4:174.46.206.0/23",
      " ip4:174.46.10.129/32 ip4:143.220.15.0/24 ip4:143.220.17.0/24 ip4:143.220.32.0/24 ip4:216.71.144.176 ip4:207.54.86.45 include:_spf.qualtrics.com include:amazonses.com ~all",
      "atlassian-domain-verification=NNeumMyMPkAxVMrj7qq1zrhVVGl/5usz/MXkCgRheK8j05h3hDbEs6zZdYhHhGt8",
      "0ed1fe018af5796b96adc34642aa2a42756ef1a82e",
      "adobe-idp-site-verification=55cac8ffb5b23b50c94d629752efc925f61ea92c1254d16d8bd6f0affe96e97e",
      "openai-domain-verification=dv-8uyHnjMDd4ZJ1w1CapYvN7jZ",
      "onetrust-domain-verification=aea188f6772b4e0a9e7464f3a5d39d88",
      "anthropic-domain-verification-wxcd0c=BgSYxLEu4oZNGb1STL7CkvTPg",
      "docusign=52095567-2918-44fb-ba89-2af8aa120c2b",
      "xVXYh2htSzJmE6VkToy/aGAmNs8cxK2vV+6I70GL/zlQHSbfrd6n2vPKyYeokIK4okHucqCOzxF9J/FLb7VQZA==",
      "4k87v34q679nnktm7msw176n2mjjt2f2",
      "MS=ms51433796",
      "tz7y9ps639fshlhk6fmljls36vsgmsh2",
      "6hszhhybwmrbh92rpj7m8rm8rclry7gs"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc_agg@vali.email,mailto:dmarc@mms-org.uriports.com; ruf=mailto:dmarc@mms-org.uriports.com; fo=1:d:s"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=nejm.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Dec 28 00:00:00 2025 GMT",
    "notAfter": "Jan 26 23:59:59 2027 GMT",
    "san": [
      "nejm.org"
    ],
    "days_left": 122,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "100.56.81.175",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: awselb/2.0"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nejm.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 302,
    "location": "https://nejm.org:443/"
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
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "source": "certspotter",
    "count": 73,
    "notable": [
      "staging.ad.nejm.org",
      "staging.catalyst-drsite.nejm.org",
      "staging.prod.nejm.org",
      "staging.qa.nejm.org",
      "staging.voices.nejm.org",
      "store.nejm.org"
    ],
    "sample": [
      "ai.catalyst-drsite.nejm.org",
      "bc.nejm.org",
      "blogs.nejm.org",
      "blogstest.nejm.org",
      "catalyst.events.nejm.org",
      "catalystinsights.nejm.org",
      "catalystinsightspanel.nejm.org",
      "catalystinsightssurvey.nejm.org",
      "ce.massmed.nejm.org",
      "clinical-conversations-podcast.nejm.org",
      "cme-info.nejm.org",
      "drsite.nejm.org",
      "embargoed.qa.nejm.org",
      "embargoed.www.nejm.org",
      "events.nejm.org",
      "evidence.catalyst-drsite.nejm.org",
      "handheld.nejm.org",
      "intl-content.nejm.org",
      "knowledgeplusqa.nejm.org",
      "m.c.nejm.org"
    ]
  },
  "apex_txt": [
    "atlassian-domain-verification=NNeumMyMPkAxVMrj7qq1zrhVVGl/5usz/MXkCgRheK8j05h3hD",
    "adobe-idp-site-verification=55cac8ffb5b23b50c94d629752efc925f61ea92c1254d16d8bd6",
    "openai-domain-verification=dv-8uyHnjMDd4ZJ1w1CapYvN7jZ",
    "onetrust-domain-verification=aea188f6772b4e0a9e7464f3a5d39d88",
    "anthropic-domain-verification-wxcd0c=BgSYxLEu4oZNGb1STL7CkvTPg"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "not_before": "20251228000000",
      "not_after": "20270126235959"
    }
  },
  "http2": {
    "robots_disallow": [
      "/action",
      "/help",
      "/search",
      "/feedback",
      "/rss",
      "/action/clickThrough",
      "/action/showLogin",
      "/page/account-confirmation-thanks",
      "/media",
      "/servlet/linkout",
      "/author/",
      "/doi/mlt/",
      "/",
      "/action",
      "/help"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-100-56-81-175.compute-1.amazonaws.com."
    ]
  },
  "elapsed_s": 32.8,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
