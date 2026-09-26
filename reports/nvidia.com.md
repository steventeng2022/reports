# Security Audit Report — nvidia.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://nvidia.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | nvidia.com |
| Test date | 2026-09-26 23:34 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **19** (High: 0, Medium: 0, Low: 4, Info: 15)

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
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | PTR1 | Reverse-DNS (PTR) fingerprint of apex IP | CWE-200 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | TLS19 | OCSP stapling not offered (cert has an OCSP URL) | CWE-298 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
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
- **Detail:** Header reveals: nginx
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
- **Detail:** Apex TXT records with verification/token content: xmind-domain-verification-fzhrb5=2CDgcQwEk3L1j2txLkWniBSnO; google-site-verification=Bgm4VneS70f1CGZKg-D3tGoEQYxxHm56CH1v8frb1OA; airtable-verification=d6d9ca2bacc2c108daad98a586ea9ae7
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m01.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 55 disallow path(s), e.g. /content/g/*, /content/gated-pdfs/*, /content/*/gated-resources/*, /content/*/gated-pdfs/*, /gated-resources/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 34.194.97.138 carries PTR ec2-34-194-97-138.compute-1.amazonaws.com. for nvidia.com.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for nvidia.com, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The nvidia.com certificate lists an AIA OCSP responder (http://ocsp.r2m01.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

## Evidence (raw response observations)

```json
{
  "domain": "nvidia.com",
  "dns": {
    "a": [
      "34.194.97.138"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "nvidia-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns7.dnsmadeeasy.com.",
      "ns5.dnsmadeeasy.com.",
      "dns2.p09.nsone.net.",
      "dns1.p09.nsone.net.",
      "ns6.dnsmadeeasy.com."
    ],
    "caa": [],
    "spf": [
      "xmind-domain-verification-fzhrb5=2CDgcQwEk3L1j2txLkWniBSnO",
      "google-site-verification=Bgm4VneS70f1CGZKg-D3tGoEQYxxHm56CH1v8frb1OA",
      "00DWF00000CuVQQ=1TBWF0000000hub",
      "_aruimzyfi76an2jxf1in2l105k6nz3b",
      "airtable-verification=d6d9ca2bacc2c108daad98a586ea9ae7",
      "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
      "_2e0v9clijhuv53e0z8ypnbin4pvcay5",
      "webexdomainverification.JUIU=a2070f62-2329-43d5-a745-0506cd1e0be8",
      "7iv8kqoklj3k99ad2hm1i3rp5u",
      "webexdomainverification.4C675B8BC9F4B136E053AB06FC0A3F65=7bca8485-5ef5-41d8-9095-9faeb8267f22",
      "0ed1fe018a86de5c28fed445dda5cec48fd7d5cc0f",
      "aliyun-site-verification=47b62ce6-8506-41f0-bb2f-07b3a645d506",
      "amazonses:tiDUkAUORs6LGjJXT0/6lf7qhM1Z/k+5ax6kvycH0KU=",
      "mongodb-site-verification=ROIaNgdagjgVhIzbnNJrLtHAQerIZZ7G",
      "b47c0mpmnsxbg005dw6b5jpft3smyxc0",
      "bua5v23vah91dl7u8q18uqeqi2",
      "2bv8cxn82sdc4jf5k46r4yjymyq99kx5",
      "docusign=96779a1c-034b-4e45-b43d-d542d10e71ec",
      "v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5pZXEi8/P4fDOafsJ88H",
      "48w2f8UQ6z98cELLNoNt2R9SU72Vub/ksg+MYGxGZRsV21FEDkPzd8JqIS95qKL6",
      "u+L/FGXdi1nknL9YowFcHZ04wR5+HEkIZ3W4Q7wzIyITul065bUB1/jN3GCf2Ab3",
      "JxKHvu2cffNwwjSwbCvvFi6Y7xtiKg7PUAmD3lJU7joS9MIwk8G35WbQjRU7F21/",
      "ryPkFmtWDEYQRAo7cJ3EORRDms06taHZN+Mx5KN2bBq/ULOdX7RURFFzzOy0xajW",
      "pOkfIyV0uk+arLr4dFthkHO0pwyBFaNAYFs141ZJFkUYhxA3G+4zljVQOMCVrMuG",
      "qwIDAQAB",
      "jxp4dypdbq8k2qfh3csbxqk3mhtt3bc2",
      "_ta09m7iwsv1mha5ex6kiebva69g310k",
      "705HTG3G6VA7V2IN61PSCVLMDC",
      "stripe-verification=87E8E0C1E618E41698A141FFBEF22C7F77D5AC285CD7404907CFB4D131F7BFFF",
      "gkr1fe2hai0i5lpj2jqmatdp4t",
      "anthropic-domain-verification-yrjjcd=ej6XWEu0ENbzDBfGT2ApwOA9u",
      "_e97jw0iw78afuye7dwuhjyh3fpm0eua",
      "wrike-verification=MzQ5MDMzNjoxNGE4MDkxMDAyYzEyNGU5YWQxNGVhYWI4ZjkzNzhhMmIwZWY4MzViYWVkZTZjZjk3YjhhYWYxNTgzYTc0ZWVl",
      "smartsheet-site-validation=GesD_luIWHnX8PgyzkdwkP4zgJbEnWFG",
      "docusign=a95fd649-319d-4f9d-b832-6925ebd520fd",
      "kp6v5hv1mb3vfdljx9tgwd4l937vd14y",
      "sonatype-verification=OSSRH-58518",
      "xz3kx787d2v3sybkp648jh2xpb41w7ss",
      "wrike-verification=MzkwOTExMDpiYjg3NmMwYTY1MjhjODk1NWY1MzZiZDQxMDljOGU5ZjMyYTIzYjNlZmYyNGQ4ZDViY2FlYjdhODkzNjMwMzBm",
      "perplexity-ai-domain-verification-q7nwx7=rsQck5ZDngPVcnFaBeEOnq8yy",
      "onetrust-domain-verification=a82a3dc15f9f4b5ba1ebebc75ee8880d",
      "ek0aq24s0hi15hq4tqtkqjj1aj",
      "slack-domain-verification=JdqDQf1IlTnyYj3bjoNb5vAAQNY43wTMTka9JV6L",
      "cxqdvl1xsmlvpwd2xd11mbp6tk4b2fn9",
      "00DWG000005SHvt=1TBWG0000000Ooj",
      "atlassian-domain-verification=TkpNmmgTUPTLgab1/pTD1DQIwSM2wKR38idvHtF1/yzRlc7ajVBMnJ1PSdIwPYH+",
      "_z66mbl00eie3gk8qvoeo0jn57peolxo",
      "mn7s1rhpyt62qychj30kwqglk6m0xbf7",
      "openai-domain-verification=dv-n75OVQToqSuaVb8uhdA5Gm5S",
      "stripe-verification=99D9E45F72AD5546982F73E692E6BF04557C64DAB69C66E6200EE7B88D8BFF58",
      "apple-domain-verification=BVP359YB3NqbMfZN",
      "_apmx74bb1j68dcnum1ooerr3537kt3f",
      "_bsu0cnbbyliltohc5op1gjad09swnyb",
      "google-site-verification=E0JpDUEbAIl3vRi2qQd2jrKE-LhGI5O6OebHTywDLYQ",
      "4mq1tkhh4a1ah00o7fpl6l9e0g",
      "facebook-domain-verification=8xnj9c1jc5elzjmp75cud9ty4ddqe1",
      "autodesk-domain-verification=DsRz7uyZ60rHqKxi31y9",
      "37e5g68gjeqgjjc64hlihvgiim",
      "xr3$HxkR2hjQBd6n8xLZeKkT2Weed2I&5t3srsv6yXqgeoGxwB#tZXM#e8JPGTJor^H#e1zRQO8@7fZmWeFrlhDhe4v01Ij%^c7",
      "_xcqf40cqfhy8igzqdkbjdyb4nys65u9",
      "openai-domain-verification=dv-NvYhgg87YsmEx1yhbZSJrBhQ",
      "00DWJ000008WdOD=1TBWJ0000000ECf",
      "fern-domain-verification-tq9vd4=ZtQlGS4odLpLlCo4IyDHQYXol",
      "6pz5xms6zpn4mngxrgm8xj6v2btwff06",
      "docker-verification=c9680cb5-881b-4f8b-a803-42a918cdcf57",
      "openai-domain-verification=dv-NFgbKpjTQ0ahyMXgoAHmOxJY",
      "8cm9gxpghxsp9574p1nz7qyvfnsp7j8p",
      "apple-domain-verification=AB3LxniJsUaLUcY5HvdpX1R8DTt0wK00TTlz9bLWYqA",
      "00Dam00001aB64r=1TBWj0000000NpR",
      "596hdfxvpnrhgnb5h0rd9jmpy5dgnmxm",
      "webexdomainverification.4faf3ee01037479be053ad06fc0aecb4=d1b282f3-54e0-4575-9fac-cfd9a87b4d3b",
      "google-site-verification=2-satGFR6KHGOFKHt9pAAhY4xpgq1pmusepMak2uuFw",
      "mtdg5mrgrnvpqfxgzd0cyl6281w2qd83",
      "lptj19vv8ny9w6g7x730jr81fwjj5js1",
      "MS=ms46230291",
      "mailigen-site-verification=58788cc4908d5697c6ea4801a7fea3f6",
      "onetrust-domain-verification=94a8e142562349faa2ba5529c6cbdc30",
      "MagCfj2QvpMlValiiUpfiQk20jX6TQiVe2kRGvpC9oO5ndpTc5Lg2Rp4EPVYKjvIb/8f4U5tRMD8uqIuaYRh8g==",
      "rbdnz94w8kspd08l35ddj10s25lzfsn3",
      "teamviewer-sso-verification=2b7c86a77be24f7b8573b688a8e22e12",
      "rzp-site-verification=e96209bbed5b907c3f31ee1eb7007f52",
      "domain-verification-yrjjcd=ej6XWEu0ENbzDBfGT2ApwOA9u",
      "1pq0y02mf1v1m7k3lr86vyxmy4y2c68b",
      "ZOOM_verify_8gBBD3UzStWKA3mt6lwsTA",
      "ciscocidomainverification=5fdcd1977e45fc341a83e8f8c0149146995952cd51fb04a9d1b950717f6e5647",
      "2417050a-133b-4a53-8378-68e5c05da937",
      "amazonses:SJniAvY8SFy0o9cZGRDXV8eDcQ5oyo+QNtLHM37omUY=",
      "duo_sso_verification=TzxwSiyiqBThbUymIdN9VVIm6xPyKGCFQZZX6Gt8DBsSqPlhDgAz8H4maEwMKEZo",
      "yandex-verification:",
      "050a0e32621f5209"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email; fo=1; ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "commonName=nvidia.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M01",
    "notBefore": "Sep 20 00:00:00 2026 GMT",
    "notAfter": "Apr  5 23:59:59 2027 GMT",
    "san": [
      "nvidia.com",
      "*.nvidia.ae",
      "*.nvidia.trade",
      "*.nvidia.world",
      "*.nvidia.video",
      "*.nvidia.luxe",
      "*.nvidia.email",
      "*.nvidia.sucks",
      "*.nvidia.site",
      "*.nvidia.ie",
      "nvidia.dk",
      "nvidia.co.in",
      "*.nvidia.university",
      "nvidia.de",
      "nvidia.com.pl",
      "nvidia.cz",
      "nvidia.bid",
      "*.nvidia.bid",
      "nvidia.co.id",
      "*.nvidia.computer",
      "nvidia.graphics",
      "*.nvidia.sex",
      "nvidia.org",
      "nvidia.info",
      "nvidia.inc",
      "*.nvidia.support",
      "nvidia.wiki",
      "nvidia.email",
      "nvidia.com.br",
      "*.nvidia.com.pl",
      "*.nvidia.company",
      "nvidia.university",
      "nvidia.video",
      "*.nvidia.co.uk",
      "nvidia.world",
      "nvidia.news",
      "nvidia.technology",
      "nvidia.eu",
      "*.nvidea.com",
      "*.nvidia.software",
      "nvidia.com.ua",
      "*.nvidia.info",
      "*.nvidia.co.at",
      "nvidia.ae",
      "*.nvidia.eu",
      "nvidia.net",
      "*.nvidia.net",
      "nvidia.ie",
      "*.nvidia.co.jp",
      "*.nvidia.de",
      "*.nvidia.foundation",
      "*.nvidia.news",
      "*.nvidia.dk",
      "*.nvidia.com",
      "*.nvidia.com.br",
      "nvidia.com.tr",
      "nvidia.co.uk",
      "nvidia.computer",
      "*.nvidia.cz",
      "nvidia.trade",
      "*.nvidia.graphics",
      "nvidia.foundation",
      "nvidia.press",
      "nvidia.ch",
      "nvidia.co.jp",
      "nvidia.site",
      "*.nvidia.global",
      "nvidia.games",
      "nvidia.company",
      "*.nvidia.ch",
      "nvidia.support",
      "nvidia.cn",
      "nvidia.ca",
      "*.nvidia.technology",
      "nvidia.sucks",
      "*.nvidia.cn",
      "nvidia.sex",
      "*.nvidia.org",
      "nvidia.software",
      "*.nvidia.inc",
      "nvidia.co.at",
      "*.nvidia.com.tr",
      "*.nvidia.ca",
      "nvidia.luxe",
      "nvidia.jp",
      "nvidia.global",
      "*.nvidia.jp",
      "*.nvidia.games",
      "*.nvidia.press",
      "*.nvidia.co.id",
      "*.nvidia.com.ua",
      "nvidia.be",
      "*.nvidia.at",
      "nvidea.com",
      "*.nvidia.wiki",
      "*.nvidia.co.in",
      "nvidia.at"
    ],
    "days_left": 191,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "34.194.97.138",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: nginx"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.nvidia.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.nvidia.com/"
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
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "xmind-domain-verification-fzhrb5=2CDgcQwEk3L1j2txLkWniBSnO",
    "google-site-verification=Bgm4VneS70f1CGZKg-D3tGoEQYxxHm56CH1v8frb1OA",
    "airtable-verification=d6d9ca2bacc2c108daad98a586ea9ae7",
    "webexdomainverification.JUIU=a2070f62-2329-43d5-a745-0506cd1e0be8",
    "webexdomainverification.4C675B8BC9F4B136E053AB06FC0A3F65=7bca8485-5ef5-41d8-9095"
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
      "aia_ocsp": "http://ocsp.r2m01.amazontrust.com",
      "serial": 10290283466661156354206296003778550678,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m01.amazontrust.com/r2m01.crl"
      ],
      "subject_dn": "311330110603550403130a6e76696469612e636f6d",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3031",
      "not_before": "20260920000000",
      "not_after": "20270405235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/content/g/*",
      "/content/gated-pdfs/*",
      "/content/*/gated-resources/*",
      "/content/*/gated-pdfs/*",
      "/gated-resources/*",
      "/*?topicPage=",
      "/*&topicPage=",
      "/*?commentPage=",
      "/*&commentPage=",
      "/*/training/academy/auth/",
      "/*/training/academy/login/",
      "/admin/",
      "/attach/",
      "/content/experience-fragments/*",
      "/content/forms/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-34-194-97-138.compute-1.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.nvidia.com/",
    "http_status": 301,
    "p404_status": 301,
    "stapling": "not-offered",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "crl": {
      "url": "http://crl.r2m01.amazontrust.com/r2m01.crl",
      "status": 200
    }
  },
  "elapsed_s": 46.7,
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
