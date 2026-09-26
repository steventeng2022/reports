# Security Audit Report — cancerresearchuk.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cancerresearchuk.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cancerresearchuk.org |
| Test date | 2026-09-26 23:21 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **23** (High: 0, Medium: 0, Low: 5, Info: 18)

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
| 20 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 21 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 22 | info | CT1 | 328 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 23 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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
- **Detail:** Apex TXT records with verification/token content: apple-domain-verification=ZIfJE9Gth65P2EaS; apple-domain-verification=IGJmYB4ReQOvnh8C421oNRDVuu5D-eZofJf6Y97qPBU; facebook-domain-verification=4hzy2r2nmzkhsj084cd7fki46jeaa3
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://ocsp.r2m04.amazontrust.com -> http-403
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 75 disallow path(s), e.g. /utilities/glossary/, /*PrinterFriendly, */prod_consump/, /support-us/, /cancer-subject/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] Reverse-DNS (PTR) fingerprint of apex IP (`PTR1`)

- **CWE:** CWE-200
- **Detail:** 18.132.167.245 carries PTR ec2-18-132-167-245.eu-west-2.compute.amazonaws.com. for cancerresearchuk.org.
- **Recommendation:** PTR labels can leak hosting/asset naming; review for internal-hostname exposure.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for cancerresearchuk.org, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] OCSP stapling not offered (cert has an OCSP URL) (`TLS19`)

- **CWE:** CWE-298
- **Detail:** The cancerresearchuk.org certificate lists an AIA OCSP responder (http://ocsp.r2m04.amazontrust.com) but no certificate_status extension was observed in a TLS 1.2 handshake; clients must query the CA themselves (or skip revocation checks).
- **Recommendation:** Enable OCSP stapling (e.g. ssl_stapling) so revocation status is served without client->CA round-trips.

### 20. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on cancerresearchuk.org is 'awselb/2.0' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 21. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on cancerresearchuk.org lists 2 <loc> URL(s) across 3 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 22. [INFO] 328 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.events.cancerresearchuk.org, admin.fundraise.cancerresearchuk.org, api.activities.cancerresearchuk.org, api.activity.cancerresearchuk.org, api.discounts.cancerresearchuk.org, api.events.cancerresearchuk.org, api.fundraise.cancerresearchuk.org, assets.cancerchat.cancerresearchuk.org, assets.fundraise.cancerresearchuk.org, auth.activities.cancerresearchuk.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 23. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: api.activity.cancerresearchuk.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "cancerresearchuk.org",
  "dns": {
    "a": [
      "18.132.167.245",
      "18.133.42.18",
      "18.171.47.200"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "cancerresearchuk-org.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-33.awsdns-04.com.",
      "ns-1410.awsdns-48.org.",
      "ns-1773.awsdns-29.co.uk.",
      "ns-885.awsdns-46.net."
    ],
    "caa": [],
    "spf": [
      "apple-domain-verification=ZIfJE9Gth65P2EaS",
      "g07kykmlvhp2d8vfzjxm1shy9n35w7nv",
      "fn1b7vvmlhfpmf35rchfpz383tm1bndy",
      "vc6k1223ptdlchvpy3s18lq144xv1slj",
      "m1rh31jnyk8f4zy25vlb01nmv62x0l9p",
      "_ly5k70e1l8gd1shizgsvpgha4v9m2ut",
      "f9w7nn10vpy421nnf3pqmfsgth5pq3hq",
      "wf7338jyn6pqbdzrjwlwtb841r6dh0hd",
      "mzm32j62qpf6tkkydk6p0ph763nnjhsp",
      "v1n0kqhknmzc5fsg2zf7tsn4780hmj1m",
      "apple-domain-verification=IGJmYB4ReQOvnh8C421oNRDVuu5D-eZofJf6Y97qPBU",
      "hpc5sj1r9xplb20nd3q43m1bzdhpb85j",
      "cglw6w22gnjt39h39kgr4wf62r05rt02",
      "facebook-domain-verification=4hzy2r2nmzkhsj084cd7fki46jeaa3",
      "wpv0g4gkpbw0kqrlm6jlrb2bxw3zd0v0",
      "_wlakz6emublsj5fvgjt8dl2i84ycrmq",
      "zdcmc5v22rdy0s5tc80j5xwl1ygcbf6g",
      "m1gfkdpv7rscd8mr64mw9wcxtsrxh0ds",
      "s50n3srkhkz08lqgjwt4zj6zrjsxnbn4",
      "5cfht3mshcf3trp03bh7jrkqcv6ddg69",
      "bnslp7wjbc8v3n5wkdr8hxl5l8fxr2hl",
      "bv1by0fvhbpznqy9xqmzr6z10lghjjgg",
      "24zprsdb1b3ync7ywmsypc3vvn70cb95",
      "dr0t5jj72k4t61lk8ffs081fj6rghv6n",
      "_exbcbqu4yx5x3py9lyawkwfuxanm7sj",
      "y9ncngdcvrvk16m4gljshc7gvhhxh8lc",
      "facebook-domain-verification=61rl1f9boyjhytks0jdex0hncnayfr",
      "g1fh5zpwprcz6cn2rq5gblvsb7lwx2t7",
      "x54b24q04j1j22dz1mvbjqzv9r9pk876",
      "d4tgqmcxcgtg2plddnyjvcqtpdyypf12",
      "rm_verify=b5ea71cdcf",
      "google-site-verification=PHwtSX75UKqvpzyPHmk4bGBzczkPu71eNXBD-GyiKbw",
      "ss0bz7586fsg4xxdmsyjqt8jcgyg8zrx",
      "x1whvwl6r9qqx6y8z1dnvk64lkbbzfqx",
      "6sqc01vxxxwzn49y5jd2p6wxdq5f7z3q",
      "s4bfybvmkvmrjl1lnmbtl3khph6h0vvb",
      "26m8th96q9myjm4zz46h7r7cvbwbwjh4",
      "bd66lyr72y3lq95qw2314t8vcy16lwps",
      "y468410l6rk4ybc5dnyrqnr1ycsmr58j",
      "40z41kzn43jd310vq6v9k622x3v9fxkx",
      "_lvx2syhktdeoxcx6mo6b51u3h1usqwx",
      "MS=ms18612172",
      "hgyx98b9cc79ztr03qm7h7qlsgl7wlyr",
      "1tn2p2x86m2jvp6wjvh9n8kf197vtmmd",
      "1ly9mvl98241ksqyw929gldgyy46f27c",
      "khdfh0nr2q0wr7563tcm7b5pfq068q5y",
      "nnp90zxqqzmkn93bwvhdl46dwvfp0v3y",
      "zzhv3bsz0x6y1hglhy4wxp3pvz2rw432",
      "6q77047g56cblw7j2h9j1bgxdfth47fl",
      "0v1c9bt4vwkdmptx84wzz413s3xsc990",
      "ww43j1bp5rmj9lgjwr0x73qbpl0mj8yf",
      "v=spf1 include:em9792.cancerresearchuk.org include:spf.protection.outlook.com include:amazonses.com -all",
      "_qydnb71cn3lqycnc1mtenmuxez97jlp",
      "7d705306nddqnj1fppb3btq58hrlrjtx",
      "6b7bv6ky1d5gbp66fgqkqhcdj7n4z04l",
      "_e8bqk4zyvefuarzhyy6hu9bizyu1ny7",
      "3rl4ld7tjl4sbpy967j2cr7y48vbxcxn",
      "7msqnpj5xr4y5syw9g44m95dfl44hjgx",
      "google-site-verification=c1Vsqct8unmvZEnNTtoZZ_dDsq-qejygwotuVnfoupY",
      "_w8opp2p377zo21qi6gh2zwgfe2bmmpa",
      "_i6zwxvcptwz9qmphgqpvbhyog72fmuo",
      "_6vt5j2zihy4gglxz8kvsmr9pq7h2a4c",
      "7g4q3fqrptyjf17dzs4js241j4v67c6t",
      "vnm8g3svr0c67s4xmgld8q209cc68364S",
      "_gu3tif2ur9nnozx0ckdgutzqdo8p38j",
      "np13rn98h5lpgjbndhr5gn31363b8xy0",
      "45qbtsvh8vd17n794pf4cpj7z8zwk0tj",
      "vxqr9nqtmryh46zfq0jqwjx316764nsk"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:65fc433b5864b@ag.dmarcly.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=www.cancerresearchuk.org",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Aug 13 00:00:00 2026 GMT",
    "notAfter": "Feb 26 23:59:59 2027 GMT",
    "san": [
      "www.cancerresearchuk.org",
      "*.cancerresearchuk.org",
      "*.raceforlife.cancerresearchuk.org",
      "cancerresearchuk.org"
    ],
    "days_left": 153,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "18.132.167.245",
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
      "origin": "https://sub.cancerresearchuk.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://cancerresearchuk.org:443/"
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
    "source": "crt.sh",
    "count": 328,
    "notable": [
      "admin.events.cancerresearchuk.org",
      "admin.fundraise.cancerresearchuk.org",
      "api.activities.cancerresearchuk.org",
      "api.activity.cancerresearchuk.org",
      "api.discounts.cancerresearchuk.org",
      "api.events.cancerresearchuk.org",
      "api.fundraise.cancerresearchuk.org",
      "assets.cancerchat.cancerresearchuk.org",
      "assets.fundraise.cancerresearchuk.org",
      "auth.activities.cancerresearchuk.org",
      "auth.cancerresearchuk.org",
      "ecards.shop.cancerresearchuk.org",
      "gitlab.cancerresearchuk.org",
      "jira.cancerresearchuk.org",
      "jobs.cancerresearchuk.org"
    ],
    "sample": [
      "aa2.raceforlife.cancerresearchuk.org",
      "about-cancer.cancerresearchuk.org",
      "aboutus.cancerresearchuk.org",
      "account.cancerresearchuk.org",
      "action.cancerresearchuk.org",
      "activities.cancerresearchuk.org",
      "activity.cancerresearchuk.org",
      "admin.events.cancerresearchuk.org",
      "admin.fundraise.cancerresearchuk.org",
      "allmacro.cancerresearchuk.org",
      "alwaysonvpn.cancerresearchuk.org",
      "ambassadormap.cancerresearchuk.org",
      "amplify.fundraise.cancerresearchuk.org",
      "ams.cancerresearchuk.org",
      "amws.cancerresearchuk.org",
      "api.activities.cancerresearchuk.org",
      "api.activity.cancerresearchuk.org",
      "api.discounts.cancerresearchuk.org",
      "api.events.cancerresearchuk.org",
      "api.fundraise.cancerresearchuk.org"
    ],
    "dangling": [
      "api.activity.cancerresearchuk.org"
    ]
  },
  "apex_txt": [
    "apple-domain-verification=ZIfJE9Gth65P2EaS",
    "apple-domain-verification=IGJmYB4ReQOvnh8C421oNRDVuu5D-eZofJf6Y97qPBU",
    "facebook-domain-verification=4hzy2r2nmzkhsj084cd7fki46jeaa3",
    "facebook-domain-verification=61rl1f9boyjhytks0jdex0hncnayfr",
    "google-site-verification=PHwtSX75UKqvpzyPHmk4bGBzczkPu71eNXBD-GyiKbw"
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
      "aia_ocsp": "http://ocsp.r2m04.amazontrust.com",
      "serial": 7753095356988335536171050034728758678,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.r2m04.amazontrust.com/r2m04.crl"
      ],
      "subject_dn": "3121301f060355040313187777772e63616e6365727265736561726368756b2e6f7267",
      "issuer_dn": "310b3009060355040613025553310f300d060355040a1306416d617a6f6e311c301a06035504031313416d617a6f6e205253412032303438204d3034",
      "not_before": "20260813000000",
      "not_after": "20270226235959"
    },
    "ocsp": "http-403"
  },
  "http2": {
    "robots_disallow": [
      "/utilities/glossary/",
      "/*PrinterFriendly",
      "*/prod_consump/",
      "/support-us/",
      "/cancer-subject/",
      "/career-level/",
      "/client/",
      "/content/",
      "/container-type/",
      "/content-department/",
      "/country/",
      "/event-type/",
      "/file/",
      "/file.html",
      "/gift-calculator-ranges/"
    ]
  },
  "x12": {
    "status": 301,
    "ptr": [
      "ec2-18-132-167-245.eu-west-2.compute.amazonaws.com."
    ]
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.cancerresearchuk.org:443/",
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
    "sitemap": {
      "urls": 2,
      "indexes": 3
    },
    "crl": {
      "url": "http://crl.r2m04.amazontrust.com/r2m04.crl",
      "status": 200
    }
  },
  "elapsed_s": 35.4,
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
