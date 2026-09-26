# Security Audit Report — cancerresearchuk.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://cancerresearchuk.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | cancerresearchuk.org |
| Test date | 2026-09-25 23:12 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 5, Info: 8)

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
| 12 | info | CT1 | 328 hostnames found via Certificate Transparency (crt.sh) | CWE-200 |
| 13 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

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

### 12. [INFO] 328 hostnames found via Certificate Transparency (crt.sh) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.events.cancerresearchuk.org, admin.fundraise.cancerresearchuk.org, api.activities.cancerresearchuk.org, api.activity.cancerresearchuk.org, api.discounts.cancerresearchuk.org, api.events.cancerresearchuk.org, api.fundraise.cancerresearchuk.org, assets.cancerchat.cancerresearchuk.org, assets.fundraise.cancerresearchuk.org, auth.activities.cancerresearchuk.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 13. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: api.activity.cancerresearchuk.org; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "cancerresearchuk.org",
  "dns": {
    "a": [
      "51.24.206.15",
      "18.132.167.245",
      "18.133.42.18"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "cancerresearchuk-org.mail.protection.outlook.com (pref 5)"
    ],
    "ns": [
      "ns-1410.awsdns-48.org.",
      "ns-33.awsdns-04.com.",
      "ns-885.awsdns-46.net.",
      "ns-1773.awsdns-29.co.uk."
    ],
    "spf": [
      "_exbcbqu4yx5x3py9lyawkwfuxanm7sj",
      "hgyx98b9cc79ztr03qm7h7qlsgl7wlyr",
      "ww43j1bp5rmj9lgjwr0x73qbpl0mj8yf",
      "1tn2p2x86m2jvp6wjvh9n8kf197vtmmd",
      "45qbtsvh8vd17n794pf4cpj7z8zwk0tj",
      "6sqc01vxxxwzn49y5jd2p6wxdq5f7z3q",
      "MS=ms18612172",
      "7g4q3fqrptyjf17dzs4js241j4v67c6t",
      "d4tgqmcxcgtg2plddnyjvcqtpdyypf12",
      "nnp90zxqqzmkn93bwvhdl46dwvfp0v3y",
      "g07kykmlvhp2d8vfzjxm1shy9n35w7nv",
      "26m8th96q9myjm4zz46h7r7cvbwbwjh4",
      "apple-domain-verification=IGJmYB4ReQOvnh8C421oNRDVuu5D-eZofJf6Y97qPBU",
      "x1whvwl6r9qqx6y8z1dnvk64lkbbzfqx",
      "fn1b7vvmlhfpmf35rchfpz383tm1bndy",
      "v=spf1 include:em9792.cancerresearchuk.org include:spf.protection.outlook.com include:amazonses.com -all",
      "f9w7nn10vpy421nnf3pqmfsgth5pq3hq",
      "1ly9mvl98241ksqyw929gldgyy46f27c",
      "zzhv3bsz0x6y1hglhy4wxp3pvz2rw432",
      "_wlakz6emublsj5fvgjt8dl2i84ycrmq",
      "wpv0g4gkpbw0kqrlm6jlrb2bxw3zd0v0",
      "y9ncngdcvrvk16m4gljshc7gvhhxh8lc",
      "_w8opp2p377zo21qi6gh2zwgfe2bmmpa",
      "_i6zwxvcptwz9qmphgqpvbhyog72fmuo",
      "g1fh5zpwprcz6cn2rq5gblvsb7lwx2t7",
      "bd66lyr72y3lq95qw2314t8vcy16lwps",
      "y468410l6rk4ybc5dnyrqnr1ycsmr58j",
      "khdfh0nr2q0wr7563tcm7b5pfq068q5y",
      "cglw6w22gnjt39h39kgr4wf62r05rt02",
      "wf7338jyn6pqbdzrjwlwtb841r6dh0hd",
      "_6vt5j2zihy4gglxz8kvsmr9pq7h2a4c",
      "_qydnb71cn3lqycnc1mtenmuxez97jlp",
      "6q77047g56cblw7j2h9j1bgxdfth47fl",
      "40z41kzn43jd310vq6v9k622x3v9fxkx",
      "m1gfkdpv7rscd8mr64mw9wcxtsrxh0ds",
      "vnm8g3svr0c67s4xmgld8q209cc68364S",
      "google-site-verification=PHwtSX75UKqvpzyPHmk4bGBzczkPu71eNXBD-GyiKbw",
      "bnslp7wjbc8v3n5wkdr8hxl5l8fxr2hl",
      "rm_verify=b5ea71cdcf",
      "s50n3srkhkz08lqgjwt4zj6zrjsxnbn4",
      "bv1by0fvhbpznqy9xqmzr6z10lghjjgg",
      "0v1c9bt4vwkdmptx84wzz413s3xsc990",
      "ss0bz7586fsg4xxdmsyjqt8jcgyg8zrx",
      "s4bfybvmkvmrjl1lnmbtl3khph6h0vvb",
      "6b7bv6ky1d5gbp66fgqkqhcdj7n4z04l",
      "x54b24q04j1j22dz1mvbjqzv9r9pk876",
      "vc6k1223ptdlchvpy3s18lq144xv1slj",
      "7d705306nddqnj1fppb3btq58hrlrjtx",
      "7msqnpj5xr4y5syw9g44m95dfl44hjgx",
      "_lvx2syhktdeoxcx6mo6b51u3h1usqwx",
      "_ly5k70e1l8gd1shizgsvpgha4v9m2ut",
      "m1rh31jnyk8f4zy25vlb01nmv62x0l9p",
      "5cfht3mshcf3trp03bh7jrkqcv6ddg69",
      "google-site-verification=c1Vsqct8unmvZEnNTtoZZ_dDsq-qejygwotuVnfoupY",
      "3rl4ld7tjl4sbpy967j2cr7y48vbxcxn",
      "_gu3tif2ur9nnozx0ckdgutzqdo8p38j",
      "hpc5sj1r9xplb20nd3q43m1bzdhpb85j",
      "apple-domain-verification=ZIfJE9Gth65P2EaS",
      "zdcmc5v22rdy0s5tc80j5xwl1ygcbf6g",
      "24zprsdb1b3ync7ywmsypc3vvn70cb95",
      "vxqr9nqtmryh46zfq0jqwjx316764nsk",
      "facebook-domain-verification=4hzy2r2nmzkhsj084cd7fki46jeaa3",
      "v1n0kqhknmzc5fsg2zf7tsn4780hmj1m",
      "facebook-domain-verification=61rl1f9boyjhytks0jdex0hncnayfr",
      "dr0t5jj72k4t61lk8ffs081fj6rghv6n",
      "_e8bqk4zyvefuarzhyy6hu9bizyu1ny7",
      "np13rn98h5lpgjbndhr5gn31363b8xy0",
      "mzm32j62qpf6tkkydk6p0ph763nnjhsp"
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
    "days_left": 154,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "51.24.206.15",
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
  "elapsed_s": 30.1,
  "rechecked": "2026-09-25 23:12 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
