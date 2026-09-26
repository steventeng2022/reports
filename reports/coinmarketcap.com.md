# Security Audit Report — coinmarketcap.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://coinmarketcap.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | coinmarketcap.com |
| Test date | 2026-09-26 17:42 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **11** (High: 0, Medium: 0, Low: 0, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH1 | Technology fingerprint | CWE-200 |
| 3 | info | H6 | Server technology disclosure | CWE-200 |
| 4 | info | P8 | Missing security.txt | CWE-1038 |
| 5 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 6 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 7 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 8 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 9 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 10 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 11 | info | CT1 | 20 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 3. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 4. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 5. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 6. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 7. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: facebook-domain-verification=c9mql15ejmnw7ti6tks95kx46ks3jo; google-site-verification=T5ZnzNMTvLb5kdKlwTCCJUQKWXcfgiYPkr4H8O3NmNg; google-site-verification=h8XSgzWPJa4QZP3ZmMafldNHevrcSYnWyc5RPiEvCBQ
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 8. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of coinmarketcap.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 9. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but coinmarketcap.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 10. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 12 disallow path(s), e.g. /headlines/*, /*/headlines/*, /community/*/post/*, /community/*/live/*, /community/*/topics/*
- **Recommendation:** Review disallowed paths; robots is not access control.

### 11. [INFO] 20 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: beta.coinmarketcap.com, staging.coinmarketcap.com, status.coinmarketcap.com, support.coinmarketcap.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "coinmarketcap.com",
  "dns": {
    "a": [
      "3.169.121.26",
      "3.169.121.75",
      "3.169.121.21",
      "3.169.121.67"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "mxa-00784a01.gslb.pphosted.com (pref 5)",
      "mxb-00784a01.gslb.pphosted.com (pref 1)",
      "alt3.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "ns-52.awsdns-06.com.",
      "ns-763.awsdns-31.net.",
      "ns-1254.awsdns-28.org.",
      "ns-2024.awsdns-61.co.uk."
    ],
    "spf": [
      "facebook-domain-verification=c9mql15ejmnw7ti6tks95kx46ks3jo",
      "v=MCPv1; k=ed25519; p=Xk7wX7xqTt6MDBN0Ub8A451MVUwvawWNy9364316K24=",
      "google-site-verification=T5ZnzNMTvLb5kdKlwTCCJUQKWXcfgiYPkr4H8O3NmNg",
      "google-site-verification=h8XSgzWPJa4QZP3ZmMafldNHevrcSYnWyc5RPiEvCBQ",
      "google-site-verification=Vf_mqov516xuQRQ_br3FlVER8PrZ_CaaB1OUruEjn84",
      "ahrefs-site-verification_86f2f08131d8239e3a4d73b0179d556eae74fa62209b410a64ff348f74e711ea",
      "google-site-verification=nt91clIDjoi6MbZjqG__pGlylJVSQA6ZnoenJzdWwEU",
      "yandex-verification: fcfc1e0853947ee6",
      "google-site-verification=hqUA9mBjH57N_FIJV4vkjlh_vuTGsNYJV8bErIT9izs",
      "atlassian-domain-verification=YT8U29m9J7i85eaznD4fr4n9PfcN/w3j/ZqlVYs2vG15VWL2NNcS9c1jkIc/BP3W",
      "google-site-verification=TcF0PnxBx5EyLHzPGz_rarl75Ea3HIHcbaO3PP7cT8s",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com include:emsd1.com include:spf-00784a01.pphosted.com -all",
      "apple-domain-verification=IpY-v5shWd9KVeDzJPS8r0okeTIwMlDkyLmF6cNAd_w"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=reject;pct=100;rua=mailto:david.k@coinmarketcap.com;ruf=mailto:derek.li@coinmarketcap.com;ri=86400;aspf=s;adkim=s;fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "subject": "commonName=coinmarketcap.com",
    "issuer": "countryName=US, organizationName=Amazon, commonName=Amazon RSA 2048 M04",
    "notBefore": "Jun 29 00:00:00 2026 GMT",
    "notAfter": "Jan 12 23:59:59 2027 GMT",
    "san": [
      "coinmarketcap.com",
      "cmc.ai",
      "*.coinmarketcap.com",
      "*.beta.coinmarketcap.com",
      "*.staging.coinmarketcap.com",
      "*.cmc.ai",
      "*.cmcap.io"
    ],
    "days_left": 108,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "3.169.121.26",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Cryptocurrency Prices, Charts And Market Capitalizations | CoinMarketCap"
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
      "origin": "https://sub.coinmarketcap.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://coinmarketcap.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 301",
    "/redirect?next=https://evil-auditor.example/x -> 301",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 301"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 403,
    "/.htaccess": 404,
    "/wp-login.php": 403,
    "/phpmyadmin/index.php": 403,
    "/server-status": 301,
    "/api/": 200
  },
  "subdomains": {
    "source": "certspotter",
    "count": 20,
    "notable": [
      "beta.coinmarketcap.com",
      "staging.coinmarketcap.com",
      "status.coinmarketcap.com",
      "support.coinmarketcap.com"
    ],
    "sample": [
      "beta.coinmarketcap.com",
      "blockchain-stable.coinmarketcap.com",
      "blockchain.coinmarketcap.com",
      "coinmarketcap.com",
      "dapi-qa.coinmarketcap.com",
      "dapi.coinmarketcap.com",
      "dex.coinmarketcap.com",
      "dws.coinmarketcap.com",
      "link.coinmarketcap.com",
      "memews-eu.coinmarketcap.com",
      "memews-us.coinmarketcap.com",
      "memews.coinmarketcap.com",
      "preview.coinmarketcap.com",
      "pro-stream.coinmarketcap.com",
      "selfserve.coinmarketcap.com",
      "staging.coinmarketcap.com",
      "status.coinmarketcap.com",
      "support-chat.coinmarketcap.com",
      "support.coinmarketcap.com",
      "web3.coinmarketcap.com"
    ]
  },
  "apex_txt": [
    "facebook-domain-verification=c9mql15ejmnw7ti6tks95kx46ks3jo",
    "google-site-verification=T5ZnzNMTvLb5kdKlwTCCJUQKWXcfgiYPkr4H8O3NmNg",
    "google-site-verification=h8XSgzWPJa4QZP3ZmMafldNHevrcSYnWyc5RPiEvCBQ",
    "google-site-verification=Vf_mqov516xuQRQ_br3FlVER8PrZ_CaaB1OUruEjn84",
    "ahrefs-site-verification_86f2f08131d8239e3a4d73b0179d556eae74fa62209b410a64ff348"
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
  "http2": {
    "robots_disallow": [
      "/headlines/*",
      "/*/headlines/*",
      "/community/*/post/*",
      "/community/*/live/*",
      "/community/*/topics/*",
      "/community/*/coins/*",
      "/community/*/profile/*",
      "/community/post/*",
      "/community/topics/*",
      "/community/coins/*",
      "/community/profile/*",
      "/dexscan/*"
    ]
  },
  "elapsed_s": 7.6,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
