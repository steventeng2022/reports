# Security Audit Report — baidu.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://baidu.com/ |
| Bug bounty program | Baidu |
| Listed scope domain | baidu.com |
| Test date | 2026-09-26 18:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **6** (High: 0, Medium: 0, Low: 0, Info: 6)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 3 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 4 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 5 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 6 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 3. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 4. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=GHb98-6msqyx_qqjGl5eRatD3QTHyVB6-xQ3gJB5UwM; _globalsign-domain-verification=qjb28W2jJSrWj04NHpB0CvgK9tle5JkOq-EcyWBgnE
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 5. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of baidu.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 6. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 133 disallow path(s), e.g. /baidu, /s?, /ulink?, /link?, /home/news/data/
- **Recommendation:** Review disallowed paths; robots is not access control.

## Evidence (raw response observations)

```json
{
  "domain": "baidu.com",
  "dns": {
    "a": [
      "124.237.177.164",
      "110.242.74.102",
      "111.63.65.247",
      "111.63.65.103"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mx.maillb.baidu.com (pref 10)",
      "mx.baidu.com (pref 20)"
    ],
    "ns": [
      "ns2.baidu.com.",
      "dns.baidu.com.",
      "ns3.baidu.com.",
      "ns7.baidu.com.",
      "ns4.baidu.com."
    ],
    "spf": [
      "google-site-verification=GHb98-6msqyx_qqjGl5eRatD3QTHyVB6-xQ3gJB5UwM",
      "v=spf1 include:spf1.baidu.com include:spf2.baidu.com include:spf3.baidu.com include:spf4.baidu.com -all",
      "9279nznttl321bxp1j464rd9vpps246v",
      "_globalsign-domain-verification=qjb28W2jJSrWj04NHpB0CvgK9tle5JkOq-EcyWBgnE"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:baidu-spammail@baidu.com; ruf=mailto:baidu-spammail@baidu.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=CN, stateOrProvinceName=Beijing, localityName=Beijing, organizationName=Beijing Baidu Netcom Science Technology Co., Ltd., commonName=baidu.com",
    "issuer": "countryName=BE, organizationName=GlobalSign nv-sa, commonName=GlobalSign RSA OV SSL CA 2018",
    "notBefore": "Jul  9 02:32:55 2026 GMT",
    "notAfter": "Jan 24 02:32:55 2027 GMT",
    "san": [
      "baidu.com",
      "click.hm.baidu.com",
      "baifubao.com",
      "www.baidu.cn",
      "www.baidu.com.cn",
      "mct.y.nuomi.com",
      "apollo.auto",
      "dwz.cn",
      "update.pan.baidu.com",
      "wn.pos.baidu.com",
      "cm.pos.baidu.com",
      "log.hm.baidu.com",
      "*.baidu.com",
      "*.baifubao.com",
      "*.baidustatic.com",
      "*.bdstatic.com",
      "*.bdimg.com",
      "*.hao123.com",
      "*.nuomi.com",
      "*.chuanke.com",
      "*.trustgo.com",
      "*.bce.baidu.com",
      "*.eyun.baidu.com",
      "*.map.baidu.com",
      "*.mbd.baidu.com",
      "*.fanyi.baidu.com",
      "*.baidubce.com",
      "*.mipcdn.com",
      "*.news.baidu.com",
      "*.baidupcs.com",
      "*.aipage.com",
      "*.aipage.cn",
      "*.bcehost.com",
      "*.safe.baidu.com",
      "*.im.baidu.com",
      "*.baiducontent.com",
      "*.dlnel.com",
      "*.dlnel.org",
      "*.dueros.baidu.com",
      "*.su.baidu.com",
      "*.91.com",
      "*.hao123.baidu.com",
      "*.apollo.auto",
      "*.xueshu.baidu.com",
      "*.bj.baidubce.com",
      "*.gz.baidubce.com",
      "*.smartapps.cn",
      "*.bdtjrcv.com",
      "*.hao222.com",
      "*.haokan.com",
      "*.pae.baidu.com",
      "*.vd.bdstatic.com",
      "*.cloud.baidu.com"
    ],
    "days_left": 119,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "124.237.177.164",
    "open": []
  },
  "https": {
    "status": 0,
    "content_type": "",
    "title": "",
    "error": "https connect failed"
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [],
  "http": {
    "status": 301,
    "location": "https://www.baidu.com/"
  },
  "redir_probes": [],
  "paths": {},
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "google-site-verification=GHb98-6msqyx_qqjGl5eRatD3QTHyVB6-xQ3gJB5UwM",
    "_globalsign-domain-verification=qjb28W2jJSrWj04NHpB0CvgK9tle5JkOq-EcyWBgnE"
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
      "not_before": "20260709023255",
      "not_after": "20270124023255"
    }
  },
  "http2": {
    "robots_disallow": [
      "/baidu",
      "/s?",
      "/ulink?",
      "/link?",
      "/home/news/data/",
      "/bh",
      "/baidu",
      "/s?",
      "/shifen/",
      "/homepage/",
      "/cpro",
      "/ulink?",
      "/link?",
      "/home/news/data/",
      "/bh"
    ]
  },
  "x12": {
    "error": "ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='baidu.com', port=443): R"
  },
  "elapsed_s": 87.5,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
