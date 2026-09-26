# Security Audit Report — creativemarket.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://creativemarket.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | creativemarket.com |
| Test date | 2026-09-26 17:42 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 1, Info: 11)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 6 | info | H6 | Server technology disclosure | CWE-200 |
| 7 | info | P8 | Missing security.txt | CWE-1038 |
| 8 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 9 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 10 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 11 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 12 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.27.236:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.27.236:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 6. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 7. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 8. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 9. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 10. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (o0qnkm911nx7kn.creativemarket.com and xa4ie2otb8f4tg.creativemarket.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 11. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=o06UtMir6spz9U81R1jgVspJe-h2SQL3l25JWXHO-No; google-site-verification=_1Bh-ba5uJAVphxjDQOE5JrTSGn7qPy-scJOuB8Fn2c; google-site-verification=9dM4OOkYQ1jgIlhAh9QwY1smcki10zvmPcAilwsn984
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 12. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of creativemarket.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "creativemarket.com",
  "dns": {
    "a": [
      "104.18.27.236",
      "104.18.26.236"
    ],
    "aaaa": [
      "2606:4700::6812:1bec",
      "2606:4700::6812:1aec"
    ],
    "cname": null,
    "mx": [
      "alt1.aspmx.l.google.com (pref 5)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt4.aspmx.l.google.com (pref 10)"
    ],
    "ns": [
      "simone.ns.cloudflare.com.",
      "ram.ns.cloudflare.com."
    ],
    "spf": [
      "google-site-verification=o06UtMir6spz9U81R1jgVspJe-h2SQL3l25JWXHO-No",
      "google-site-verification=_1Bh-ba5uJAVphxjDQOE5JrTSGn7qPy-scJOuB8Fn2c",
      "google-site-verification=9dM4OOkYQ1jgIlhAh9QwY1smcki10zvmPcAilwsn984",
      "v=spf1 include:_spf.google.com include:sendgrid.net include:mail.zendesk.com include:_spf.mailgun.org  ~all",
      "google-site-verification=KnP0Q8kZF8AklumyR98JDQhcGVuSPPhYz71Eu5BxtyQ",
      "MS=ms49014779",
      "google-site-verification=qKCBZfUAtlffU_5exbyfUIPFvaQNgalXKVKHdZ_yq0I",
      "google-site-verification=RLtqARphmXRxEa0MJdvehSqA1EXfFlBGE_Ncr09ATgo",
      "bugcrowd-verification=ace6499849f3a071d3cd5f48ae25fb76",
      "rbn304r0t27nflr0664jwrk74hwrpklw",
      "google-site-verification=xLmsaIL8UceIPgixV8uVXfNRP_O0D15_IRAU-jihhSE",
      "google-site-verification=iHAGg1uBsC_VIeBWwe0cums1YMQFij3M1qnjGTQ0csY",
      "google-site-verification=pER8ejDjXLNeEa94-RN4EKj96DuOS0uCCyUabuslNTA",
      "google-site-verification=Jga1T34soq0dMRGYnFvV8h1KgT-L2ZBqc6jpmBUqtV8"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:4aa2925f86404c12b8ba2f332f32fa59@dmarc-reports.cloudflare.net,mailto:re+fyn3azxnxei@dmarc.postmarkapp.com; ruf=mailto:dmarc-ruf@creativemarket.com; sp=quarantine; aspf=r;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=creativemarket.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Aug 20 04:41:48 2026 GMT",
    "notAfter": "Nov 18 05:41:46 2026 GMT",
    "san": [
      "creativemarket.com",
      "*.creativemarket.com"
    ],
    "days_left": 52,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.27.236",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 403,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "tech": [
    "Server: cloudflare",
    "Cloudflare CDN/WAF"
  ],
  "cookies": [
    {
      "domain": "creativemarket.com",
      "samesite": "none"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.creativemarket.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://creativemarket.com/"
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
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=o06UtMir6spz9U81R1jgVspJe-h2SQL3l25JWXHO-No",
    "google-site-verification=_1Bh-ba5uJAVphxjDQOE5JrTSGn7qPy-scJOuB8Fn2c",
    "google-site-verification=9dM4OOkYQ1jgIlhAh9QwY1smcki10zvmPcAilwsn984",
    "google-site-verification=KnP0Q8kZF8AklumyR98JDQhcGVuSPPhYz71Eu5BxtyQ",
    "google-site-verification=qKCBZfUAtlffU_5exbyfUIPFvaQNgalXKVKHdZ_yq0I"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.10045.4.3.2",
      "key_alg": "1.2.840.10045.2.1",
      "key_bits": 256,
      "curve": "1.2.840.10045.3.1.7",
      "aia_ocsp": null
    }
  },
  "http2": {
    "hsts_preloaded": true
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
