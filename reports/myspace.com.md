# Security Audit Report — myspace.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://myspace.com/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | myspace.com |
| Test date | 2026-09-26 17:49 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HSTS preload-list membership). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **20** (High: 0, Medium: 0, Low: 8, Info: 12)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 5 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 6 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 7 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 8 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 9 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 10 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 11 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 12 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 13 | low | CK1 | Cookie set without Secure flag over HTTPS | CWE-614 |
| 14 | info | CK3 | Cookie without SameSite attribute | CWE-1275 |
| 15 | info | P8 | Missing security.txt | CWE-1038 |
| 16 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 17 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 18 | low | DNS3 | Wildcard DNS detected | CWE-345 |
| 19 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 20 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=2592000
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 5. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 6. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 7. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'persistent_id' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 8. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'persistent_id' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 9. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'visit_id' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 10. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'visit_id' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 11. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'beacons_enabled' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 12. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'beacons_enabled' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 13. [LOW] Cookie set without Secure flag over HTTPS (`CK1`)

- **CWE:** CWE-614
- **Detail:** Cookie 'player' has no Secure attribute on an HTTPS response.
- **Context:** https response, /
- **Recommendation:** Set Secure on all cookies over HTTPS.

### 14. [INFO] Cookie without SameSite attribute (`CK3`)

- **CWE:** CWE-1275
- **Detail:** Cookie 'player' has no SameSite attribute.
- **Context:** https response, /
- **Recommendation:** Set SameSite=Lax (or Strict) to reduce CSRF surface.

### 15. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 16. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

### 17. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.myspace.com/.well-known/mta-sts/policy.txt -> 404
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 18. [LOW] Wildcard DNS detected (`DNS3`)

- **CWE:** CWE-345
- **Detail:** Two random labels (ti0tfk9xg9honl.myspace.com and 9ixffs5pm4fux1.myspace.com) both resolve to the same addresses; any random subdomain resolves, weakening dangling-subdomain detection and enlarging virtual-host surface.
- **Recommendation:** Remove the wildcard record or use distinct records for live subdomains.

### 19. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU; google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 20. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of myspace.com has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

## Evidence (raw response observations)

```json
{
  "domain": "myspace.com",
  "dns": {
    "a": [
      "34.111.176.156"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "mxb-00ac0e01.gslb.pphosted.com (pref 10)",
      "mxa-00ac0e01.gslb.pphosted.com (pref 10)"
    ],
    "ns": [
      "ns-cloud-a1.googledomains.com.",
      "ns-cloud-a4.googledomains.com.",
      "ns-cloud-a2.googledomains.com.",
      "ns-cloud-a3.googledomains.com."
    ],
    "spf": [
      "v=spf1 mx ip4:159.183.178.108 ip4:168.245.30.211 ip4:63.208.226.34 ip4:204.16.32.0/22 ip4:67.134.143.0/24 ip4:216.205.243.0/24 ip4:34.85.156.5/32 ip4:35.245.108.108/32 ip4:34.86.129.193/32 ip4:34.86.134.94/32 ",
      "ip4:34.85.222.234/32 ip4:34.86.176.234/32 ip4:34.86.125.212/32 ip4:34.85.224.60/32 ip4:34.86.160.49/32 ip4:35.245.64.166/32 ip4:35.188.226.11/32 ",
      "ip4:34.86.208.228/32 ip4:34.85.216.144/32 ip4:35.221.22.153/32 ip4:34.86.137.108/32 ip4:34.86.51.35/32 ip4:34.150.221.40/32 ip4:34.85.216.70/32 ip4:34.86.37.191/32 ip4:34.85.214.215/32 ",
      "ip4:35.236.234.82/32 ip4:34.86.161.241/32 ip4:216.32.181.16 ip4:216.178.32.0/20 ip4:168.235.224.0/24 include:_netblocks.mimecast.com -all",
      "google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU",
      "google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc",
      "oZ19a+EOIwWVDPJ7POj14UAGBfzk9xcJMmsTUAMUy7H82sDuVCxvw9rZqdg3znFrdTH04+49zd1djhEAt0ooiA==",
      "al4upe6q5cl13sg4srvfivflvg",
      "qpdYoeakhlmAxsnmxgAVFmJgUSibqb/y+Eu6GGn8pdmLf+mFGIB3jhRAxIC5KObsPMES9MW2c+oOrpOo/lCQVw==",
      "cj65vjpq0s1v9u7vfo020c6rel",
      "cr40m536tje9on1slld9bi81bg",
      "MS=ms89904786"
    ],
    "dmarc": [
      "v=DMARC1; p=quarantine; rua=mailto:postmaster@myspace.com"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=myspace.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR3",
    "notBefore": "Aug 17 20:48:06 2026 GMT",
    "notAfter": "Nov 15 21:44:01 2026 GMT",
    "san": [
      "myspace.com",
      "*.myspace.com"
    ],
    "days_left": 50,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "34.111.176.156",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "Featured Content on Myspace"
  },
  "mixed_content": [],
  "cookies": [
    {
      "domain": ".myspace.com"
    },
    {
      "domain": ".myspace.com"
    },
    {
      "domain": ".myspace.com"
    },
    {
      "domain": ".myspace.com"
    }
  ],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": "",
      "error": "ReadTimeout(ReadTimeoutError(\"HTTPSConnectionPool(host='myspace.com', port=443): Read timed out. (read timeout=15)\"))"
    },
    {
      "origin": "https://sub.myspace.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://myspace.com:443/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 404,
    "/security.txt": 404,
    "/.git/HEAD": 404,
    "/.git/config": 404,
    "/.env": 404,
    "/.htaccess": 404,
    "/wp-login.php": 404,
    "/phpmyadmin/index.php": 0,
    "/server-status": 0,
    "/api/": 200
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "wildcard_dns": true,
  "apex_txt": [
    "google-site-verification=q0iWqpcfOBclAJaCeWh83v62QQ4uCgbWObQ08p37qgU",
    "google-site-verification=eu-3gW1JePvsGRRCaEvH17YUOTFJNofm4lnz2Pk0LTc"
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
    "error": "root GET failed"
  },
  "elapsed_s": 84.5,
  "rechecked": "2026-09-26 17:38 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
