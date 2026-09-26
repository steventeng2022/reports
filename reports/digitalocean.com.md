# Security Audit Report — digitalocean.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://digitalocean.com/ |
| Bug bounty program | DigitalOcean |
| Listed scope domain | digitalocean.com |
| Test date | 2026-09-25 09:20 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **13** (High: 0, Medium: 0, Low: 4, Info: 9)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 3 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | low | H2 | Missing CSP header | CWE-1021 |
| 7 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.19.173.68:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.19.173.68:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 7. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 8. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 9. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 10. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 11. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 12. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 13. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

## Evidence (raw response observations)

```json
{
  "domain": "digitalocean.com",
  "dns": {
    "a": [
      "104.19.173.68",
      "104.19.174.68"
    ],
    "aaaa": [
      "2606:4700::6813:ad44",
      "2606:4700::6813:ae44"
    ],
    "cname": null,
    "mx": [
      "aspmx2.googlemail.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt1.aspmx.l.google.com (pref 5)",
      "alt2.aspmx.l.google.com (pref 5)",
      "aspmx3.googlemail.com (pref 10)"
    ],
    "ns": [
      "kim.ns.cloudflare.com.",
      "walt.ns.cloudflare.com."
    ],
    "spf": [
      "stripe-verification=421878fd7101a929f0ea36163be2295b3fc012b9a0bc99ffd484a83e60996e01",
      "stripe-verification=a973e20b4ad2b58603dc6df1e1511f1f0974766512c2ff5c5533099a59fb115c",
      "teamviewer-sso-verification=614425da1843404ebe7504af4bff0dcd",
      "teamviewer-sso-verification=5c39eae7664e4e80a7e5bae6bc4d3991",
      "stripe-verification=de7b481fb94c6c8a20a9c55ff303f96a039ef4fc3131ea11364d9916c4e9a21f",
      "google-site-verification=6_lXIKeIJtrPwaQhZcDcaXQja4ByeiFU2gDcTMuTijQ",
      "stripe-verification=b69a661304f47463194cd46b2c35c8f8e1862539e29f1bddbb69579426a53ef9",
      "dtuqIuOjtDLiAl7YTXvTJJ78bbQq6ACm",
      "stripe-verification=dab9251d3476acbdb63d9c93c21c8371c4d9143bdfc7214ee2611326f3b051d3",
      "status-page-domain-verification=tj3q88fkv3j1",
      "sprout-social-db4e46f7-f461-4675-b4d5-a172a9a30ade",
      "anthropic-domain-verification-dh0bxk=TJRyEfjJC38Zqu4LB1dulxSBf",
      "v=spf1 include:spf.digitalocean.com include:_spf.google.com include:_spf.salesforce.com include:mg-spf.greenhouse.io include:helpscoutemail.com -all",
      "google-site-verification=fuHvbNU2hYfbN9RoK0XFtSLh0qAMAI9Ucw42eYDUTOc",
      "smartsheet-site-validation=TLcMGw2JGRoifAi2GdDaLat1-825u5vb",
      "stripe-verification=7744401ba1e29e328fe564961edab72baa98a6e918e0079bb22df62cb5bf6f23",
      "stripe-verification=3fe3198a843102a2e47a8eb52f0953da4c982db06a26d5dce9a7624cad785d5e",
      "stripe-verification=8DF3E7E1EAC07BB343B0BDF23F93163838648386C6114E107E085B6F170E67DE",
      "stripe-verification=ef8010dac57762d5dbc26b1aab014279f3ef0ebc3f06c5ae6c42c33dba2233b0",
      "_uz7uxsojbrthbcfwkfhrsd3abwyzryf",
      "mixpanel-domain-verify=4ff6bde2-746a-4794-87e3-6f17921293c8",
      "stripe-verification=8BF765DED74005431CDF0A65578C22B307C4B648290C808972410FE2DA6BB589",
      "stripe-verification=2BCFA2CD117F45F83F39DEDA5A7E6106299C28A23B5010E6E3BA5FDB2F61F54D",
      "stripe-verification=9FCE4410B23190F9C5C7EF5FDFEFEE821AF589CB703E6C8C6DA924FD4A99475C",
      "stripe-verification=45e8c480f3cd8e399a5a575cd6907be931bdb63ffa4a474b08e220d8c391a2b2",
      "stripe-verification=F691FE072DF56977FEC2B21F484548F5F150CA5A9E9B972A2479AE04C2C60F35",
      "asv=b5f543d370a3a7fee9ff29f31d312e65",
      "parallels-domain-verification=fa1f1607144e4383bb6e48e2e045d550c15ce091b4894845b934496071c81db0",
      "jamf-site-verification=WcdOvJYHqFoQ42iFjqJVsg",
      "stripe-verification=1C9C705D562471C3AA3D743AB2EC0ABBF75B3A775CA7A086A3F65835BACFB2CB",
      "MS=ms33165602",
      "jetbrains-domain-verification=1hmiczqdw7qr1se179z8tqxfy",
      "cursor-domain-verification-362gj0=wtPDNjMWC1AkVAKVJ5hz5JACn",
      "atlassian-domain-verification=vNGhwIzzcLrF7H9pazlsH17hC9W5zBEPX6o0C8f4hFfguiPaZdwZg3O4wSS8cYZ0"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; rua=mailto:fdpfb1lo@ag.dmarcian.com; ruf=mailto:fdpfb1lo@fr.dmarcian.com;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=digitalocean.com",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 11 03:12:56 2026 GMT",
    "notAfter": "Dec 10 04:12:47 2026 GMT",
    "san": [
      "digitalocean.com",
      "*.digitalocean.com"
    ],
    "days_left": 75,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.19.173.68",
    "open": [
      8080,
      8443
    ]
  },
  "https": {
    "status": 301,
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
      "domain": "digitalocean.com",
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
      "origin": "https://sub.digitalocean.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.digitalocean.com/"
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
    "/.git/HEAD": 403,
    "/.git/config": 403,
    "/.env": 403,
    "/.htaccess": 301,
    "/wp-login.php": 301,
    "/phpmyadmin/index.php": 301,
    "/server-status": 301,
    "/api/": 301
  },
  "subdomains": {
    "status": "crt.sh 502 (certspotter 429)"
  },
  "elapsed_s": 117.2,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
