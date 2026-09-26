# Security Audit Report — bbb.org

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://bbb.org/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | bbb.org |
| Test date | 2026-09-26 18:46 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **18** (High: 0, Medium: 0, Low: 3, Info: 15)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 4 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 5 | info | TECH1 | Technology fingerprint | CWE-200 |
| 6 | info | TECH2 | HTTP upgrade advertised (Alt-Svc) | CWE-200 |
| 7 | low | H2 | Missing CSP header | CWE-1021 |
| 8 | low | H4 | No clickjacking protection | CWE-1023 |
| 9 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 10 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 11 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 12 | info | H6 | Server technology disclosure | CWE-200 |
| 13 | info | P8 | Missing security.txt | CWE-1038 |
| 14 | low | MAIL12 | MTA-STS TXT published but policy file unreachable | CWE-285 |
| 15 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 16 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 17 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 18 | info | CT1 | 44 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.13.85:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 104.18.13.85:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 6. [INFO] HTTP upgrade advertised (Alt-Svc) (`TECH2`)

- **CWE:** CWE-200
- **Detail:** Alt-Svc: h3=":443"; ma=86400
- **Recommendation:** Verify the advertised protocol endpoints are configured.

### 7. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

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

### 14. [LOW] MTA-STS TXT published but policy file unreachable (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.bbb.org/.well-known/mta-sts/policy.txt failed from this vantage point.
- **Recommendation:** Publish a reachable policy.txt or remove the TXT record.

### 15. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: airtable-verification=c6510236934b04ad8e279c50f5ba261d; google-site-verification=vbCoHJ2AdOVcONDq3HpldnSUFPqkLqLsGqepsvIG3W8; anthropic-domain-verification-1pw1ts=9bt3Q0epDBUzD0U2d9u38ULex
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 16. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of bbb.org has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 17. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but bbb.org is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 18. [INFO] 44 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: api-gateway.dev.bbb.org, api-gateway.stage.bbb.org, api-legacy.stage.bbb.org, ask-bbb.dev.bbb.org, ask-bbb.stage.bbb.org, bbb-web.dev.bbb.org, bbb-web.stage.bbb.org, corecms.dev.bbb.org, corecms.stage.bbb.org, header-footer.dev.bbb.org
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "bbb.org",
  "dns": {
    "a": [
      "104.18.13.85",
      "104.18.12.85"
    ],
    "aaaa": [
      "2606:4700::6812:d55",
      "2606:4700::6812:c55"
    ],
    "cname": null,
    "mx": [
      "bbb-org.mail.protection.outlook.com (pref 0)",
      "usb-smtp-inbound-2.mimecast.com (pref 10)"
    ],
    "ns": [
      "sky.ns.cloudflare.com.",
      "ben.ns.cloudflare.com."
    ],
    "spf": [
      "airtable-verification=c6510236934b04ad8e279c50f5ba261d",
      "MS=ms51510006",
      "MS=ms70871153",
      "google-site-verification=vbCoHJ2AdOVcONDq3HpldnSUFPqkLqLsGqepsvIG3W8",
      "anthropic-domain-verification-1pw1ts=9bt3Q0epDBUzD0U2d9u38ULex",
      "TS-GateMark-XerusPlaty-BishopCastor-MuleArctic",
      "TAILSCALE-v5jb4LWi9twmrM7F2iv1",
      "canva-site-verification=17rTdC3iGSynnfP0MM3AxA",
      "atlassian-sending-domain-verification=3439449f-9f47-43a0-b8d4-5547eb95d654",
      "google-gws-recovery-domain-verification=69716138",
      "google-site-verification=sqG5mY8Hhz4UmPAIpQFTicF7UYQNiU_soZvbYouBOcc",
      "brevo-code:0e7907f04aee89146d8699fe9b1e761e",
      "linkedin-site-verification=f1538191-6fff-4d9f-b874-131440fe2859",
      "MS=ms42622636",
      "v=spf1 include:_spf.psm.knowbe4.com include:simplelists.com include:docebosaas.com include:spfbbb.bluebbb.org include:stspg-customer.com include:sendgrid.net -all",
      "linkedin-site-verification=01c52a57-4144-410e-9dd7-cdad211a2499",
      "linkedin-site-verification=7e3a9aa5-56d0-408f-875b-2f90a2949a8d",
      "_mp71k0i4mlicenedphurdghi22bzipz",
      "google-site-verification=z0BQYT93-PT2Fu2bTuVIpYMJo9lEtQJCPRdJsfzMgYo",
      "atlassian-domain-verification=mir0Y7FBh7vWasF7DQkZu7/P04Fj6MOtgGOTB8pGdjcBZmExhPHag3je/Kgoc54b",
      "Target: 0ed1fe018a8dab4f1075c24ce291b3534d6253b1c7",
      "status-page-domain-verification=qg8m0xbmfqv7"
    ],
    "dmarc": [
      "v=DMARC1; p=none; rua=mailto:39a3b8628f3f867@rep.dmarcanalyzer.com; ruf=mailto:39a3b8628f3f867@for.dmarcanalyzer.com; fo=1;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=bbb.org",
    "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WE1",
    "notBefore": "Sep 21 20:30:13 2026 GMT",
    "notAfter": "Dec 20 21:29:54 2026 GMT",
    "san": [
      "bbb.org",
      "www.stage.bbb.org"
    ],
    "days_left": 85,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "104.18.13.85",
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
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.bbb.org",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://www.bbb.org/"
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
    "source": "certspotter",
    "count": 44,
    "notable": [
      "api-gateway.dev.bbb.org",
      "api-gateway.stage.bbb.org",
      "api-legacy.stage.bbb.org",
      "ask-bbb.dev.bbb.org",
      "ask-bbb.stage.bbb.org",
      "bbb-web.dev.bbb.org",
      "bbb-web.stage.bbb.org",
      "corecms.dev.bbb.org",
      "corecms.stage.bbb.org",
      "header-footer.dev.bbb.org",
      "header-footer.stage.bbb.org",
      "help.bbb.org",
      "img.noreply.bbb.org",
      "scamtracker.dev.bbb.org",
      "scamtracker.stage.bbb.org"
    ],
    "sample": [
      "26106802.bbb.org",
      "aem-dev.bbb.org",
      "aem-stage.bbb.org",
      "aem.bbb.org",
      "api-gateway.dev.bbb.org",
      "api-gateway.prod.bbb.org",
      "api-gateway.stage.bbb.org",
      "api-legacy.stage.bbb.org",
      "ask-bbb.dev.bbb.org",
      "ask-bbb.prod.bbb.org",
      "ask-bbb.stage.bbb.org",
      "bbb-web.dev.bbb.org",
      "bbb-web.prod.bbb.org",
      "bbb-web.stage.bbb.org",
      "bbb.org",
      "bostonhelp.bbb.org",
      "corecms.bbb.org",
      "corecms.dev.bbb.org",
      "corecms.stage.bbb.org",
      "councilvpn.bbb.org"
    ]
  },
  "apex_txt": [
    "airtable-verification=c6510236934b04ad8e279c50f5ba261d",
    "google-site-verification=vbCoHJ2AdOVcONDq3HpldnSUFPqkLqLsGqepsvIG3W8",
    "anthropic-domain-verification-1pw1ts=9bt3Q0epDBUzD0U2d9u38ULex",
    "canva-site-verification=17rTdC3iGSynnfP0MM3AxA",
    "atlassian-sending-domain-verification=3439449f-9f47-43a0-b8d4-5547eb95d654"
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
      "aia_ocsp": null,
      "not_before": "20260921203013",
      "not_after": "20261220212954"
    }
  },
  "x12": {
    "status": 301
  },
  "elapsed_s": 5.4,
  "rechecked": "2026-09-26 18:44 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- Findings are reported against the public program scope; submission through the program tracker is pending.
