# Security Audit Report — gitlab.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://gitlab.com/ |
| Bug bounty program | GitLab |
| Listed scope domain | gitlab.com |
| Test date | 2026-09-27 01:21 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **39** (High: 0, Medium: 9, Low: 2, Info: 28)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | medium | PRT21 | FTP service (cleartext) reachable | CWE-319 |
| 3 | info | PRT22 | SSH reachable | CWE-200 |
| 4 | medium | PRT23 | Telnet service (cleartext) reachable | CWE-319 |
| 5 | info | PRT25 | SMTP (port 25) reachable | CWE-200 |
| 6 | info | PRT53 | DNS service reachable | CWE-200 |
| 7 | info | PRT110 | POP3 (cleartext) reachable | CWE-319 |
| 8 | info | PRT143 | IMAP (cleartext) reachable | CWE-319 |
| 9 | info | PRT993 | IMAPS (port 993) reachable | CWE-200 |
| 10 | info | PRT995 | POP3S (port 995) reachable | CWE-200 |
| 11 | medium | PRT1433 | MSSQL (port 1433) reachable | CWE-200 |
| 12 | medium | PRT3306 | MySQL (port 3306) reachable | CWE-200 |
| 13 | info | PRT3389 | RDP (port 3389) reachable | CWE-200 |
| 14 | medium | PRT5432 | PostgreSQL (port 5432) reachable | CWE-200 |
| 15 | medium | PRT5900 | VNC (port 5900) reachable | CWE-200 |
| 16 | medium | PRT6379 | Redis (port 6379) reachable | CWE-200 |
| 17 | info | PRT8000 | Alternate web service (port 8000) reachable | CWE-200 |
| 18 | info | PRT8080 | Alternate web service (port 8080) reachable | CWE-200 |
| 19 | info | PRT8443 | Alternate web service (port 8443) reachable | CWE-200 |
| 20 | info | PRT8888 | Alternate web service (port 8888) reachable | CWE-200 |
| 21 | info | PRT9090 | Service (port 9090, e.g. Elasticsearch/debug) reachable | CWE-200 |
| 22 | medium | PRT9200 | Elasticsearch (port 9200) reachable | CWE-200 |
| 23 | medium | PRT27017 | MongoDB (port 27017) reachable | CWE-200 |
| 24 | info | TECH1 | Technology fingerprint | CWE-200 |
| 25 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 26 | info | H6 | Server technology disclosure | CWE-200 |
| 27 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 28 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 29 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 30 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 31 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 32 | low | CSP1 | CSP present but still allows unsafe directives | CWE-1021 |
| 33 | info | CSP2 | CSP reporting endpoint disclosed | CWE-200 |
| 34 | info | CK9 | Framework/stack inferred from cookie name | CWE-200 |
| 35 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 36 | info | SEC1 | security.txt published with a contact address | CWE-1038 |
| 37 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 38 | info | WK2 | OIDC discovery document published | CWE-200 |
| 39 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [MEDIUM] FTP service (cleartext) reachable (`PRT21`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 172.65.251.78:21 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 3. [INFO] SSH reachable (`PRT22`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:22 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 4. [MEDIUM] Telnet service (cleartext) reachable (`PRT23`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 172.65.251.78:23 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 5. [INFO] SMTP (port 25) reachable (`PRT25`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:25 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 6. [INFO] DNS service reachable (`PRT53`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:53 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 7. [INFO] POP3 (cleartext) reachable (`PRT110`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 172.65.251.78:110 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 8. [INFO] IMAP (cleartext) reachable (`PRT143`)

- **CWE:** CWE-319
- **Detail:** TCP connect to 172.65.251.78:143 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 9. [INFO] IMAPS (port 993) reachable (`PRT993`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:993 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 10. [INFO] POP3S (port 995) reachable (`PRT995`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:995 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 11. [MEDIUM] MSSQL (port 1433) reachable (`PRT1433`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:1433 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 12. [MEDIUM] MySQL (port 3306) reachable (`PRT3306`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:3306 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 13. [INFO] RDP (port 3389) reachable (`PRT3389`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:3389 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 14. [MEDIUM] PostgreSQL (port 5432) reachable (`PRT5432`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:5432 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 15. [MEDIUM] VNC (port 5900) reachable (`PRT5900`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:5900 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 16. [MEDIUM] Redis (port 6379) reachable (`PRT6379`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:6379 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 17. [INFO] Alternate web service (port 8000) reachable (`PRT8000`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:8000 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 18. [INFO] Alternate web service (port 8080) reachable (`PRT8080`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:8080 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 19. [INFO] Alternate web service (port 8443) reachable (`PRT8443`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:8443 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 20. [INFO] Alternate web service (port 8888) reachable (`PRT8888`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:8888 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 21. [INFO] Service (port 9090, e.g. Elasticsearch/debug) reachable (`PRT9090`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:9090 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 22. [MEDIUM] Elasticsearch (port 9200) reachable (`PRT9200`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:9200 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 23. [MEDIUM] MongoDB (port 27017) reachable (`PRT27017`)

- **CWE:** CWE-200
- **Detail:** TCP connect to 172.65.251.78:27017 succeeded (state-only check, no payload sent).
- **Recommendation:** If the service is not required publicly, close the port or restrict by network.

### 24. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: cloudflare; Cloudflare CDN/WAF
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 25. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 26. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: cloudflare
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 27. [INFO] No MTA-STS record (_mta-sts) - opportunistic TLS not enforced (`MAIL11`)

- **CWE:** CWE-223
- **Detail:** Domain sends mail (MX present) but publishes no MTA-STS policy (RFC 8461).
- **Recommendation:** Consider MTA-STS to require TLS to known MTAs.

### 28. [INFO] No TLS-RPT record (_smtp._tls) (`MAIL13`)

- **CWE:** CWE-223
- **Detail:** No TLS-RPT policy for SMTP TLS reporting (RFC 8451/8452).
- **Recommendation:** Consider TLS-RPT for TLS delivery reporting.

### 29. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: gitlab-pages-verification-code=5228e61c992af7e65f5f5160f0587fb4; jamf-site-verification=nRPNM9HJGzWzUkvBtgvBrg; google-site-verification=lnPjOx5EAxmESH8FSn4colWVMAxe18K4ZIopDB1IEDY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 30. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but gitlab.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 31. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 86 disallow path(s), e.g. /autocomplete/users, /autocomplete/projects, /search, /admin, /profile
- **Recommendation:** Review disallowed paths; robots is not access control.

### 32. [LOW] CSP present but still allows unsafe directives (`CSP1`)

- **CWE:** CWE-1021
- **Detail:** Content-Security-Policy of gitlab.com permits unsafe-inline, unsafe-eval; inline script injection still executes.
- **Recommendation:** Replace unsafe-inline/unsafe-eval with nonces, hashes, or trusted types.

### 33. [INFO] CSP reporting endpoint disclosed (`CSP2`)

- **CWE:** CWE-200
- **Detail:** CSP of gitlab.com includes a report-uri/report-to endpoint; the endpoint URL and its acceptance behavior are exposed.
- **Recommendation:** Verify the CSP report endpoint rate-limits and authenticates submissions.

### 34. [INFO] Framework/stack inferred from cookie name (`CK9`)

- **CWE:** CWE-200
- **Detail:** Cookie '_cfuvid' set on gitlab.com indicates Cloudflare visitor cookie.
- **Recommendation:** Keep the disclosed stack current; confirm the cookie is still needed.

### 35. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on gitlab.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of gitlab.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 36. [INFO] security.txt published with a contact address (`SEC1`)

- **CWE:** CWE-1038
- **Detail:** /.well-known/security.txt on gitlab.com is live and contains a contact (email/URL); the security contact endpoint is publicly disclosed.
- **Recommendation:** Confirm the published contact is current and monitored (RFC 9116).

### 37. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on gitlab.com lists 2485 <loc> URL(s); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 38. [INFO] OIDC discovery document published (`WK2`)

- **CWE:** CWE-200
- **Detail:** /.well-known/openid-configuration on gitlab.com is live (issuer: https://gitlab.com); the OIDC endpoint configuration (authorization/token/JWKS URLs) is publicly disclosed.
- **Recommendation:** Confirm the published OIDC metadata matches the deployed identity architecture.

### 39. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on gitlab.com identify the edge as CloudFront; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

## Evidence (raw response observations)

```json
{
  "domain": "gitlab.com",
  "dns": {
    "a": [
      "172.65.251.78"
    ],
    "aaaa": [
      "2606:4700:90:0:f22e:fbec:5bed:a9b9"
    ],
    "cname": null,
    "mx": [
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "jermaine.ns.cloudflare.com.",
      "diva.ns.cloudflare.com."
    ],
    "caa": [
      "0 iodef \"mailto:security@gitlab.com\"",
      "0 issuewild \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issue \"awstrust.com\"",
      "0 issuewild \"letsencrypt.org\"",
      "0 issue \"comodoca.com\"",
      "0 issuewild \"digicert.com; cansignhttpexchanges=yes\"",
      "0 issue \"digicert.com; cansignhttpexchanges=yes\"",
      "0 issue \"pki.goog; cansignhttpexchanges=yes\"",
      "0 issuewild \"comodoca.com\"",
      "0 issue \"amazontrust.com\"",
      "0 issue \"globalsign.com\"",
      "0 issue \"amazon.com\"",
      "0 issue \"ssl.com\"",
      "0 issue \"sectigo.com\"",
      "0 issuewild \"ssl.com\"",
      "0 issue \"amazonaws.com\"",
      "0 issue \"letsencrypt.org\""
    ],
    "spf": [
      "gitlab-pages-verification-code=5228e61c992af7e65f5f5160f0587fb4",
      "MS=ms60523131",
      "v=spf1 include:mail.zendesk.com include:_spf.google.com include:mktomail.com include:_spf.salesforce.com include:_spf-ip.gitlab.com a:zgateway.zuora.com include:mailgun.org include:_spf.sendergen.com ip4:35.80.141.6/32 ip4:44.229.121.55/32 -all",
      "jamf-site-verification=nRPNM9HJGzWzUkvBtgvBrg",
      "google-site-verification=lnPjOx5EAxmESH8FSn4colWVMAxe18K4ZIopDB1IEDY",
      "docusign=1a7d6818-2cf5-4956-a9fb-c3d2e9a578dd",
      "smartsheet-site-validation=wTADkxxpf97DU9ZxO4RuFpZJyRvP7MRm",
      "_globalsign-domain-verification=4azHJ7gL04Dr8r2VR0txu7OrWg7uZpU6v7LOHVP1b3",
      "onetrust-domain-verification=84b59aa2659244d486b0b86f5db073dd",
      "v=MCPv1; k=ed25519; p=MmZM6XexKcX4jiWqHtn3M0av9Q7HDmonAdP6PqktwX0=",
      "google-site-verification=QiG7NTIWpedorFi71mMN7OVe2Fo_yA6RclsxO8stOa8",
      "asv=3f763643512ad5bdcc0d42caea1b3951",
      "adobe-idp-site-verification=5a5e001556a2c0595ed571d2a1f7b5f8a749a00742853e035eb909bdd31622b8",
      "zapier-domain-verification-challenge=a1d665be-8176-4ada-9707-4332dfa7a2cc",
      "openai-domain-verification=dv-Uq90dak9n7LidGh0WsdFOOUu",
      "google-site-verification=iWR2UGQb3MvVY83zY47ZFrGFVFLG6ADfpjqchlQjnok",
      "google-site-verification=vPPg6DGiVgf5vhzQg5zGISLao6-07-lVzzpqvmCFe5Y",
      "google-site-verification=uT9dAMjaTlnkbC0VnN5flFWp0Bsze7zHObWjZwkd2p8",
      "google-site-verification=XDRo7LEOqv6OV0RfGDFh7G2XgpzdycygGJBqde334q4",
      "stripe-verification=E331E16D59119AEFB547211475C2E225C1BF6EB8CB885D300536B2852EAD3D74",
      "uber-domain-verification=38ba2b7b-5ae3-4694-9701-086b20ea3d36",
      "serval-domain-verification-rahzqw=w9adwbCM3CJ9BrXnAleSWuMqz",
      "onetrust-domain-verification=af5b5fda116e45a9b4c4abcd9e571923",
      "mgverify=2dd945066758840fe3bfbd9ccf90e2c6000458f13345baa576338880dcc86658",
      "MS=ms83893381",
      "decagon-domain-verification-cmrbvs=Lb6bOM0iABwwrWBstDaKWS3U8",
      "mgverify=9549a96a4bc9886fbf483bcd56872eaf2b5b9e690d264024041cf446664cb114",
      "drift-domain-verification=fa583cfff88c496bcc62651057550656a98ab3e689c314255a1a6ae848e3e56d",
      "apple-domain-verification=UNUD9vY0Jp9z5TjO",
      "google-site-verification=6Cb3PPpoMp6-xRavXf2HZz03s7pplQeG5MiUaPGIu_Q"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc_agg@vali.email;"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=gitlab.com",
    "issuer": "countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV R36",
    "notBefore": "Apr 26 00:00:00 2026 GMT",
    "notAfter": "Nov 10 23:59:59 2026 GMT",
    "san": [
      "gitlab.com",
      "auth.gitlab.com",
      "customers.gitlab.com",
      "email.customers.gitlab.com",
      "gprd.gitlab.com",
      "www.gitlab.com"
    ],
    "days_left": 44,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "172.65.251.78",
    "open": [
      21,
      22,
      23,
      25,
      53,
      110,
      143,
      993,
      995,
      1433,
      3306,
      3389,
      5432,
      5900,
      6379,
      8000,
      8080,
      8443,
      8888,
      9090,
      9200,
      27017
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
      "domain": "gitlab.com",
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
      "origin": "https://sub.gitlab.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://gitlab.com/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 200",
    "/redirect?next=https://evil-auditor.example/x -> 200",
    "/go?url=https://evil-auditor.example/x -> 301",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 200,
    "/sitemap.xml": 200,
    "/.well-known/security.txt": 200,
    "/security.txt": 200,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 200,
    "/.htaccess": 200,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "status": "ct-pending"
  },
  "apex_txt": [
    "gitlab-pages-verification-code=5228e61c992af7e65f5f5160f0587fb4",
    "jamf-site-verification=nRPNM9HJGzWzUkvBtgvBrg",
    "google-site-verification=lnPjOx5EAxmESH8FSn4colWVMAxe18K4ZIopDB1IEDY",
    "_globalsign-domain-verification=4azHJ7gL04Dr8r2VR0txu7OrWg7uZpU6v7LOHVP1b3",
    "onetrust-domain-verification=84b59aa2659244d486b0b86f5db073dd"
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
      "aia_ocsp": "http://ocsp.sectigo.com",
      "serial": 1599692504969997123620166625973204726,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": null,
      "subject_dn": "311330110603550403130a6769746c61622e636f6d",
      "issuer_dn": "310b300906035504061302474231183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f205075626c6963205365727665722041757468656e7469636174696f6e20434120445620523336",
      "not_before": "20260426000000",
      "not_after": "20261110235959"
    },
    "ocsp": "explicit-status"
  },
  "http2": {
    "robots_disallow": [
      "/autocomplete/users",
      "/autocomplete/projects",
      "/search",
      "/admin",
      "/profile",
      "/dashboard",
      "/users",
      "/api/v*",
      "/help",
      "/s/",
      "/-/profile",
      "/-/profile/",
      "/-/user_settings/",
      "/-/ide/",
      "/-/experiment"
    ]
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://about.gitlab.com/",
    "http_status": 301,
    "p404_status": 302,
    "stapling": "inconclusive",
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 301,
    "hsts": "max-age=31536000",
    "security_txt": "/.well-known/security.txt",
    "sitemap": {
      "urls": 2485,
      "indexes": 0
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301,
    "oidc": "https://gitlab.com"
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "CloudFront"
    ]
  },
  "elapsed_s": 20.1,
  "rechecked": "2026-09-27 01:08 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- OCSP status came from one signed OCSP request (HTTP GET) to each certificate's own AIA responder; HSTS preload membership was checked against the current Chromium static preload list (net/http/transport_security_state_static.json, fetched 2026-09-27).
- OCSP stapling presence was observed by sending one template TLS ClientHello (fresh random + session-id; only the SNI rewritten to the target) and inspecting the server's first flight for the certificate_status extension; on TLS1.2 that observation is conclusive, on TLS1.3-only servers it is recorded as inconclusive. Observe-only: no second flight, no completed handshake, no state change.
- re-run #14 passive additions: certificate hygiene is parsed from the DER the base TLS check already fetched (no extra requests); HTML-level angles read the root document already fetched for header checks; the only extra requests are read-only GETs to /.well-known/security.txt (or /security.txt), /sitemap.xml, and at most one certificate CRL distribution point.
- re-run #15 passive additions: TLS 1.0/1.1, cipher-suite and key-exchange observations come from the handshake the base TLS check already performed plus one quiet re-handshake with no HTTP traffic; HTML-level angles read the root document already fetched for header checks; the only extra request this pass is a read-only GET to /.well-known/openid-configuration (plus the earlier passes' security.txt, sitemap.xml and CRL GETs).
- re-run #16 passive additions: the edge/protocol angles read the alt-svc, server-timing and CDN-identification headers from the one root GET; the preconnect/dns-prefetch, base-href and noindex angles parse the already-fetched root document; the TLS 1.2-only ceiling, SHA-1 signature and weak-key angles use the certificate evidence the base TLS check already captured; the only extra requests this pass are two read-only GETs (/.well-known/jwks.json and /.well-known/change-password).
- Findings are reported against the public program scope; submission through the program tracker is pending.
