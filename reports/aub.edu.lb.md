# Security Audit Report — aub.edu.lb

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://aub.edu.lb/ |
| Bug bounty program | top-websites gist (no active program match) |
| Listed scope domain | aub.edu.lb |
| Test date | 2026-09-27 02:18 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **33** (High: 0, Medium: 0, Low: 5, Info: 28)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | info | MAIL4 | DMARC policy is p=none (monitor only) | CWE-200 |
| 3 | low | MIX1 | Mixed content: HTTP resources referenced from HTTPS page | CWE-319 |
| 4 | info | TECH1 | Technology fingerprint | CWE-200 |
| 5 | low | H1 | Missing HSTS header | CWE-319 |
| 6 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 7 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 8 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 9 | info | H6 | Server technology disclosure | CWE-200 |
| 10 | info | P8 | Missing security.txt | CWE-1038 |
| 11 | low | MAIL6 | SPF record has no explicit all mechanism (implicit +all) | CWE-285 |
| 12 | info | MAIL11 | No MTA-STS record (_mta-sts) - opportunistic TLS not enforced | CWE-223 |
| 13 | info | MAIL13 | No TLS-RPT record (_smtp._tls) | CWE-223 |
| 14 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 15 | info | OCSP3 | No OCSP responder URL in certificate (no stapling possible) | CWE-603 |
| 16 | info | ROB1 | robots.txt discloses disallowed paths (asset map) | CWE-200 |
| 17 | info | CCH1 | HTML document served with cacheable freshness headers | CWE-922 |
| 18 | info | DNS7 | No CAA record (any CA may issue) | CWE-295 |
| 19 | info | SRV1 | Server header discloses a product version | CWE-200 |
| 20 | info | HTML2 | Third-party <script> loaded without Subresource Integrity | CWE-345 |
| 21 | info | HTML3 | Third-party <iframe> embedded in root document | CWE-643 |
| 22 | info | SIT1 | sitemap.xml discloses an indexed URL inventory | CWE-200 |
| 23 | info | HTML4 | Meta generator tag discloses site technology | CWE-200 |
| 24 | low | HTML5 | State-changing HTML form without an anti-CSRF token | CWE-352 |
| 25 | info | HTML7 | Insecure http:// references inside an HTTPS document | CWE-319 |
| 26 | info | HTML11 | Document references many third-party domains | CWE-200 |
| 27 | info | HTML8 | Inline scripts without nonce/hash under a CSP | CWE-1021 |
| 28 | info | TLS27 | TLS 1.2 ceiling: 1.3 not negotiated with a modern client | CWE-327 |
| 29 | info | TLS30 | Wildcard SAN on the leaf certificate | CWE-298 |
| 30 | info | HTML16 | Inline event handlers in root document | CWE-79 |
| 31 | info | HTML17 | Leftover development notes in HTML comments | CWE-200 |
| 32 | info | CT1 | 299 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 33 | low | CT2 | Dangling subdomain(s) from certificate transparency no longer resolve | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [INFO] DMARC policy is p=none (monitor only) (`MAIL4`)

- **CWE:** CWE-200
- **Detail:** DMARC is published but policy is 'none'; failing mail is not quarantined.
- **Recommendation:** Move to p=quarantine/reject once monitor reports are clean.

### 3. [LOW] Mixed content: HTTP resources referenced from HTTPS page (`MIX1`)

- **CWE:** CWE-319
- **Detail:** References found: href="http://
- **Recommendation:** Serve assets over HTTPS (or protocol-relative URLs).

### 4. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: Microsoft-IIS/8.5; X-Powered-By: ASP.NET; X-AspNet-Version: 4.0.30319
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

### 5. [LOW] Missing HSTS header (`H1`)

- **CWE:** CWE-319
- **Detail:** No Strict-Transport-Security header present. Browsers do not enforce HTTPS for repeat visits.
- **Context:** https response, /
- **Recommendation:** Add Strict-Transport-Security with max-age >= 31536000 and preload.

### 6. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 7. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 8. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 9. [INFO] Server technology disclosure (`H6`)

- **CWE:** CWE-200
- **Detail:** Header reveals: Microsoft-IIS/8.5
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 10. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 11. [LOW] SPF record has no explicit all mechanism (implicit +all) (`MAIL6`)

- **CWE:** CWE-285
- **Detail:** Without -all/~all/+all the SPF record implicitly authorizes all senders.
- **Recommendation:** End the SPF record with -all or ~all.

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
- **Detail:** Apex TXT records with verification/token content: google-site-verification=NIoCNLajkOt8Tm9mZfAcX2oYc9oWtCG3yxwLDiJXmeU; openai-domain-verification=dv-DWZ0HxSw0kUap6jjuTBsOiGk; ciscocidomainverification=421e71e3fc1322e159b9b2f1506ee2b6e8d9e3b38b975a6c68409d
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 15. [INFO] No OCSP responder URL in certificate (no stapling possible) (`OCSP3`)

- **CWE:** CWE-603
- **Detail:** Certificate of aub.edu.lb has no Authority Information Access OCSP entry.
- **Recommendation:** Enable OCSP (and stapling) so revocation can be checked.

### 16. [INFO] robots.txt discloses disallowed paths (asset map) (`ROB1`)

- **CWE:** CWE-200
- **Detail:** robots.txt lists 5 disallow path(s), e.g. /_catalogs/, /_layouts/, /search/, /register/, /*?*/
- **Recommendation:** Review disallowed paths; robots is not access control.

### 17. [INFO] HTML document served with cacheable freshness headers (`CCH1`)

- **CWE:** CWE-922
- **Detail:** Response for https://aub.edu.lb/ carries Cache-Control: private, max-age=0 (plus ETag/Last-Modified freshness fields); shared/shared-CDN caches may store the document (passive cache-poisoning surface).
- **Recommendation:** Use no-store for personalized HTML or verify strict cache keys and Vary headers.

### 18. [INFO] No CAA record (any CA may issue) (`DNS7`)

- **CWE:** CWE-295
- **Detail:** No CAA record found for aub.edu.lb; apex edu.lb, so any public CA can issue a certificate for the zone.
- **Recommendation:** Publish a CAA record (issue; <CA>) to constrain which CAs may issue for the domain.

### 19. [INFO] Server header discloses a product version (`SRV1`)

- **CWE:** CWE-200
- **Detail:** Server header on aub.edu.lb is 'Microsoft-IIS/8.5' and includes a version number, which narrows targeted vulnerability research.
- **Recommendation:** Serve a generic Server value without the version.

### 20. [INFO] Third-party <script> loaded without Subresource Integrity (`HTML2`)

- **CWE:** CWE-345
- **Detail:** Root document of aub.edu.lb loads 11 cross-origin script(s) without an integrity attribute, e.g. https://www.googletagmanager.com/gtag/js?id=G-SWFTK13CJR, https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js, https://aubcdn.azureedge.net/aubwebsite/AUB/js/jquery.actual.min.js; a compromise of any such third-party host can inject code.
- **Recommendation:** Add SRI integrity attributes or self-host critical scripts.

### 21. [INFO] Third-party <iframe> embedded in root document (`HTML3`)

- **CWE:** CWE-643
- **Detail:** Root document of aub.edu.lb embeds 2 cross-origin iframe(s), e.g. https://www.googletagmanager.com/ns.html?id=GTM-KZDZDJJ, https://www.youtube.com/embed/ja33j9rQ2so?rel=0&enablejsapi=1; embedded origins are framed inside the page with its trust context.
- **Recommendation:** Review embedded origins and consider sandbox attributes.

### 22. [INFO] sitemap.xml discloses an indexed URL inventory (`SIT1`)

- **CWE:** CWE-200
- **Detail:** /sitemap.xml on aub.edu.lb lists 14 <loc> URL(s) across 15 sitemap-index entr(ies); the public URL inventory helps passive reconnaissance.
- **Recommendation:** Review the sitemap for stale/unintended URLs; keep it minimal.

### 23. [INFO] Meta generator tag discloses site technology (`HTML4`)

- **CWE:** CWE-200
- **Detail:** Root document of aub.edu.lb declares generator: Microsoft SharePoint; generator tags fingerprint the site builder/CMS for targeted attacks.
- **Recommendation:** Remove the generator meta tag or keep it consistent with the deployed version.

### 24. [LOW] State-changing HTML form without an anti-CSRF token (`HTML5`)

- **CWE:** CWE-352
- **Detail:** Root document of aub.edu.lb contains 1 state-changing form(s) (POST/PUT/PATCH/DELETE) with no recognizable anti-CSRF token input.
- **Recommendation:** Add a per-session anti-CSRF token to state-changing forms.

### 25. [INFO] Insecure http:// references inside an HTTPS document (`HTML7`)

- **CWE:** CWE-319
- **Detail:** Root document of aub.edu.lb references 12 distinct http:// URL(s) (e.g. http://alumni.aub.edu.lb/s/1716/start.aspx?gid=2&pgid=61, http://boldly.aub.edu.lb/, http://boldly.aub.edu.lb/#funding-v2); using them drops to unencrypted transport.
- **Recommendation:** Use https:// references or relative URLs.

### 26. [INFO] Document references many third-party domains (`HTML11`)

- **CWE:** CWE-200
- **Detail:** Root document of aub.edu.lb references 20 distinct third-party registrable domains (e.g. microsoft.com, org.lb, cloudflare.com, googletagmanager.com, azureedge.net); each is a supply-chain/trust dependency of the page.
- **Recommendation:** Review third-party integrations and pin critical ones (SRI/subresource policies).

### 27. [INFO] Inline scripts without nonce/hash under a CSP (`HTML8`)

- **CWE:** CWE-1021
- **Detail:** Root document of aub.edu.lb sends a CSP but contains 46 inline script(s) with no nonce- or hash-attribute, so the policy must rely on 'unsafe-inline'.
- **Recommendation:** Use per-script nonces/hashes and drop 'unsafe-inline'.

### 28. [INFO] TLS 1.2 ceiling: 1.3 not negotiated with a modern client (`TLS27`)

- **CWE:** CWE-327
- **Detail:** The quiet handshake to aub.edu.lb negotiated TLSv1.2 even though the client offered TLS 1.3; the edge caps at 1.2 (legacy/compatibility configuration).
- **Recommendation:** Enable TLS 1.3 at the edge.

### 29. [INFO] Wildcard SAN on the leaf certificate (`TLS30`)

- **CWE:** CWE-298
- **Detail:** The leaf certificate of aub.edu.lb contains wildcard SAN entry(ies) *.aub.edu.lb, *.aub.edu, *.aubmc.org; a single key compromise or mis-issuance covers every subdomain of that name.
- **Recommendation:** Prefer per-host certificates for high-value subdomains (auth, API, admin).

### 30. [INFO] Inline event handlers in root document (`HTML16`)

- **CWE:** CWE-79
- **Detail:** The root document of aub.edu.lb contains 1 inline event handler attribute(s); each is a DOM-level execution point that SRI does not constrain.
- **Recommendation:** Move handlers to external scripts where feasible and keep them covered by CSP.

### 31. [INFO] Leftover development notes in HTML comments (`HTML17`)

- **CWE:** CWE-200
- **Detail:** The root document of aub.edu.lb contains dev-note comment(s) (e.g. Do Not Remove This Label(monitored by OpManager): OpManager ); leftover TODO/FIXME/deprecated notes are an information-disclosure and maintenance signal.
- **Recommendation:** Remove or convert stale development comments before shipping.

### 32. [INFO] 299 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: ngoi-isplatform.test.ghi.aub.edu.lb, test.aub.edu.lb, vpn.aub.edu.lb
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

### 33. [LOW] Dangling subdomain(s) from certificate transparency no longer resolve (`CT2`)

- **CWE:** CWE-200
- **Detail:** Historical subdomains no longer have A/AAAA records: test.aub.edu.lb; content may still be served via virtual-host fallback.
- **Recommendation:** Reclaim or delete dangling subdomains to reduce virtual-hosting attack surface.

## Evidence (raw response observations)

```json
{
  "domain": "aub.edu.lb",
  "dns": {
    "a": [
      "40.127.138.74"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "aub-edu-lb.mail.protection.outlook.com (pref 0)"
    ],
    "ns": [
      "lava.aub.edu.lb.",
      "ash.northeurope.cloudapp.azure.com.",
      "rose.aub.edu.lb.",
      "magma.aub.edu.lb.",
      "zeina.aub.edu.lb."
    ],
    "caa": [],
    "spf": [
      "google-site-verification=NIoCNLajkOt8Tm9mZfAcX2oYc9oWtCG3yxwLDiJXmeU",
      "openai-domain-verification=dv-DWZ0HxSw0kUap6jjuTBsOiGk",
      "ciscocidomainverification=421e71e3fc1322e159b9b2f1506ee2b6e8d9e3b38b975a6c68409d591b5f4c0f",
      "apple-domain-verification=6gAxqrh5UO8G0TgM",
      "mentimeter-7517212d-53b0-454a-a51a-58de590aaad4",
      "v=spf1 +ip4:193.188.128.10/32 +ip4:193.188.128.39/32 ",
      "+ip4:193.188.128.41/32 +ip4:193.188.128.50/32 ",
      "+ip4:54.240.35.57/32 +ip4:193.188.129.5/32 ",
      "+ip4:193.188.128.69/32 ip4:193.188.128.16/32 ",
      "include:zeptomail.net include:_spf.salesforce.com +include:spf.protection.outlook.com include:spf.symplicity.com ~all",
      "google-site-verification=9MsV81Hg7gw2Sgc4tNSXaQktR2FWaGTUeYxZtLBb3Lk",
      "google-site-verification=fwk46Yls3T43Nu3xZ677JWvPpfeSfaYF_cesWhonw-Y",
      "HARICA-Jck6FQFsbhgljuf8FV3"
    ],
    "dmarc": [
      "v=DMARC1; p=none; pct=100; rua=mailto:dmarc@aub.edu.lb,mailto:dmarc-reports@aub.edu.lb; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-SHA384",
    "subject": "commonName=*.aub.edu.lb",
    "issuer": "countryName=GR, organizationName=Hellenic Academic and Research Institutions CA, commonName=GEANT TLS RSA 1",
    "notBefore": "Jul 22 23:39:43 2026 GMT",
    "notAfter": "Feb  6 23:39:42 2027 GMT",
    "san": [
      "*.aub.edu.lb",
      "aub.edu.lb",
      "*.aub.edu",
      "*.aubmc.org",
      "aubmc.org",
      "*.aubmc.org.lb",
      "aubmc.org.lb"
    ],
    "days_left": 132,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "40.127.138.74",
    "open": []
  },
  "https": {
    "status": 200,
    "content_type": "text/html; charset=utf-8",
    "title": "American University of Beirut | AUB"
  },
  "mixed_content": [
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://",
    "href=\"http://"
  ],
  "tech": [
    "Server: Microsoft-IIS/8.5",
    "X-Powered-By: ASP.NET",
    "X-AspNet-Version: 4.0.30319"
  ],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.aub.edu.lb",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 307,
    "location": "https://aub.edu.lb/"
  },
  "redir_probes": [
    "/redirect?url=https://evil-auditor.example/x -> 302",
    "/redirect?next=https://evil-auditor.example/x -> 302",
    "/go?url=https://evil-auditor.example/x -> 302",
    "/url?url=https://evil-auditor.example/x -> 302"
  ],
  "paths": {
    "/robots.txt": 302,
    "/sitemap.xml": 302,
    "/.well-known/security.txt": 302,
    "/security.txt": 302,
    "/.git/HEAD": 302,
    "/.git/config": 302,
    "/.env": 302,
    "/.htaccess": 302,
    "/wp-login.php": 302,
    "/phpmyadmin/index.php": 302,
    "/server-status": 302,
    "/api/": 302
  },
  "subdomains": {
    "source": "certspotter",
    "count": 299,
    "notable": [
      "ngoi-isplatform.test.ghi.aub.edu.lb",
      "test.aub.edu.lb",
      "vpn.aub.edu.lb"
    ],
    "sample": [
      "150.aub.edu.lb",
      "acdi.aub.edu.lb",
      "argos.aub.edu.lb",
      "arl.aub.edu.lb",
      "aub.edu.lb",
      "aubnetdb.aub.edu.lb",
      "bam.aub.edu.lb",
      "bandevmobile.aub.edu.lb",
      "bandevmobiletstapi.aub.edu.lb",
      "banmobile.aub.edu.lb",
      "banner-appnav.aub.edu.lb",
      "banssb1.aub.edu.lb",
      "banssb2.aub.edu.lb",
      "bantstsso.aub.edu.lb",
      "bantstwf.aub.edu.lb",
      "banwf.aub.edu.lb",
      "banwf1.aub.edu.lb",
      "banwf2.aub.edu.lb",
      "beis1.aub.edu.lb",
      "beis2.aub.edu.lb"
    ],
    "dangling": [
      "test.aub.edu.lb"
    ]
  },
  "apex_txt": [
    "google-site-verification=NIoCNLajkOt8Tm9mZfAcX2oYc9oWtCG3yxwLDiJXmeU",
    "openai-domain-verification=dv-DWZ0HxSw0kUap6jjuTBsOiGk",
    "ciscocidomainverification=421e71e3fc1322e159b9b2f1506ee2b6e8d9e3b38b975a6c68409d",
    "apple-domain-verification=6gAxqrh5UO8G0TgM",
    "google-site-verification=9MsV81Hg7gw2Sgc4tNSXaQktR2FWaGTUeYxZtLBb3Lk"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.2",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.11",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 4096,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": null,
      "serial": 146672127896156680581472603476293248293,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl"
      ],
      "san": [
        "*.aub.edu.lb",
        "aub.edu.lb",
        "*.aub.edu",
        "*.aubmc.org",
        "aubmc.org",
        "*.aubmc.org.lb",
        "aubmc.org.lb"
      ],
      "subject_dn": "3115301306035504030c0c2a2e6175622e6564752e6c62",
      "issuer_dn": "310b300906035504061302475231373035060355040a0c2e48656c6c656e69632041636164656d696320616e6420526573656172636820496e737469747574696f6e732043413118301606035504030c0f4745414e5420544c53205253412031",
      "not_before": "20260722233943",
      "not_after": "20270206233942"
    }
  },
  "http2": {
    "robots_disallow": [
      "/_catalogs/",
      "/_layouts/",
      "/search/",
      "/register/",
      "/*?*/"
    ]
  },
  "x12": {
    "status": 200
  },
  "x13": {
    "root_status": 200,
    "http_status": 307,
    "p404_status": 302,
    "quic": {
      "ok": false,
      "version": "",
      "note": "deferred (vantage drops udp/443)"
    }
  },
  "x14": {
    "root_status": 200,
    "sitemap": {
      "urls": 14,
      "indexes": 15
    },
    "crl": {
      "url": "http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "ECDHE-RSA-AES256-SHA384",
    "cipher_ver": "TLSv1.2",
    "root_status": 200
  },
  "x16": {
    "root_status": 200
  },
  "x17": {
    "wildcard_san": [
      "*.aub.edu.lb",
      "*.aub.edu",
      "*.aubmc.org",
      "*.aubmc.org.lb"
    ],
    "inline_handlers": 1,
    "dev_comments": [
      "Do Not Remove This Label(monitored by OpManager): OpManager Alive"
    ]
  },
  "elapsed_s": 64.1,
  "rechecked": "2026-09-27 02:16 UTC"
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
- re-run #17 passive additions: the retired-header angles (Public-Key-Pins, Expect-CT, X-Permitted-Cross-Domain-Policies, Via, COOP/COEP, Permissions-Policy) read from the one root GET; the wildcard SAN, http:// OCSP and 398-day-cap angles use the certificate evidence the base TLS check already captured (SAN now harvested from the existing DER); the only extra requests this pass are three read-only GETs (/.well-known/dpop-jwks.json, /.well-known/origin-rsa-keys.json, /.well-known/llms.txt).
- Findings are reported against the public program scope; submission through the program tracker is pending.
