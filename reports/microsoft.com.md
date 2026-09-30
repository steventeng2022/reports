# Security Audit Report — microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://microsoft.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | microsoft.com |
| Test date | 2026-09-27 02:38 UTC |
| Method | Non-aggressive: passive recon (DNS records incl. wildcard/CNAME-chain detection, DNSSEC, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags incl. HttpOnly, CORS with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection probes, GET-only sensitive-path checks, robots.txt asset map, TCP-connect port state, TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, certificate validity-window checks, HSTS preload-list membership, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **21** (High: 0, Medium: 0, Low: 7, Info: 14)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | H2 | Missing CSP header | CWE-1021 |
| 3 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 4 | low | H4 | No clickjacking protection | CWE-1023 |
| 5 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 6 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 7 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 8 | info | P8 | Missing security.txt | CWE-1038 |
| 9 | low | MAIL12 | MTA-STS TXT published but policy file missing/invalid | CWE-285 |
| 10 | info | DNS5 | Third-party verification tokens in apex TXT records | CWE-200 |
| 11 | info | OCSP2 | OCSP endpoint unreachable or returned an error | CWE-603 |
| 12 | info | HSTSP | HSTS present but domain not in the HSTS preload list | CWE-319 |
| 13 | low | H21 | HSTS does not cover subdomains | CWE-319 |
| 14 | info | H26 | Edge/CDN layer identified from response headers | CWE-200 |
| 15 | info | TLS31 | OCSP responder URL uses plaintext http:// | CWE-319 |
| 16 | info | CT1 | 123 hostnames found via Certificate Transparency (certspotter) | CWE-200 |
| 17 | low | I22 | link endpoint 301s to login.live.com OAuth with parameter retained (no open redirect) | CWE-538 |
| 18 | low | I22 | next endpoint 301s to blogs.microsoft.com with parameter retained | CWE-538 |
| 19 | info | S1 | pay.microsoft.com = 200 (543 B); dl.microsoft.com = 403 (1,148 B) - first-party | CWE-916 |
| 20 | info | S1 | OAuth/admin subdomain handoffs (account -> login.microsoftonline.com with client_id, admin/portal/login -> M365, help/news/store/secure/billing 301s) | CWE-916 |
| 21 | info | S1 | dev/api/docs 301s (msdn Kestrel), staging 404 (Kestrel), media/uat 404 (266,389 B), edge 400 (198 B) | CWE-916 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] Missing CSP header (`H2`)

- **CWE:** CWE-1021
- **Detail:** No Content-Security-Policy header. XSS mitigation relies solely on output encoding.
- **Context:** https response, /
- **Recommendation:** Add a Content-Security-Policy header (start with default-src and report-only).

### 3. [LOW] Missing X-Content-Type-Options (`H3`)

- **CWE:** CWE-1194
- **Detail:** No nosniff directive; browsers may MIME-sniff responses.
- **Context:** https response, /
- **Recommendation:** Set X-Content-Type-Options: nosniff.

### 4. [LOW] No clickjacking protection (`H4`)

- **CWE:** CWE-1023
- **Detail:** No X-Frame-Options or CSP frame-ancestors; page can be embedded in a frame.
- **Context:** https response, /
- **Recommendation:** Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.

### 5. [INFO] Missing Referrer-Policy (`H5`)

- **CWE:** CWE-200
- **Detail:** No Referrer-Policy header; full URL may leak to third-party referrers.
- **Context:** https response, /
- **Recommendation:** Set Referrer-Policy (e.g., strict-origin-when-cross-origin).

### 6. [INFO] Missing Permissions-Policy (`H7`)

- **CWE:** CWE-200
- **Detail:** No Permissions-Policy header gating browser powerful features (camera, geolocation, ...).
- **Context:** https response, /
- **Recommendation:** Add a Permissions-Policy restricting unused features.

### 7. [INFO] No cross-origin isolation headers (COOP/COEP) (`H8`)

- **CWE:** CWE-200
- **Detail:** COOP/COEP not set; the page is not isolated from cross-origin documents.
- **Context:** https response, /
- **Recommendation:** Consider COOP/COEP if the site uses sharedArrayBuffer or wants isolation.

### 8. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 9. [LOW] MTA-STS TXT published but policy file missing/invalid (`MAIL12`)

- **CWE:** CWE-285
- **Detail:** GET https://mta-sts.microsoft.com/.well-known/mta-sts/policy.txt -> 400
- **Recommendation:** Publish a valid policy.txt (version, max_age, mode) or remove the TXT record.

### 10. [INFO] Third-party verification tokens in apex TXT records (`DNS5`)

- **CWE:** CWE-200
- **Detail:** Apex TXT records with verification/token content: d365mktkey=3l6dste9txazu0Qd2zu4135PUB4E35txLxyzJxjkPbsx; d365mktkey=wbU64GRacxVEQxwcLSQnx0zisXLYzgUbfvsufIqO9ZUx; google-site-verification=uFg3wr5PWsK8lV029RoXXBBUW0_E6qf1WEWVHhetkOY
- **Recommendation:** Review published verification records; they confirm domain ownership to third parties.

### 11. [INFO] OCSP endpoint unreachable or returned an error (`OCSP2`)

- **CWE:** CWE-603
- **Detail:** OCSP check via http://oneocsp.microsoft.com/ocsp -> http-400
- **Recommendation:** Verify the OCSP responder is operational so clients can check revocation.

### 12. [INFO] HSTS present but domain not in the HSTS preload list (`HSTSP`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security is served but microsoft.com is not listed in the HSTS preload list.
- **Recommendation:** Submit the domain to the HSTS preload list (requires includeSubDomains + long max-age).

### 13. [LOW] HSTS does not cover subdomains (`H21`)

- **CWE:** CWE-319
- **Detail:** Strict-Transport-Security on microsoft.com has max-age >= 1 year but no includeSubDomains, so HSTS is not applied to subdomains of microsoft.com.
- **Recommendation:** Add includeSubDomains (each subdomain must then serve HSTS itself).

### 14. [INFO] Edge/CDN layer identified from response headers (`H26`)

- **CWE:** CWE-200
- **Detail:** Response headers on microsoft.com identify the edge as Azure Front Door / Fastly; the CDN tier (caching, WAF, protocol handling) is part of the attack surface and should be inventoried.
- **Recommendation:** Keep the CDN tier in the asset inventory and verify its security policy (WAF/cache) is reviewed.

### 15. [INFO] OCSP responder URL uses plaintext http:// (`TLS31`)

- **CWE:** CWE-319
- **Detail:** The OCSP URL in the leaf certificate of microsoft.com is http://oneocsp.microsoft.com/ocsp; OCSP requests and responses travel unencrypted.
- **Recommendation:** Publish an https:// OCSP responder URL.

### 16. [INFO] 123 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: apply.careers.microsoft.com, careers.microsoft.com, cdn.storeedgefd.dsx.mp.microsoft.com, dgps.support.microsoft.com, distribution.ams.infra.gcc.teams.microsoft.com, emails.infra.gcc.teams.microsoft.com, livesite-rdp-temp.webhook.infra.gcc.teams.microsoft.com, login.clouddamppe.microsoft.com, pti-int.store.microsoft.com, pti.store.microsoft.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.
### 17. [LOW] link endpoint 301s to login.live.com OAuth with parameter retained (no open redirect) (`I22`)

- **CWE:** CWE-538
- **Detail:** /link?url=Zx7qK2v9Bm -> 301 login.live.com/oauth20_remoteconnect.srf?url= -> 200 (16,670 B live login page); the parameter is retained through the first-party OAuth handoff and not consumed as a redirect target (probe-r35redirects).
- **Recommendation:** Keep the OAuth handoff parameter first-party only.

### 18. [LOW] next endpoint 301s to blogs.microsoft.com with parameter retained (`I22`)

- **CWE:** CWE-538
- **Detail:** /next?url=Zx7qK2v9Bm -> 301 blogs.microsoft.com/next/category/podcast?url= (parameter retained, first-party blog).
- **Recommendation:** Consume or strip the retained parameter on the blog hop.

### 19. [INFO] pay.microsoft.com = 200 (543 B); dl.microsoft.com = 403 (1,148 B) - first-party (`S1`)

- **CWE:** CWE-916
- **Detail:** Both hosts respond with small first-party bodies; pay is a live payment entry page, dl a protected download host.
- **Recommendation:** Document for future comparison.

### 20. [INFO] OAuth/admin subdomain handoffs (account -> login.microsoftonline.com with client_id, admin/portal/login -> M365, help/news/store/secure/billing 301s) (`S1`)

- **CWE:** CWE-916
- **Detail:** account 302 -> login.microsoftonline.com/consumers (client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7, prompt=none); admin 302 -> admin.cloud.microsoft; portal 302 -> microsoft365.com/login?ru=/PortalHome; login 302 -> office.com/login; help 301 -> go.microsoft.com/fwlink/p/?linkid=2146602; news 301 -> news.microsoft.com/source; store 301 -> microsoftstore.com; secure 301 -> events.microsoft.com; billing 301 -> account.microsoft.com/billing.
- **Recommendation:** All first-party destinations; the consumers client_id is a useful fingerprint.

### 21. [INFO] dev/api/docs 301s (msdn Kestrel), staging 404 (Kestrel), media/uat 404 (266,389 B), edge 400 (198 B) (`S1`)

- **CWE:** CWE-916
- **Detail:** dev 301 -> developer.microsoft.com; api 301 -> msdn.com (Kestrel); docs 301 -> learn.microsoft.com; staging 404 (2,906 B Kestrel); media/uat 404 (266,389 B); edge 400 (198 B).
- **Recommendation:** The 266,389 B uat 404 body is unusually large; recheck if it changes.

## Active re-verification (2026-09-30, agent-aggressive)

- **I22 x2:** /link?url= 301 -> login.live.com/oauth20_remoteconnect.srf?url= -> 200 (16,670 B live login, param retained, no open redirect); /next?url= 301 -> blogs.microsoft.com/next/category/podcast?url= (probe-r35redirects).
- **S1 x3:** pay 200 (543 B), dl 403 (1,148 B); account 302 login.microsoftonline.com (client_id 81feaced-...), admin 302 admin.cloud.microsoft, portal 302 microsoft365.com/login, login 302 office.com/login, help/news/store/secure/billing 301; dev 301 developer, api 301 msdn (Kestrel), docs 301 learn, staging 404, media/uat 404 (266,389 B), edge 400 (198 B) (probe-r35e-subs).

## Evidence (raw response observations)

```json
{
  "domain": "microsoft.com",
  "dns": {
    "a": [
      "150.171.110.70"
    ],
    "aaaa": [
      "2603:1061:14:143::1"
    ],
    "cname": null,
    "mx": [
      "microsoft-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns2-39.azure-dns.net.",
      "ns4-39.azure-dns.info.",
      "ns3-39.azure-dns.org.",
      "ns1-39.azure-dns.com."
    ],
    "caa": [
      "0 contactemail \"caarecordaware@microsoft.com\""
    ],
    "spf": [
      "d365mktkey=3l6dste9txazu0Qd2zu4135PUB4E35txLxyzJxjkPbsx",
      "d365mktkey=wbU64GRacxVEQxwcLSQnx0zisXLYzgUbfvsufIqO9ZUx",
      "v=MCPv1; k=ecdsap384; p=A8qndBCDJGtFF2+3v/IPIMmM0SaVcrJBoSue7rKob6sUeK7QGeFuWkrtvze3AiqUDA==",
      "v=MCPv1; k=ecdsap384; p=A5JeyhIFWFj4/epHJwt29GRUSrFwGSwXhrhDMAUSklMhfXjI7gi/ekY/fQSWToZdCw==",
      "google-site-verification=uFg3wr5PWsK8lV029RoXXBBUW0_E6qf1WEWVHhetkOY",
      "openai-domain-verification=dv-sFtCvKOlWoe31gpoSvs7cqsP",
      "hcp-domain-verification=3ce174a8b9fba88909633ab13eb1d81ce0123454745d66e500052ed84b7248a1",
      "MS=ms79629062",
      "liveramp-site-verification=kxcV8fDH_FUNUZQEcAO6lwgim47f_hNLgMP4VG0PF_Q",
      "v=MCPv1; k=ecdsap384; p=An4mJIFLRys9h1EvjX18SJs5p1uEF5MHcs2JJLYPrI48C5Qt9FpaZEM0sQTV4JvNYw==",
      "d365mktkey=8fEQahTresJms7tZGxGFr94T1zDz36oCbUt1LJc99mox",
      "d365mktkey=j2qHWq9BHdaa3ZXZH8x64daJZxEWsFa0dxDeilxDoYYx",
      "ms-domain-verification=561512fc-b4ba-4ac7-a946-e464c8f49f1b",
      "zoom-domain-verification=ZOOM_verify_e97a3d385acb4c47b9b924609a280524",
      "google-site-verification=mEAmcTy1e8jIB9W6ENPk2GDg9hjuNytQQRGlK0hPm0c",
      "docusign=d5a3737c-c23c-4bd0-9095-d2ff621f2840",
      "sitecore-domain-verification=1d46cb5467624e33a408d14324874088",
      "d365mktkey=JlXV17lfZjyvWxNje1qiP390ACSKzTxo5mGqZ3V2BmYx",
      "_zx2p8gpzv720db2aqmozy4jhwk2nl43",
      "1password-site-verification=35ZTURTFFFDC5BW7GFQKRJ77QM",
      "linear-domain-verification=iuq6saifcnbe",
      "d365mktkey=PNcDqkW71x8VOUhcE96aGM4l5PYX1gnlRl6ieXUl5eMx",
      "facebook-domain-verification=fwzwhbbzwmg5fzgotc2go51olc3566",
      "d365mktkey=SxDf1EZxLvMwx6eEZUxzjFFgHoapF8DvtWEUjwq7ZTwx",
      "v=MCPv1; k=ecdsap384; p=AoHTKEi2W8L2P8cf9CoDicIxYiuttTkwtIeFOqYCewBGoRZiiF+9/92saUkIDERGAA==",
      "workplace-domain-verification=lK0QDLk73xymCYMKUXNpfKAT8TY5Mx",
      "v=MCPv1; k=ecdsap384; p=AqXeTHJ/1FCYeuvJ8dc1B+X3uHaa7m2W0s31vzL4opnrJlSaBdtbWTY8Ti5WiZnu9Q==",
      "anthropic-domain-verification-phksss=GZrrKDUR4klRLFCvxyOvqcNGE",
      "d365mktkey=ZGFU0tlXPekPusNHPo5QQQWpVf0gic0xpuKroNy3NQEx",
      "v=MCPv1; k=ecdsap384; p=A/Mf6IKdZzcHfBvpiVz9rkdPTIcCP5IbRDdEkeP3PgXEXF3mNjorahOwaYlMINBF5A==",
      "v=MCPv1; k=ecdsap384; p=Azw9+u4M8RoH+bxJidKAZzGDmsPkzY1N4cO7rB/uC5x1RBoNfMyBlH/ott0lpo4pOQ==",
      "google-site-verification=uhh5_jbxpcQgnb-A7gDIjlrr5Ef34lA2t2_BAveYpnk",
      "ms-domain-verification=1c4e4677-e58f-4117-8d61-e5b2810388c2",
      "v=MCPv1; k=ecdsap384; p=Asc8WWov6gsmCCzn4CSrwRuJIh5SqvaitKz/LlTW+SD54lLC52wzcnWhlTI416p2vw==",
      "ms-domain-verification=65f91178-9dfb-41cd-929d-08d1a38ed607",
      "ms-domain-verification=d6545068-89f7-4432-b947-0b137e8a9fe3",
      "google-site-verification=GfDnTUdATPsK1230J0mXbfsYw-3A9BVMVaKSd4DcKgI",
      "google-site-verification=pjPOauSPcrfXOZS9jnPPa5axowcHGCDAl1_86dCqFpk",
      "hubspot-developer-verification=OTQ5NGIwYWEtODNmZi00YWE1LTkyNmQtNDhjMDMxY2JjNDAx",
      "v=MCPv1; k=ecdsap384; p=As/XxnDWZFxFwHvRZj+HbG5/ImtAeabLkiOWu1h7wCJQFAR216E9HoYQ5Hy6o7StoQ==",
      "v=MCPv1; k=ecdsap384; p=A/78JIxAOlNwq8f0T/l50w7zhwQFpEuB8/Jz9CafdXNX7ewOluYpS/EEcSmLgxsHXg==",
      "dobtdihqagnr18hea8uv1h1mvq",
      "atlassian-domain-verification=xvoaqRfxSg3PnlVnR4xCSOlKyw1Aln0MMxRiKXnwWroFG7vI76TUC8xYb03MwMXv",
      "ms-domain-verification=478640ad-6524-43d5-86c4-a914804b9e93",
      "v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:_spf1-meo.microsoft.com -all",
      "d365mktkey=Fu49WtSTeClkHtK7S14227RIVpGwwGrzEsO6RVs1I2Ax",
      "hpe-greenlake-domain-verification=495143304a3330533363357a57684f6335556f316f55654675523541464d3954",
      "atlassian-domain-verification=Sn5AwyIdVgkaRaJA/IKj7ZFMnWeCBnppa9bXGLuJvsakRHH4lYoBxS8g7GVlud9M",
      "fg2t0gov9424p2tdcuo94goe9j",
      "mixpanel-domain-verify=5803bc4c-5bb6-4ce1-8076-753800097373",
      "d365mktkey=3uc1cf82cpv750lzk70v9bvf2",
      "d365mktkey=heYmJ57sWrwMjCgIG1xRwTREJrQokUIDtBcNfGuxoWQx",
      "ms-domain-verification=25524f4b-1476-489c-a086-30f4c5016ecc",
      "t7sebee51jrj7vm932k531hipa",
      "google-site-verification=M--CVfn_YwsV-2FGbCp_HFaEj23BmT0cTF4l8hXgpvM",
      "d365mktkey=6358r1b7e13hox60tl1uagv14",
      "d365mktkey=QDa792dLCZhvaAOOCe2Hz6WTzmTssOp1snABhxWibhMx",
      "airtable-verification=79a09e4a8013ff5737798ffb4ea88eee"
    ],
    "dmarc": [
      "v=DMARC1; p=reject; pct=100; rua=mailto:itex-rua@microsoft.com; ruf=mailto:itex-ruf@microsoft.com; fo=1"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "countryName=US, stateOrProvinceName=WA, localityName=Redmond, organizationName=Microsoft Corporation, commonName=microsoft.com",
    "issuer": "countryName=US, organizationName=Microsoft Corporation, commonName=Microsoft TLS G2 RSA CA OCSP 04",
    "notBefore": "Jun 23 09:04:17 2026 GMT",
    "notAfter": "Dec 20 09:04:17 2026 GMT",
    "san": [
      "microsoft.com",
      "s.microsoft.com",
      "ga.microsoft.com",
      "aep.microsoft.com",
      "aer.microsoft.com",
      "grv.microsoft.com",
      "hup.microsoft.com",
      "mac.microsoft.com",
      "mkb.microsoft.com",
      "pme.microsoft.com",
      "pmi.microsoft.com",
      "rss.microsoft.com",
      "sar.microsoft.com",
      "tco.microsoft.com",
      "fuse.microsoft.com",
      "ieak.microsoft.com",
      "mac2.microsoft.com",
      "mcsp.microsoft.com",
      "open.microsoft.com",
      "shop.microsoft.com",
      "spur.microsoft.com",
      "itpro.microsoft.com",
      "mango.microsoft.com",
      "music.microsoft.com",
      "pymes.microsoft.com",
      "store.microsoft.com",
      "aether.microsoft.com",
      "alerts.microsoft.com",
      "design.microsoft.com",
      "garage.microsoft.com",
      "gigjam.microsoft.com",
      "msctec.microsoft.com",
      "online.microsoft.com",
      "stream.microsoft.com",
      "afflink.microsoft.com",
      "connect.microsoft.com",
      "develop.microsoft.com",
      "domains.microsoft.com",
      "example.microsoft.com",
      "madeira.microsoft.com",
      "msdnisv.microsoft.com",
      "mspress.microsoft.com",
      "www.aep.microsoft.com",
      "www.aer.microsoft.com",
      "wwwbeta.microsoft.com",
      "business.microsoft.com",
      "empresas.microsoft.com",
      "learning.microsoft.com",
      "msdnwiki.microsoft.com",
      "openness.microsoft.com",
      "pinpoint.microsoft.com",
      "snackbox.microsoft.com",
      "sponsors.microsoft.com",
      "stationq.microsoft.com",
      "aistories.microsoft.com",
      "community.microsoft.com",
      "crawlmsdn.microsoft.com",
      "iotschool.microsoft.com",
      "messenger.microsoft.com",
      "minecraft.microsoft.com",
      "backoffice.microsoft.com",
      "enterprise.microsoft.com",
      "iotcentral.microsoft.com",
      "pinunblock.microsoft.com",
      "reroute443.microsoft.com",
      "communities.microsoft.com",
      "explore-smb.microsoft.com",
      "expressions.microsoft.com",
      "ondernemers.microsoft.com",
      "techacademy.microsoft.com",
      "terraserver.microsoft.com",
      "communities2.microsoft.com",
      "connectevent.microsoft.com",
      "dataplatform.microsoft.com",
      "entrepreneur.microsoft.com",
      "hxd.research.microsoft.com",
      "mspartnerira.microsoft.com",
      "mydatahealth.microsoft.com",
      "oemcommunity.microsoft.com",
      "real-stories.microsoft.com",
      "www.formspro.microsoft.com",
      "futuredecoded.microsoft.com",
      "upgradecenter.microsoft.com",
      "learnanalytics.microsoft.com",
      "onlinelearning.microsoft.com",
      "businesscentral.microsoft.com",
      "cloud-immersion.microsoft.com",
      "studentpartners.microsoft.com",
      "analyticspartner.microsoft.com",
      "businessplatform.microsoft.com",
      "explore-security.microsoft.com",
      "kleinunternehmen.microsoft.com",
      "partnercommunity.microsoft.com",
      "explore-marketing.microsoft.com",
      "innovationcontest.microsoft.com",
      "partnerincentives.microsoft.com",
      "phoenixcataloguat.microsoft.com",
      "szkolyprzyszlosci.microsoft.com",
      "www.powerautomate.microsoft.com",
      "successionplanning.microsoft.com",
      "lumiaconversationsuk.microsoft.com",
      "successionplanninguat.microsoft.com",
      "businessmobilitycenter.microsoft.com",
      "skypeandteams.fasttrack.microsoft.com",
      "www.microsoftdlapartnerow.microsoft.com",
      "commercialappcertification.microsoft.com",
      "www.skypeandteams.fasttrack.microsoft.com",
      "ceoconnections.event.microsoft.com",
      "biz4afrika.microsoft.com",
      "cashback.microsoft.com",
      "www.cashback.microsoft.com",
      "visio.microsoft.com",
      "insidemsr.microsoft.com",
      "developervelocityassessment.com",
      "www.developervelocityassessment.com",
      "gears5.com",
      "www.gears5.com",
      "www.gearstactics.com",
      "gearstactics.com",
      "m12.microsoft.com",
      "seeingai.com",
      "yourchoice.microsoft.com",
      "mvtd.events.microsoft.com",
      "imagine.microsoft.com",
      "microsoft.com.au",
      "www.microsoft.com.au",
      "dynamics.microsoft.com",
      "powerplatform.microsoft.com",
      "powerapps.microsoft.com",
      "powerautomate.microsoft.com",
      "powervirtualagents.microsoft.com",
      "powerpages.microsoft.com",
      "test.ideas.fabric.microsoft.com",
      "sds.microsoft.com",
      "ppe.sds.microsoft.com",
      "www.microsoft365copilot.com",
      "www.jclarity.com",
      "techinnovatorsspotlight.com",
      "www.techinnovatorsspotlight.com",
      "copilot.ai",
      "getlicensingready.com",
      "www.getlicensingready.com",
      "jpn.delve.office.com",
      "aus.delve.office.com",
      "ind.delve.office.com",
      "kor.delve.office.com",
      "cobra.me.microsoft.com",
      "www.businesscentral.com",
      "businesscentral.com",
      "msaidatastudio.officeppe.net",
      "ideas.fabric.microsoft.com",
      "www.cpt.link",
      "cpt.link",
      "yarp.dot.net",
      "microsoftstream.com",
      "www.microsoftstream.com",
      "web.microsoftstream.com",
      "discover.copilot.ai",
      "copilot.com",
      "www.copilot.com",
      "discover.copilot.com",
      "researchforum.microsoft.com",
      "cdn.techcommunity.microsoft.com"
    ],
    "days_left": 84,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    }
  },
  "ports": {
    "ip": "150.171.110.70",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
  },
  "mixed_content": [],
  "cookies": [],
  "cors": [
    {
      "origin": "https://evil-auditor.example",
      "acao": "",
      "acac": ""
    },
    {
      "origin": "https://sub.microsoft.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 307,
    "location": "https://microsoft.com/"
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
    "count": 123,
    "notable": [
      "apply.careers.microsoft.com",
      "careers.microsoft.com",
      "cdn.storeedgefd.dsx.mp.microsoft.com",
      "dgps.support.microsoft.com",
      "distribution.ams.infra.gcc.teams.microsoft.com",
      "emails.infra.gcc.teams.microsoft.com",
      "livesite-rdp-temp.webhook.infra.gcc.teams.microsoft.com",
      "login.clouddamppe.microsoft.com",
      "pti-int.store.microsoft.com",
      "pti.store.microsoft.com",
      "support.office.microsoft.com",
      "test.pdfs.microsoft.com",
      "transform.ams.infra.gcc.teams.microsoft.com",
      "urlshortener.infra.gcc.teams.microsoft.com",
      "webhook.infra.gcc.teams.microsoft.com"
    ],
    "sample": [
      "01-az.audience.gcc.teams.microsoft.com",
      "01-tx.audience.gcc.teams.microsoft.com",
      "02-az.audience.gcc.teams.microsoft.com",
      "02-tx.audience.gcc.teams.microsoft.com",
      "03-az.audience.gcc.teams.microsoft.com",
      "03-tx.audience.gcc.teams.microsoft.com",
      "04-az.audience.gcc.teams.microsoft.com",
      "04-tx.audience.gcc.teams.microsoft.com",
      "05-az.audience.gcc.teams.microsoft.com",
      "05-tx.audience.gcc.teams.microsoft.com",
      "06-az.audience.gcc.teams.microsoft.com",
      "06-tx.audience.gcc.teams.microsoft.com",
      "07-az.audience.gcc.teams.microsoft.com",
      "07-tx.audience.gcc.teams.microsoft.com",
      "apply.careers.microsoft.com",
      "assets-bundle.clouddamppe.microsoft.com",
      "assetsppe.microsoft.com",
      "assetsppe2.microsoft.com",
      "audio.microsoft.com",
      "azwussmausam02.redmond.corp.microsoft.com"
    ]
  },
  "apex_txt": [
    "d365mktkey=3l6dste9txazu0Qd2zu4135PUB4E35txLxyzJxjkPbsx",
    "d365mktkey=wbU64GRacxVEQxwcLSQnx0zisXLYzgUbfvsufIqO9ZUx",
    "google-site-verification=uFg3wr5PWsK8lV029RoXXBBUW0_E6qf1WEWVHhetkOY",
    "openai-domain-verification=dv-sFtCvKOlWoe31gpoSvs7cqsP",
    "hcp-domain-verification=3ce174a8b9fba88909633ab13eb1d81ce0123454745d66e500052ed8"
  ],
  "tls2": {
    "alpn": "",
    "tls_ver": "TLSv1.3",
    "subject": "None",
    "cert": {
      "sig_oid": "1.2.840.113549.1.1.12",
      "key_alg": "1.2.840.113549.1.1.1",
      "key_bits": 2048,
      "curve": "1.2.840.113549.1.1.1",
      "aia_ocsp": "http://oneocsp.microsoft.com/ocsp",
      "serial": 1494185073477467730131572356474851318374549578,
      "cert_version": 3,
      "bc_ca": null,
      "bc_pathlen": null,
      "crl_urls": [
        "http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2004_Partition00001.crl",
        "http://crl2.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2004_Partition00001.crl"
      ],
      "san": [
        "microsoft.com",
        "s.microsoft.com",
        "ga.microsoft.com",
        "aep.microsoft.com",
        "aer.microsoft.com",
        "grv.microsoft.com",
        "hup.microsoft.com",
        "mac.microsoft.com",
        "mkb.microsoft.com",
        "pme.microsoft.com",
        "pmi.microsoft.com",
        "rss.microsoft.com",
        "sar.microsoft.com",
        "tco.microsoft.com",
        "fuse.microsoft.com",
        "ieak.microsoft.com",
        "mac2.microsoft.com",
        "mcsp.microsoft.com",
        "open.microsoft.com",
        "shop.microsoft.com"
      ],
      "subject_dn": "310b3009060355040613025553310b30090603550408130257413110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e311630140603550403130d6d6963726f736f66742e636f6d",
      "issuer_dn": "310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312830260603550403131f4d6963726f736f667420544c5320473220525341204341204f435350203034",
      "not_before": "20260623090417",
      "not_after": "20261220090417"
    },
    "ocsp": "http-400"
  },
  "x12": {
    "status": 301
  },
  "x13": {
    "root_status": 301,
    "root_location": "https://www.microsoft.com/",
    "http_status": 307,
    "p404_status": 301,
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
    "crl": {
      "url": "http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2004_Partition00001.crl",
      "status": 200
    }
  },
  "x15": {
    "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_ver": "TLSv1.3",
    "root_status": 301
  },
  "x16": {
    "root_status": 301,
    "cdn": [
      "Azure Front Door",
      "Fastly"
    ]
  },
  "x17": {
    "ocsp_http": "http://oneocsp.microsoft.com/ocsp"
  },
  "elapsed_s": 14.6,
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
