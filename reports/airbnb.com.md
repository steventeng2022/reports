# Security Audit Report — airbnb.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://airbnb.com/ |
| Bug bounty program | Airbnb |
| Listed scope domain | airbnb.com |
| Test date | 2026-09-25 08:22 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **12** (High: 0, Medium: 0, Low: 4, Info: 8)

| # | Severity | ID | Finding | CWE |
|---|---|---|---|---|
| 1 | info | DNS2 | DNSSEC not authenticated (no AD flag from resolvers) | CWE-399 |
| 2 | low | TLS4 | TLS certificate expires within 30 days | CWE-298 |
| 3 | info | TECH1 | Technology fingerprint | CWE-200 |
| 4 | low | H2 | Missing CSP header | CWE-1021 |
| 5 | low | H3 | Missing X-Content-Type-Options | CWE-1194 |
| 6 | low | H4 | No clickjacking protection | CWE-1023 |
| 7 | info | H5 | Missing Referrer-Policy | CWE-200 |
| 8 | info | H7 | Missing Permissions-Policy | CWE-200 |
| 9 | info | H8 | No cross-origin isolation headers (COOP/COEP) | CWE-200 |
| 10 | info | H6 | Server technology disclosure | CWE-200 |
| 11 | info | P8 | Missing security.txt | CWE-1038 |
| 12 | info | CT1 | 249 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

## Detailed findings

### 1. [INFO] DNSSEC not authenticated (no AD flag from resolvers) (`DNS2`)

- **CWE:** CWE-399
- **Detail:** Public resolvers did not return the AD flag for this zone; DNSSEC is not enabled for the apex zone.
- **Recommendation:** Consider enabling DNSSEC for integrity protection of DNS records.

### 2. [LOW] TLS certificate expires within 30 days (`TLS4`)

- **CWE:** CWE-298
- **Detail:** Certificate expires in 27 days (notAfter Oct 22 23:59:59 2026 GMT).
- **Recommendation:** Plan renewal / enable automated renewal (e.g., ACME).

### 3. [INFO] Technology fingerprint (`TECH1`)

- **CWE:** CWE-200
- **Detail:** Detected: Server: nginx
- **Recommendation:** Keep the disclosed stack current and patch promptly; consider trimming verbose headers.

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
- **Detail:** Header reveals: nginx
- **Context:** https response, /
- **Recommendation:** Consider hiding or shortening the Server header.

### 11. [INFO] Missing security.txt (`P8`)

- **CWE:** CWE-1038
- **Detail:** No .well-known/security.txt found (RFC 9116).
- **Context:** https response, /
- **Recommendation:** Publish .well-known/security.txt per RFC 9116.

### 12. [INFO] 249 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: admin.airbnb.com, admin.dev.staging.airbnb.com, api.airbnb.com, api.akamai-ci.airbnb.com, api.akamai-dev.airbnb.com, api.dev.staging.airbnb.com, api.preprod.airbnb.com, careers.airbnb.com, careers.next.airbnb.com, dev.staging.airbnb.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "airbnb.com",
  "dns": {
    "a": [
      "166.117.27.62",
      "166.117.189.176"
    ],
    "aaaa": [],
    "cname": null,
    "mx": [
      "alt4.aspmx.l.google.com (pref 10)",
      "alt3.aspmx.l.google.com (pref 10)",
      "aspmx.l.google.com (pref 1)",
      "alt2.aspmx.l.google.com (pref 5)",
      "alt1.aspmx.l.google.com (pref 5)"
    ],
    "ns": [
      "ns-474.awsdns-59.com.",
      "dns4.p08.nsone.net.",
      "dns3.p08.nsone.net.",
      "ns-1453.awsdns-53.org.",
      "ns-1932.awsdns-49.co.uk.",
      "dns2.p08.nsone.net.",
      "ns-558.awsdns-05.net.",
      "dns1.p08.nsone.net."
    ],
    "spf": [
      "elevenlabs=igH15TA-6-8aXgxhsL6--iDut7kibGkXsl3Qrvth8gY",
      "openai-domain-verification=dv-g8FeEwzIIZCUjUpPuF8szG3a",
      "docusign=1c606b88-26ef-48f9-8913-a4251a947532",
      "adobe-idp-site-verification=e68ae64c-3a65-4439-b368-0042e72c4cc8",
      "bettercomp-verify=2b6685a8a6a942417057188531c867db5c85bc8aa25f038a77784e6f0f8bc84f",
      "lucidlink-verification=B2MS39YZ6H92VYF0X75CJHKRC4",
      "status-page-domain-verification=vxdvtv6jn2y9",
      "google-site-verification=Dz--VdnW2R_4K45T0eM8i0vNpFlip_o10WidHL5a3cg",
      "dtm-domain-verification=pKWJVhJM8WfWtDBjyfKZjwxGurB9fiCf1TpvWO_Kvmw",
      "atlassian-domain-verification=mvMbea0qZ4IoMr8/xjkRYgjiHikXBbF04PZnZYv1Nj9UgppCnagnNaSo4T8QnCnP",
      "canva-site-verification=LTDCDSi1WalQaoEcq8B1WA",
      "wework-site-verification=pnT3RXj0097aqZvB",
      "status-page-domain-verification=tb81t2ndk8pb",
      "neat-pulse-domain-verification-Kkvm4PN=ab046095-265e-45ae-8816-c61097444bfd",
      "anthropic-domain-verification-2s2h87=NaRxcN9zTtIb3insUyX7U264A",
      "1password-site-verification=2UO5LR7CZBAKBDNJPUTRIFTUJM",
      "MS=ms85621737",
      "ecostruxure-it-verification=5dd49b15-5fc0-4967-914f-3cc7b2fd6cdf",
      "DirectFedAuthUrl=https://airbnb.okta.com/app/airbnb_pwcprodnewhiddensaml_1/exk223q4dm1BiHGe81d8/sso/saml",
      "google-site-verification=A8e2zY9GYwx8D7x0aOz09Vl4gHfPmv86y_TbW1TUDqs",
      "yahoo-verification-key=YbxdxsyS96Uy5zQpwbZnLfjBY3tMlG2qWTSLHvVrsZ8=",
      "google-site-verification=EFtD_37EY5f55YpAvM8rJ-e6Mwi1I3HF9Xuym2-ZlY8",
      "v=spf1 include:spf1.airbnb.com ip6:2c0f:fb50:4864::/56 ip6:2a00:1450:4864::/56 ip6:2800:3f0:4864::/56 ip6:2607:f8b0:4864::/56 ip6:2404:6800:4864::/56 ip6:2001:4860:4864::/56 ip4:98.77.0.0/16 ip4:87.253.232.0/21 ip4:76.223.176.0/20 ip4:76.223.128.0/19 -all",
      "gradle-verification=VV7U686RA4HKV4QKVJ4L85Q6V6CJ6",
      "cisco-ci-domain-verification=eef9c0a839b89aed57cdd00866d163bb0660fec297c0c1e4b275baec96cfa10",
      "webexdomainverification.725890277b499457e053ab06fc0a5ef4=b060825b-4db4-4ce3-a61e-debc56370fc0",
      "reejig-platform-domain-verification-0dc5cd=a9i760YDrujxnHMEEoXwZP5bD",
      "segment-site-verification=ZkxkEuKJrGI9MrWGC0qw795Xkj9ZlcBq",
      "stripe-verification=271cb9609512aa1a36ff5693b0a5cd9f04d19e089e8abae29dde633abc19749d",
      "datadome-domain-verify=W7kEoUrcETDB4afh6Dg5XcjzGWIxidID",
      "miro-verification=c5c6890aa37542fb59662ade09a0778c6e028b2f",
      "facebook-domain-verification=t3zulila9jjnrfbyt6vjamhqdxz47f",
      "apple-domain-verification=KVJVb0VKHY0IkzDH",
      "webexdomainverification.=162d362c-c218-48f0-8b53-0017116e6f29",
      "docusign=d56dee1c-0384-4ffa-8801-e6bea308af97",
      "paloaltonetworks-site-verification=4df1258d8366090409f33305a49c27e5e867aa6dfd8d8d936c60bdee3396ee04",
      "rzp-site-verification=31fa3e1cd566e8d7347ed9bb16424c59",
      "google-site-verification=_e6Ayd8GN0S5dR116WkaM5ds5tx3ekRD5DC9-51pGrg",
      "masv=MDSVaBxDxTKiIngeAbltVvdnlTkAhnci",
      "google-site-verification=HEoQR0xvby-BYv7pNt06jkvTF44l6rvMnREUZSTyfYQ"
    ],
    "dmarc": [
      "v=DMARC1;p=reject;sp=reject;pct=100;ruf=mailto:dmarc.forensic@airbnb.com;rua=mailto:dmarc.aggregate@airbnb.com;aspf=r;adkim=r;fo=1;ri=3600"
    ],
    "dnssec_authenticated": false
  },
  "tls": {
    "status": "ok",
    "chain": "trusted",
    "version": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "subject": "countryName=US, stateOrProvinceName=California, localityName=San Francisco, organizationName=Airbnb, Inc., commonName=airbnb.com",
    "issuer": "countryName=US, organizationName=DigiCert Inc, commonName=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "notBefore": "Jun 25 00:00:00 2026 GMT",
    "notAfter": "Oct 22 23:59:59 2026 GMT",
    "san": [
      "airbnb.com",
      "airbnb.at",
      "airbnb.com.mt",
      "airbnb.com.ar",
      "airbnb.com.ee",
      "airbnb.com.ph",
      "dr.airbnb.com",
      "airbnb.dk",
      "airbnb.com.py",
      "airbnb.com.co",
      "airbnb.rs",
      "airbnb.lu",
      "airbnb.co.uk",
      "airbnb.jp",
      "airbnb.co.za",
      "airbnb.co.nz",
      "airbnb.is",
      "airbnb.cz",
      "airbnb.co.in",
      "airbnb.lv",
      "airbnb.ba",
      "airbnb.com.bz",
      "airbnb.es",
      "airbnb.am",
      "airbnb.pl",
      "airbnb.gy",
      "airbnb.se",
      "airbnb.com.br",
      "airbnb.com.ni",
      "airbnb.cl",
      "airbnb.co.il",
      "airbnb.com.ec",
      "airbnb.com.ua",
      "airbnb.com.hn",
      "airbnb.com.sv",
      "airbnb.org",
      "airbnb.ca",
      "airbnb.pt",
      "airbnb.fr",
      "airbnb.be",
      "airbnb.de",
      "airbnb.hu",
      "airbnb.lt",
      "airbnb.com.gt",
      "airbnb.no",
      "airbnb.az",
      "airbnb.com.hk",
      "airbnb.si",
      "airbnb.com.ro",
      "airbnb.co.cr",
      "airbnb.me",
      "airbnb.gr",
      "airbnb.com.bo",
      "airbnb.com.tr",
      "airbnb.com.au",
      "airbnb.com.vn",
      "airbnb.co.kr",
      "airbnb.la",
      "airbnb.co.ve",
      "airbnb.cat",
      "airbnb.com.hr",
      "airbnb.com.kh",
      "airbnb.com.my",
      "airbnb.fi",
      "airbnb.ae",
      "airbnb.com.sg",
      "airbnb.ch",
      "airbnb.com.pa",
      "airbnb.it",
      "airbnb.mx",
      "airbnb.com.pe",
      "airbnb.com.tw",
      "airbnb.cn",
      "airbnb.ie",
      "airbnb.co.id",
      "airbnb.al",
      "airbnb.tools",
      "airbnb.nl"
    ],
    "days_left": 27,
    "protocols": {
      "SSLv3": false,
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": false
    }
  },
  "ports": {
    "ip": "166.117.27.62",
    "open": []
  },
  "https": {
    "status": 301,
    "content_type": "",
    "title": ""
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
      "origin": "https://sub.airbnb.com",
      "acao": "",
      "acac": ""
    }
  ],
  "http": {
    "status": 301,
    "location": "https://airbnb.com/"
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
    "count": 249,
    "notable": [
      "admin.airbnb.com",
      "admin.dev.staging.airbnb.com",
      "api.airbnb.com",
      "api.akamai-ci.airbnb.com",
      "api.akamai-dev.airbnb.com",
      "api.dev.staging.airbnb.com",
      "api.preprod.airbnb.com",
      "careers.airbnb.com",
      "careers.next.airbnb.com",
      "dev.staging.airbnb.com",
      "git.airbnb.com",
      "grafana.iac-dev.airbnb.com",
      "grafana.iac.airbnb.com",
      "hr.airbnb.com",
      "hr.next.airbnb.com"
    ],
    "sample": [
      "8c9be.airbnb.com",
      "admin-lite-next.airbnb.com",
      "admin-lite-staging.airbnb.com",
      "admin-lite.airbnb.com",
      "admin-next.airbnb.com",
      "admin-staging.airbnb.com",
      "admin.airbnb.com",
      "admin.dev.staging.airbnb.com",
      "airbnb.com",
      "akamai-staging.airbnb.com",
      "amex-mtls-staging.airbnb.com",
      "amex-mtls.airbnb.com",
      "api.airbnb.com",
      "api.akamai-ci.airbnb.com",
      "api.akamai-dev.airbnb.com",
      "api.dev.staging.airbnb.com",
      "api.preprod.airbnb.com",
      "ar.airbnb.com",
      "ar.next.airbnb.com",
      "az.airbnb.com"
    ]
  },
  "elapsed_s": 137.2,
  "rechecked": "2026-09-25 10:43 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
