# Security Audit Report — microsoft.com

## Scope and authorization

| Item | Value |
|---|---|
| Target | https://microsoft.com/ |
| Bug bounty program | Microsoft Online Services |
| Listed scope domain | microsoft.com |
| Test date | 2026-09-25 10:01 UTC |
| Method | Non-aggressive: passive recon (DNS records, DNSSEC, SPF/DMARC, certificate-transparency subdomains) + read-only active checks (HTTP(S) headers, cookie flags, CORS with Origin header, GET-only open-redirect probes, GET-only sensitive-path checks, TCP-connect port state, TLS certificate/protocol/cipher analysis). No injection, no fuzzing, no forms, no auth, no state changes. |

## Summary

Total findings: **9** (High: 0, Medium: 0, Low: 3, Info: 6)

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
| 9 | info | CT1 | 123 hostnames found via Certificate Transparency (certspotter) | CWE-200 |

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

### 9. [INFO] 123 hostnames found via Certificate Transparency (certspotter) (`CT1`)

- **CWE:** CWE-200
- **Detail:** Notable hostnames: apply.careers.microsoft.com, careers.microsoft.com, cdn.storeedgefd.dsx.mp.microsoft.com, dgps.support.microsoft.com, distribution.ams.infra.gcc.teams.microsoft.com, emails.infra.gcc.teams.microsoft.com, livesite-rdp-temp.webhook.infra.gcc.teams.microsoft.com, login.clouddamppe.microsoft.com, pti-int.store.microsoft.com, pti.store.microsoft.com
- **Recommendation:** Review all CT hostnames (including historical ones) for forgotten/stale assets.

## Evidence (raw response observations)

```json
{
  "domain": "microsoft.com",
  "dns": {
    "a": [
      "150.171.110.70"
    ],
    "aaaa": [
      "2603:1061:14:16b::1"
    ],
    "cname": null,
    "mx": [
      "microsoft-com.mail.protection.outlook.com (pref 10)"
    ],
    "ns": [
      "ns3-39.azure-dns.org.",
      "ns1-39.azure-dns.com.",
      "ns2-39.azure-dns.net.",
      "ns4-39.azure-dns.info."
    ],
    "spf": [
      "d365mktkey=6358r1b7e13hox60tl1uagv14",
      "ms-domain-verification=478640ad-6524-43d5-86c4-a914804b9e93",
      "d365mktkey=PNcDqkW71x8VOUhcE96aGM4l5PYX1gnlRl6ieXUl5eMx",
      "d365mktkey=3l6dste9txazu0Qd2zu4135PUB4E35txLxyzJxjkPbsx",
      "linear-domain-verification=iuq6saifcnbe",
      "d365mktkey=3uc1cf82cpv750lzk70v9bvf2",
      "d365mktkey=j2qHWq9BHdaa3ZXZH8x64daJZxEWsFa0dxDeilxDoYYx",
      "atlassian-domain-verification=Sn5AwyIdVgkaRaJA/IKj7ZFMnWeCBnppa9bXGLuJvsakRHH4lYoBxS8g7GVlud9M",
      "v=MCPv1; k=ecdsap384; p=A8qndBCDJGtFF2+3v/IPIMmM0SaVcrJBoSue7rKob6sUeK7QGeFuWkrtvze3AiqUDA==",
      "v=MCPv1; k=ecdsap384; p=Asc8WWov6gsmCCzn4CSrwRuJIh5SqvaitKz/LlTW+SD54lLC52wzcnWhlTI416p2vw==",
      "airtable-verification=79a09e4a8013ff5737798ffb4ea88eee",
      "google-site-verification=uFg3wr5PWsK8lV029RoXXBBUW0_E6qf1WEWVHhetkOY",
      "v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:_spf1-meo.microsoft.com -all",
      "ms-domain-verification=65f91178-9dfb-41cd-929d-08d1a38ed607",
      "d365mktkey=Fu49WtSTeClkHtK7S14227RIVpGwwGrzEsO6RVs1I2Ax",
      "fg2t0gov9424p2tdcuo94goe9j",
      "v=MCPv1; k=ecdsap384; p=A5JeyhIFWFj4/epHJwt29GRUSrFwGSwXhrhDMAUSklMhfXjI7gi/ekY/fQSWToZdCw==",
      "d365mktkey=wbU64GRacxVEQxwcLSQnx0zisXLYzgUbfvsufIqO9ZUx",
      "ms-domain-verification=d6545068-89f7-4432-b947-0b137e8a9fe3",
      "liveramp-site-verification=kxcV8fDH_FUNUZQEcAO6lwgim47f_hNLgMP4VG0PF_Q",
      "d365mktkey=JlXV17lfZjyvWxNje1qiP390ACSKzTxo5mGqZ3V2BmYx",
      "ms-domain-verification=561512fc-b4ba-4ac7-a946-e464c8f49f1b",
      "ms-domain-verification=25524f4b-1476-489c-a086-30f4c5016ecc",
      "ms-domain-verification=1c4e4677-e58f-4117-8d61-e5b2810388c2",
      "google-site-verification=mEAmcTy1e8jIB9W6ENPk2GDg9hjuNytQQRGlK0hPm0c",
      "anthropic-domain-verification-phksss=GZrrKDUR4klRLFCvxyOvqcNGE",
      "hpe-greenlake-domain-verification=495143304a3330533363357a57684f6335556f316f55654675523541464d3954",
      "v=MCPv1; k=ecdsap384; p=A/78JIxAOlNwq8f0T/l50w7zhwQFpEuB8/Jz9CafdXNX7ewOluYpS/EEcSmLgxsHXg==",
      "workplace-domain-verification=lK0QDLk73xymCYMKUXNpfKAT8TY5Mx",
      "dobtdihqagnr18hea8uv1h1mvq",
      "v=MCPv1; k=ecdsap384; p=An4mJIFLRys9h1EvjX18SJs5p1uEF5MHcs2JJLYPrI48C5Qt9FpaZEM0sQTV4JvNYw==",
      "t7sebee51jrj7vm932k531hipa",
      "1password-site-verification=35ZTURTFFFDC5BW7GFQKRJ77QM",
      "d365mktkey=ZGFU0tlXPekPusNHPo5QQQWpVf0gic0xpuKroNy3NQEx",
      "facebook-domain-verification=fwzwhbbzwmg5fzgotc2go51olc3566",
      "MS=ms79629062",
      "mixpanel-domain-verify=5803bc4c-5bb6-4ce1-8076-753800097373",
      "sitecore-domain-verification=1d46cb5467624e33a408d14324874088",
      "hcp-domain-verification=3ce174a8b9fba88909633ab13eb1d81ce0123454745d66e500052ed84b7248a1",
      "v=MCPv1; k=ecdsap384; p=AoHTKEi2W8L2P8cf9CoDicIxYiuttTkwtIeFOqYCewBGoRZiiF+9/92saUkIDERGAA==",
      "google-site-verification=pjPOauSPcrfXOZS9jnPPa5axowcHGCDAl1_86dCqFpk",
      "zoom-domain-verification=ZOOM_verify_e97a3d385acb4c47b9b924609a280524",
      "d365mktkey=8fEQahTresJms7tZGxGFr94T1zDz36oCbUt1LJc99mox",
      "d365mktkey=heYmJ57sWrwMjCgIG1xRwTREJrQokUIDtBcNfGuxoWQx",
      "google-site-verification=M--CVfn_YwsV-2FGbCp_HFaEj23BmT0cTF4l8hXgpvM",
      "d365mktkey=SxDf1EZxLvMwx6eEZUxzjFFgHoapF8DvtWEUjwq7ZTwx",
      "v=MCPv1; k=ecdsap384; p=As/XxnDWZFxFwHvRZj+HbG5/ImtAeabLkiOWu1h7wCJQFAR216E9HoYQ5Hy6o7StoQ==",
      "atlassian-domain-verification=xvoaqRfxSg3PnlVnR4xCSOlKyw1Aln0MMxRiKXnwWroFG7vI76TUC8xYb03MwMXv",
      "v=MCPv1; k=ecdsap384; p=A/Mf6IKdZzcHfBvpiVz9rkdPTIcCP5IbRDdEkeP3PgXEXF3mNjorahOwaYlMINBF5A==",
      "docusign=d5a3737c-c23c-4bd0-9095-d2ff621f2840",
      "_zx2p8gpzv720db2aqmozy4jhwk2nl43",
      "v=MCPv1; k=ecdsap384; p=AqXeTHJ/1FCYeuvJ8dc1B+X3uHaa7m2W0s31vzL4opnrJlSaBdtbWTY8Ti5WiZnu9Q==",
      "openai-domain-verification=dv-sFtCvKOlWoe31gpoSvs7cqsP",
      "v=MCPv1; k=ecdsap384; p=Azw9+u4M8RoH+bxJidKAZzGDmsPkzY1N4cO7rB/uC5x1RBoNfMyBlH/ott0lpo4pOQ==",
      "google-site-verification=GfDnTUdATPsK1230J0mXbfsYw-3A9BVMVaKSd4DcKgI",
      "d365mktkey=QDa792dLCZhvaAOOCe2Hz6WTzmTssOp1snABhxWibhMx",
      "hubspot-developer-verification=OTQ5NGIwYWEtODNmZi00YWE1LTkyNmQtNDhjMDMxY2JjNDAx",
      "google-site-verification=uhh5_jbxpcQgnb-A7gDIjlrr5Ef34lA2t2_BAveYpnk"
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
  "elapsed_s": 9.7,
  "rechecked": "2026-09-25 07:46 UTC"
}
```

## Notes

- All tests used a standard browser User-Agent; only GET requests and TCP-connect state checks were sent to the target.
- No injection payloads, no fuzzing, no form submissions, no authentication, and no state was modified on the target.
- DNS lookups went to public resolvers (8.8.8.8 / 1.1.1.1); subdomain data came from certificate-transparency logs (crt.sh / certspotter).
- Findings are reported against the public program scope; submission through the program tracker is pending.
