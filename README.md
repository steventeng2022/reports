# Bounty Hunt - Findings Index (Passive Re-audit)

Re-test date: 2026-09-27 (UTC; Asia/Taipei 2026-09-27). **635 of the 635 sites currently in this repo were passively re-audited (100% coverage after re-runs #8-#17; re-run #17 re-scanned ALL sites this pass with the extended passive suite + new #17 passive classes, branch codex/passive-redo)** with a non-aggressive methodology: passive reconnaissance (DNS records incl. wildcard/CNAME-chain detection, DNSSEC status, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomain logs) plus read-only checks (TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HTTP/HTTPS security headers, cookie flags incl. HttpOnly, CORS behavior with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection and sensitive-path probes, robots.txt asset map, TCP-connect port state, HSTS preload-list membership, certificate validity-window checks, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication, edge/protocol-advertisement surface (alt-svc QUIC advertisement, non-standard alt-svc port, server-timing exposure, CDN/edge header fingerprint), root-document network surface (preconnect/dns-prefetch third-party declarations, cross-origin base-href, noindex root posture), certificate posture from existing handshake evidence (TLS 1.2-only ceiling, SHA-1 leaf signature, weak leaf key), JWKS publication, RFC 8615 change-password endpoint, retired/legacy-header surface (Public-Key-Pins/HPKP still deployed, deprecated Expect-CT, legacy Flash cross-domain-policy exposure, Via proxy-hop chain disclosure, partial COOP/COEP cross-origin isolation, explicit Permissions-Policy sensitive-feature allowance), certificate posture from the existing handshake evidence (wildcard SAN scope, plaintext http:// OCSP transport, 398-day cap for post-2026-03-15 issuances), dpop-jwks/origin-rsa-keys/llms.txt well-known publication, root-document surface (missing html lang, inline event handlers, leftover dev comments, legacy object/embed, data: URIs)). No injection, no fuzzing, no forms submitted, no authenticated sessions, no state changes.

Per the repo merge convention, where another agent's active findings exceed the passive count for a site, the index keeps the higher number (those findings remain in the agents' own repos/summaries); report files below are the passive re-audit baseline.
Supplemental non-passive reports carried from main: apache.org-deepdive, coursera.org-deepdive, edx.org-deepdive, freecodecamp.org-deepdive, go.dev-deepdive, khanacademy.org-deepdive, owasp.org-deepdive (agent-deepdive zero-day sweep; 7 files, 136 findings). Their findings are already included in the base-domain rows above per the main convention, so they are not double-counted in the total.

**Total findings across all sites: 14667** (High: 2, Medium: 216, Low: 3311, Info: 11138)

| Site | Findings | High | Med | Low | Info | Program |
|---|---|---|---|---|---|---|
| eventbrite.co.uk | 12 | 0 | 3 | 7 | 2 | top-websites gist (no active program match) |
| symfony.com | 27 | 0 | 0 | 25 | 2 | top-websites gist (no active program match) |
| thumbtack.com | 13 | 0 | 2 | 3 | 8 | top-websites gist (no active program match) |
| jamanetwork.com | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| dol.gov | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| docs.wixstatic.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| mozilla.org | 5 | 0 | 0 | 2 | 3 | Mozilla |
| indiegogo.com | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| cdn.jsdelivr.net | 5 | 0 | 0 | 3 | 2 | jsDelivr |
| siteground.com | 38 | 0 | 0 | 35 | 3 | top-websites gist (no active program match) |
| lefigaro.fr | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| developer.mozilla.org | 7 | 0 | 0 | 7 | 0 | top-websites gist (no active program match) |
| tiny.cc | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| propublica.org | 25 | 0 | 2 | 20 | 3 | top-websites gist (no active program match) |
| digg.com | 28 | 0 | 0 | 23 | 5 | top-websites gist (no active program match) |
| technorati.com | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| access.redhat.com | 15 | 0 | 0 | 12 | 3 | top-websites gist (no active program match) |
| wsj.com | 6 | 0 | 0 | 4 | 2 | The Wall Street Journal |
| gstatic.com | 35 | 0 | 0 | 34 | 1 | Google |
| gplus.to | 11 | 0 | 1 | 8 | 2 | top-websites gist (no active program match) |
| google.cn | 10 | 0 | 0 | 7 | 3 | top-websites gist (no active program match) |
| ericsson.com | 29 | 0 | 0 | 29 | 0 | top-websites gist (no active program match) |
| payhip.com | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| webmasters.googleblog.com | 26 | 0 | 0 | 25 | 1 | top-websites gist (no active program match) |
| s3-eu-west-1.amazonaws.com | 13 | 0 | 1 | 4 | 8 | top-websites gist (no active program match) |
| teespring.com | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| iheart.com | 3 | 0 | 0 | 3 | 0 | top-websites gist (no active program match) |
| gimp.org | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| buff.ly | 25 | 0 | 1 | 22 | 2 | top-websites gist (no active program match) |
| support.mozilla.org | 8 | 0 | 1 | 4 | 3 | top-websites gist (no active program match) |
| orcid.org | 9 | 0 | 1 | 5 | 3 | top-websites gist (no active program match) |
| db.tt | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| twitch.tv | 9 | 0 | 2 | 6 | 1 | Twitch |
| vox.com | 18 | 0 | 0 | 17 | 1 | top-websites gist (no active program match) |
| businesswire.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| www8.hp.com | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| journals.plos.org | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| mailchi.mp | 33 | 0 | 0 | 31 | 2 | top-websites gist (no active program match) |
| scratch.mit.edu | 30 | 0 | 1 | 21 | 8 | top-websites gist (no active program match) |
| smithsonianmag.com | 33 | 0 | 28 | 3 | 2 | top-websites gist (no active program match) |
| chromium.org | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| stumbleupon.com | 19 | 0 | 4 | 13 | 2 | top-websites gist (no active program match) |
| mediafire.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| politico.com | 5 | 0 | 0 | 3 | 2 | Politico |
| bloglovin.com | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| ssl.google-analytics.com | 13 | 0 | 3 | 7 | 3 | top-websites gist (no active program match) |
| fr.linkedin.com | 11 | 0 | 1 | 9 | 1 | top-websites gist (no active program match) |
| mozilla.com | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| nginx.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| code.visualstudio.com | 6 | 0 | 2 | 2 | 2 | top-websites gist (no active program match) |
| hawaii.edu | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| nicovideo.jp | 27 | 1 | 0 | 23 | 3 | top-websites gist (no active program match) |
| deepl.com | 32 | 0 | 0 | 31 | 1 | top-websites gist (no active program match) |
| s3.amazonaws.com | 8 | 0 | 2 | 4 | 2 | AWS |
| academic.oup.com | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| kotaku.com | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| metro.co.uk | 10 | 0 | 3 | 3 | 4 | top-websites gist (no active program match) |
| blog.feedspot.com | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| thoughtcatalog.com | 17 | 0 | 0 | 14 | 3 | top-websites gist (no active program match) |
| tumblr.com | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| thesun.co.uk | 22 | 0 | 4 | 15 | 3 | top-websites gist (no active program match) |
| sciencemag.org | 33 | 0 | 0 | 30 | 3 | top-websites gist (no active program match) |
| columbia.edu | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| blog.naver.com | 13 | 0 | 3 | 6 | 4 | top-websites gist (no active program match) |
| 1.bp.blogspot.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| 1.usa.gov | 13 | 0 | 0 | 3 | 10 | [TTS Bug Bounty](https://hackerone.com/tts) |
| 1drv.ms | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| 2.bp.blogspot.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| 3.bp.blogspot.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| 4.bp.blogspot.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| 7-zip.org | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| a.co | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| abc.com | 31 | 0 | 0 | 3 | 28 | [The Walt Disney Company](https://hackerone.com/disney) |
| abc.net.au | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| abcnews.go.com | 34 | 0 | 0 | 10 | 24 | top-websites gist (no active program match) |
| abebooks.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| about.fb.com | 21 | 0 | 0 | 5 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| about.me | 31 | 0 | 0 | 7 | 24 | top-websites gist (no active program match) |
| aboutads.info | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| accenture.com | 17 | 0 | 0 | 1 | 16 | top-websites gist (no active program match) |
| accessdata.fda.gov | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| accessify.com | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| accounts.google.com | 25 | 0 | 0 | 2 | 23 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| acm.org | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| activecampaign.com | 28 | 0 | 0 | 6 | 22 | top-websites gist (no active program match) |
| ad.doubleclick.net | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| adage.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| addons.mozilla.org | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| addthis.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| adf.ly | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| adobe.com | 21 | 0 | 0 | 4 | 17 | [Adobe](https://hackerone.com/adobe) |
| adobe.ly | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| ads.google.com | 25 | 0 | 0 | 4 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adssettings.google.com | 18 | 0 | 0 | 4 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adwords.google.com | 25 | 0 | 0 | 5 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| affiliate-program.amazon.com | 31 | 0 | 0 | 7 | 24 | [Amazon](https://hackerone.com/amazonvrp) |
| airbnb.com | 22 | 0 | 0 | 4 | 18 | [Airbnb](https://hackerone.com/airbnb) |
| airtable.com | 26 | 0 | 0 | 4 | 22 | [Airtable](https://hackerone.com/airtable) |
| ajax.googleapis.com | 20 | 0 | 0 | 5 | 15 | Google |
| aliexpress.com | 28 | 0 | 0 | 8 | 20 | [Alibaba](https://hackerone.com/alibaba) |
| aljazeera.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| allmusic.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| amazon.ca | 25 | 0 | 0 | 5 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.jp | 24 | 0 | 0 | 5 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.uk | 24 | 0 | 0 | 5 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com | 22 | 0 | 0 | 4 | 18 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.au | 23 | 0 | 0 | 4 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.br | 25 | 0 | 0 | 5 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.de | 24 | 0 | 0 | 5 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.es | 24 | 0 | 0 | 4 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.fr | 24 | 0 | 0 | 4 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.in | 24 | 0 | 0 | 4 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.it | 25 | 0 | 0 | 5 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| ameblo.jp | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| amzn.asia | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| amzn.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| amzn.to | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| analytics.google.com | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ancestry.com | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| animoto.com | 23 | 0 | 0 | 1 | 22 | top-websites gist (no active program match) |
| api.whatsapp.com | 15 | 0 | 0 | 2 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| apis.google.com | 20 | 0 | 0 | 6 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| app.box.com | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| apple.com | 20 | 0 | 0 | 5 | 15 | [Apple](https://security.apple.com) |
| apps.apple.com | 24 | 0 | 0 | 2 | 22 | [Apple](https://security.apple.com) |
| apps.facebook.com | 20 | 0 | 0 | 7 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| archives.gov | 15 | 0 | 0 | 1 | 14 | top-websites gist (no active program match) |
| arstechnica.com | 27 | 0 | 0 | 5 | 22 | top-websites gist (no active program match) |
| artsandculture.google.com | 23 | 0 | 0 | 2 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| asus.com | 8 | 0 | 1 | 1 | 6 | top-websites gist (no active program match) |
| aub.edu.lb | 33 | 0 | 0 | 5 | 28 | top-websites gist (no active program match) |
| automattic.com | 29 | 0 | 0 | 6 | 23 | top-websites gist (no active program match) |
| aws.amazon.com | 23 | 0 | 0 | 2 | 21 | [Amazon](https://hackerone.com/amazonvrp) |
| axios.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| azure.microsoft.com | 13 | 0 | 0 | 5 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| baidu.com | 19 | 0 | 0 | 4 | 15 | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| bandcamp.com | 27 | 0 | 0 | 5 | 22 | [Epic Games](https://hackerone.com/epicgames) |
| bandsintown.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| bbb.org | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| bbc.com | 23 | 0 | 0 | 4 | 19 | [BBC](https://www.bbc.com/backstage/security-disclosure-policy/) |
| beian.gov.cn | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| bhphotovideo.com | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| bigthink.com | 29 | 0 | 0 | 4 | 25 | top-websites gist (no active program match) |
| bild.de | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| bing.com | 25 | 0 | 0 | 8 | 17 | top-websites gist (no active program match) |
| bizjournals.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| blockchain.info | 22 | 0 | 0 | 4 | 18 | [Blockchain](https://hackerone.com/blockchain) |
| blog.google | 26 | 0 | 0 | 5 | 21 | Google |
| blog.hubspot.com | 26 | 0 | 0 | 1 | 25 | [HubSpot](https://bugcrowd.com/hubspot) |
| blog.livedoor.jp | 10 | 0 | 1 | 1 | 8 | top-websites gist (no active program match) |
| blog.us.playstation.com | 24 | 0 | 0 | 5 | 19 | [Playstation](https://hackerone.com/playstation) |
| blogger.com | 24 | 0 | 0 | 6 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| blogs.adobe.com | 6 | 0 | 1 | 1 | 4 | [Adobe](https://hackerone.com/adobe) |
| blogs.msdn.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| blogs.scientificamerican.com | 18 | 0 | 0 | 1 | 17 | top-websites gist (no active program match) |
| blogs.windows.com | 26 | 0 | 0 | 0 | 26 | top-websites gist (no active program match) |
| blogtalkradio.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| bloomberg.com | 18 | 0 | 0 | 2 | 16 | Bloomberg |
| bluehost.com | 23 | 0 | 0 | 5 | 18 | [Bluehost](https://bugcrowd.com/newfold-bluehostindia-vdp) |
| books.google.com | 22 | 0 | 0 | 3 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| bookstackapp.com | 20 | 0 | 0 | 4 | 16 | None (open-source project; GitHub issue tracker) |
| boredpanda.com | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| breitbart.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| britannica.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| buffer.com | 32 | 0 | 0 | 5 | 27 | [Buffer](https://buffer.com/legal#security) |
| bugs.chromium.org | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| business.facebook.com | 19 | 0 | 0 | 3 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| business.google.com | 25 | 0 | 0 | 5 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| business.linkedin.com | 28 | 0 | 0 | 2 | 26 | top-websites gist (no active program match) |
| businessinsider.com | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| buymeacoffee.com | 26 | 0 | 0 | 3 | 23 | top-websites gist (no active program match) |
| buzzfeednews.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| buzzsprout.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| ca.linkedin.com | 27 | 0 | 0 | 3 | 24 | top-websites gist (no active program match) |
| calendar.google.com | 23 | 0 | 0 | 4 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| calendly.com | 34 | 0 | 0 | 5 | 29 | top-websites gist (no active program match) |
| cambridge.org | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| canada.ca | 43 | 0 | 8 | 5 | 30 | top-websites gist (no active program match) |
| cancerresearchuk.org | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| canva.com | 23 | 0 | 0 | 5 | 18 | [Canva](https://bugcrowd.com/canva) |
| cargocollective.com | 27 | 0 | 0 | 7 | 20 | top-websites gist (no active program match) |
| cbs.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| cdc.gov | 21 | 0 | 0 | 4 | 17 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| cdn.shopify.com | 26 | 0 | 0 | 3 | 23 | [Shopify](https://hackerone.com/shopify) |
| cdnjs.cloudflare.com | 19 | 0 | 0 | 3 | 16 | [Cloudflare](https://hackerone.com/cloudflare) |
| cell.com | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| census.gov | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| chase.com | 18 | 0 | 0 | 5 | 13 | [Chase](https://responsibledisclosure.jpmorganchase.com) |
| checkpoint.com | 14 | 0 | 0 | 1 | 13 | [Check Point](https://www.checkpoint.com/white-hat/) |
| chicagotribune.com | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| chris.pirillo.com | 25 | 0 | 0 | 1 | 24 | top-websites gist (no active program match) |
| chrisjdavis.org | 36 | 0 | 8 | 25 | 3 | top-websites gist (no active program match) |
| chrome.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| chronicle.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| cisco.com | 19 | 0 | 0 | 5 | 14 | [Cisco Meraki](https://bugcrowd.com/ciscomeraki) |
| click.linksynergy.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| cloud.google.com | 23 | 0 | 0 | 2 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| cloudflare.com | 22 | 0 | 0 | 5 | 17 | [Cloudflare](https://hackerone.com/cloudflare) |
| cnbc.com | 22 | 0 | 0 | 5 | 17 | Nasdaq |
| code.google.com | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| codecanyon.net | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| codepen.io | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| codeproject.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| codex.wordpress.org | 18 | 0 | 0 | 5 | 13 | [WordPress](https://hackerone.com/wordpress) |
| coinbase.com | 19 | 0 | 0 | 3 | 16 | [Coinbase](https://hackerone.com/coinbase) |
| coinmarketcap.com | 28 | 0 | 0 | 1 | 27 | top-websites gist (no active program match) |
| collegehumor.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| connect.facebook.net | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| constantcontact.com | 25 | 0 | 0 | 5 | 20 | [Constant Contact](https://bugcrowd.com/constantcontact) |
| copyright.gov | 23 | 0 | 0 | 1 | 22 | top-websites gist (no active program match) |
| coursera.org | 22 | 0 | 4 | 9 | 9 | [Coursera](https://hackerone.com/coursera) |
| createspace.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| creativecommons.org | 28 | 0 | 0 | 4 | 24 | top-websites gist (no active program match) |
| creativemarket.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| cse.google.com | 17 | 0 | 0 | 3 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| css-tricks.com | 31 | 0 | 0 | 4 | 27 | top-websites gist (no active program match) |
| ctt.ec | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| cyber.law.harvard.edu | 22 | 0 | 0 | 5 | 17 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| dailycaller.com | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| dailymotion.com | 22 | 0 | 0 | 4 | 18 | [Dailymotion](https://yeswehack.com/programs/dailymotion-public-bug-bounty) |
| dashlane.com | 21 | 0 | 0 | 2 | 19 | [Dashlane](https://hackerone.com/dashlane) |
| data.worldbank.org | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| de-de.facebook.com | 21 | 0 | 0 | 6 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| de.linkedin.com | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| deezer.com | 20 | 0 | 0 | 4 | 16 | [Deezer](https://yeswehack.com/programs/deezer-bug-bounty-program-2019) |
| denverpost.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| design.google | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| desktop.github.com | 17 | 0 | 0 | 4 | 13 | [GitHub](https://hackerone.com/github) |
| developer.android.com | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| developer.apple.com | 22 | 0 | 0 | 1 | 21 | [Apple](https://security.apple.com) |
| developer.chrome.com | 21 | 0 | 0 | 1 | 20 | top-websites gist (no active program match) |
| developers.facebook.com | 15 | 0 | 0 | 3 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| developers.google.com | 23 | 0 | 0 | 2 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| digitalocean.com | 22 | 0 | 0 | 4 | 18 | [DigitalOcean](https://hackerone.com/digitalocean) |
| digitaltrends.com | 29 | 0 | 0 | 4 | 25 | top-websites gist (no active program match) |
| diigo.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| discordapp.com | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| disqus.com | 28 | 0 | 0 | 5 | 23 | top-websites gist (no active program match) |
| dl.dropbox.com | 15 | 0 | 0 | 3 | 12 | [DropBox](https://bugcrowd.com/dropbox) |
| dl.dropboxusercontent.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| docker.com | 19 | 0 | 0 | 4 | 15 | Docker |
| docs.google.com | 22 | 0 | 0 | 4 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| docs.microsoft.com | 19 | 0 | 0 | 3 | 16 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| download.macromedia.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| download.microsoft.com | 19 | 0 | 0 | 5 | 14 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| dribbble.com | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| drift.com | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| drive.google.com | 23 | 0 | 0 | 5 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| dropbox.com | 22 | 0 | 0 | 5 | 17 | [DropBox](https://bugcrowd.com/dropbox) |
| drupal.org | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| dw.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| dx.doi.org | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| ea.com | 28 | 0 | 0 | 6 | 22 | top-websites gist (no active program match) |
| earth.google.com | 20 | 0 | 0 | 3 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ec.europa.eu | 22 | 0 | 0 | 5 | 17 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| economictimes.indiatimes.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| economist.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| edx.org | 24 | 0 | 4 | 13 | 7 | top-websites gist (no active program match) |
| eepurl.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| eff.org | 19 | 0 | 0 | 3 | 16 | [EFF](https://www.eff.org/security/) |
| elmundo.es | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| en-gb.facebook.com | 21 | 0 | 0 | 6 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| en.advertisercommunity.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| en.wikipedia.org | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| engadget.com | 23 | 0 | 0 | 4 | 19 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| envato.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| eonline.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| epa.gov | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| es.wikipedia.org | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| espn.com | 26 | 0 | 0 | 5 | 21 | [The Walt Disney Company](https://hackerone.com/disney) |
| etsy.com | 25 | 0 | 0 | 8 | 17 | [Etsy](https://bugcrowd.com/etsy) |
| eur-lex.europa.eu | 25 | 0 | 0 | 7 | 18 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europa.eu | 20 | 0 | 0 | 5 | 15 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europarl.europa.eu | 21 | 0 | 0 | 4 | 17 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| event.on24.com | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| eventbrite.com | 23 | 0 | 0 | 5 | 18 | [Eventbrite](https://www.eventbrite.com/security/) |
| eventim.de | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| events.google.com | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| evernote.com | 27 | 0 | 0 | 4 | 23 | [Evernote](https://hackerone.com/evernote) |
| expedia.com | 19 | 0 | 0 | 4 | 15 | [Expedia Group](https://hackerone.com/expediagroup) |
| faa.gov | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| facebook.com | 21 | 0 | 0 | 7 | 14 | [Facebook](https://www.facebook.com/whitehat) |
| families.google.com | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fastcompany.com | 21 | 0 | 0 | 2 | 19 | top-websites gist (no active program match) |
| fb.com | 22 | 0 | 0 | 4 | 18 | [Facebook](https://www.facebook.com/whitehat) |
| fb.me | 18 | 0 | 0 | 3 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| fbi.gov | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| feeds.feedburner.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| filezilla-project.org | 18 | 0 | 1 | 4 | 13 | [FileZilla](https://hackerone.com/filezilla) |
| finance.yahoo.com | 23 | 0 | 0 | 3 | 20 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| firstdata.com | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| fiverr.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| flavors.me | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| flic.kr | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| flickr.com | 24 | 0 | 0 | 3 | 21 | [Flickr](https://hackerone.com/flickr) |
| flipboard.com | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| flow.microsoft.com | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| fonts.google.com | 19 | 0 | 0 | 2 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fonts.googleapis.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| forbes.com | 20 | 0 | 0 | 3 | 17 | Forbes |
| forms.gle | 17 | 0 | 0 | 4 | 13 | Google |
| forms.office.com | 18 | 0 | 0 | 5 | 13 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| foxnews.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| fr.wikipedia.org | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| france24.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| franchising.com | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| freelancer.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| freewebs.com | 26 | 0 | 0 | 7 | 19 | top-websites gist (no active program match) |
| ftc.gov | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| funnyordie.com | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| g.co | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| g.page | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| g1.globo.com | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| gartner.com | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| geni.us | 34 | 0 | 27 | 4 | 3 | top-websites gist (no active program match) |
| get.adobe.com | 15 | 0 | 0 | 5 | 10 | [Adobe](https://hackerone.com/adobe) |
| get.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| getpocket.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| getresponse.com | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| giphy.com | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| gist.github.com | 18 | 0 | 0 | 3 | 15 | [GitHub](https://hackerone.com/github) |
| github.com | 21 | 0 | 0 | 2 | 19 | [GitHub](https://hackerone.com/github) |
| gitlab.com | 40 | 0 | 9 | 2 | 29 | [GitLab](https://hackerone.com/gitlab) |
| gitter.im | 19 | 0 | 0 | 5 | 14 | [GitLab](https://hackerone.com/gitlab) |
| gleam.io | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| globalnews.ca | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| gmpg.org | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| gofundme.com | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| golang.org | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| goo.gle | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| google-analytics.com | 19 | 0 | 0 | 4 | 15 | Google |
| google.be | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| google.ca | 22 | 0 | 0 | 4 | 18 | Google |
| google.co.uk | 22 | 0 | 0 | 4 | 18 | Google |
| google.co.za | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| google.com | 23 | 0 | 0 | 5 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| google.com.br | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| google.de | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| google.it | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| google.nl | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| google.se | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| googleadservices.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| googletagmanager.com | 17 | 0 | 0 | 4 | 13 | Google |
| googlewebmastercentral.blogspot.com | 18 | 0 | 0 | 2 | 16 | top-websites gist (no active program match) |
| gov.uk | 18 | 0 | 0 | 4 | 14 | [NCSC UK](https://hackerone.com/ncsc_uk) |
| greenpeace.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| groups.google.com | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gsuite.google.com | 21 | 0 | 0 | 4 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gumroad.com | 36 | 0 | 0 | 7 | 29 | top-websites gist (no active program match) |
| hangouts.google.com | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| hbo.com | 26 | 0 | 0 | 7 | 19 | top-websites gist (no active program match) |
| hbr.org | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| health.com | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| health.harvard.edu | 21 | 0 | 0 | 4 | 17 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| healthline.com | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| heise.de | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| help.apple.com | 19 | 0 | 0 | 1 | 18 | [Apple](https://security.apple.com) |
| helpx.adobe.com | 20 | 0 | 0 | 4 | 16 | [Adobe](https://hackerone.com/adobe) |
| hkrsa.asia | 41 | 0 | 2 | 5 | 34 | top-websites gist (no active program match) |
| homedepot.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| hostgator.com | 26 | 0 | 0 | 6 | 20 | [Host Gator](https://bugcrowd.com/hostgator) |
| hostinger.com | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| hp.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| humblebundle.com | 23 | 0 | 0 | 4 | 19 | [Humble Bundle](https://bugcrowd.com/humblebundle) |
| i.imgur.com | 23 | 0 | 0 | 5 | 18 | [Imgur](https://hackerone.com/imgur) |
| i.redd.it | 18 | 0 | 0 | 4 | 14 | [Reddit](https://hackerone.com/reddit) |
| i0.wp.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| i2.wp.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| ibm.com | 22 | 0 | 0 | 6 | 16 | [IBM](https://hackerone.com/ibm) |
| iconfinder.com | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| idealo.de | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| ietf.org | 27 | 0 | 0 | 5 | 22 | IETF |
| ifttt.com | 28 | 0 | 0 | 0 | 28 | top-websites gist (no active program match) |
| ikea.com | 20 | 0 | 0 | 6 | 14 | [IKEA](https://bugs.ikea.com/) |
| imdb.com | 20 | 0 | 0 | 3 | 17 | [IMDB](https://help.imdb.com/article/imdb/general-information/how-to-report-security-issues-and-vulnerabilities/G99J5YVB8SBBMJ73?ref_=helpart_nav_14#) |
| img.youtube.com | 17 | 0 | 0 | 3 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| imgur.com | 33 | 0 | 0 | 5 | 28 | [Imgur](https://hackerone.com/imgur) |
| in.linkedin.com | 28 | 0 | 0 | 3 | 25 | top-websites gist (no active program match) |
| inc.com | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| indiewire.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| infusionsoft.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| inkscape.org | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| instagram.com | 17 | 0 | 0 | 4 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| institutvajrayogini.fr | 25 | 0 | 1 | 4 | 20 | top-websites gist (no active program match) |
| instructables.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| intel.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| irs.gov | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| is.gd | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| issuu.com | 20 | 0 | 0 | 3 | 17 | [Issuu](https://issuu.com/responsible-disclosure) |
| istockphoto.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| it.linkedin.com | 26 | 0 | 0 | 3 | 23 | top-websites gist (no active program match) |
| itunes.apple.com | 23 | 0 | 0 | 3 | 20 | [Apple](https://security.apple.com) |
| j.mp | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| ja-jp.facebook.com | 21 | 0 | 0 | 6 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| ja.wikipedia.org | 25 | 0 | 2 | 21 | 2 | top-websites gist (no active program match) |
| japantimes.co.jp | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| jetbrains.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| join.slack.com | 25 | 0 | 0 | 6 | 19 | [Slack](https://hackerone.com/slack) |
| journals.sagepub.com | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| jstor.org | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| justgiving.com | 24 | 0 | 0 | 1 | 23 | top-websites gist (no active program match) |
| keep.google.com | 20 | 0 | 0 | 4 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| khanacademy.org | 27 | 0 | 4 | 13 | 10 | [Khan Academy](https://hackerone.com/khanacademy) |
| kiva.org | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| kobo.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| kraken.com | 19 | 0 | 0 | 3 | 16 | [Kraken](https://www.kraken.com/en-us/features/security/bug-bounty) |
| l.facebook.com | 17 | 0 | 0 | 6 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| laughingsquid.com | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| launchpad.net | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| lemonde.fr | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| lenovo.com | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| lh3.googleusercontent.com | 19 | 0 | 0 | 4 | 15 | Google |
| lh4.googleusercontent.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| lh5.ggpht.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| lifehack.org | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| line.me | 22 | 0 | 0 | 4 | 18 | [LINE](https://hackerone.com/line) |
| link.springer.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| linkedin.com | 28 | 0 | 0 | 3 | 25 | top-websites gist (no active program match) |
| linktr.ee | 20 | 0 | 0 | 1 | 19 | top-websites gist (no active program match) |
| livestream.com | 23 | 0 | 0 | 5 | 18 | [Livestream](https://hackerone.com/livestream) |
| lmgtfy.com | 32 | 0 | 0 | 5 | 27 | top-websites gist (no active program match) |
| login.microsoftonline.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| logitech.com | 26 | 0 | 0 | 5 | 21 | [Logitech](https://hackerone.com/logitech) |
| lulu.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| lynda.com | 25 | 0 | 0 | 7 | 18 | top-websites gist (no active program match) |
| m.facebook.com | 18 | 0 | 0 | 6 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| m.me | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| m.youtube.com | 22 | 0 | 0 | 4 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mail.google.com | 16 | 0 | 0 | 1 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mailchimp.com | 21 | 0 | 0 | 5 | 16 | [Intuit](https://hackerone.com/intuit_rdp) |
| makeuseof.com | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| maps.google.co.jp | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| maps.google.co.nz | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| maps.google.com | 20 | 0 | 0 | 4 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| maps.googleapis.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| maps.gstatic.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| market.android.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| marketingplatform.google.com | 18 | 0 | 0 | 3 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| marketwatch.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| marriott.com | 23 | 0 | 0 | 6 | 17 | [Marriott](https://hackerone.com/marriott) |
| mashable.com | 30 | 0 | 0 | 4 | 26 | top-websites gist (no active program match) |
| medium.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| meet.google.com | 16 | 0 | 0 | 2 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| meetup.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| mega.nz | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| mentalfloss.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| messenger.com | 19 | 0 | 0 | 8 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| meta.wikimedia.org | 25 | 0 | 3 | 20 | 2 | top-websites gist (no active program match) |
| metmuseum.org | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| microsoft.com | 16 | 0 | 0 | 5 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| mixcloud.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| mlb.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| mobile.twitter.com | 22 | 0 | 0 | 3 | 19 | [Twitter](https://hackerone.com/twitter) |
| moma.org | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| money.yandex.ru | 4 | 0 | 0 | 2 | 2 | [Yandex](https://yandex.com/bugbounty/index) |
| monster.com | 12 | 0 | 0 | 1 | 11 | top-websites gist (no active program match) |
| moz.com | 28 | 0 | 0 | 3 | 25 | top-websites gist (no active program match) |
| mp.weixin.qq.com | 24 | 0 | 0 | 5 | 19 | [Tencent](https://en.security.tencent.com) |
| msdn.microsoft.com | 15 | 0 | 0 | 4 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| msn.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| music.apple.com | 27 | 0 | 0 | 2 | 25 | [Apple](https://security.apple.com) |
| myaccount.google.com | 17 | 0 | 0 | 2 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| myfitnesspal.com | 26 | 0 | 0 | 6 | 20 | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| myspace.com | 33 | 0 | 0 | 11 | 22 | top-websites gist (no active program match) |
| nasa.gov | 17 | 0 | 0 | 3 | 14 | [Nasa VDP](https://bugcrowd.com/engagements/nasa-vdp) |
| nature.com | 28 | 0 | 0 | 8 | 20 | top-websites gist (no active program match) |
| ncbi.nlm.nih.gov | 25 | 0 | 0 | 2 | 23 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| neilpatel.com | 28 | 0 | 0 | 2 | 26 | top-websites gist (no active program match) |
| nejm.org | 26 | 0 | 0 | 7 | 19 | top-websites gist (no active program match) |
| netbeans.org | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| netflix.com | 21 | 0 | 0 | 4 | 17 | [Netflix](https://bugcrowd.com/netflix) |
| networkadvertising.org | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| newegg.com | 21 | 0 | 0 | 4 | 17 | [Newegg](https://hackerone.com/newegg) |
| news.google.com | 18 | 0 | 0 | 2 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| news.harvard.edu | 13 | 0 | 0 | 2 | 11 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| news.mit.edu | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| news.yahoo.com | 18 | 0 | 0 | 5 | 13 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| note.mu | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| notion.so | 40 | 0 | 9 | 2 | 29 | top-websites gist (no active program match) |
| nvidia.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| nydailynews.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| nypost.com | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| nytimes.com | 19 | 0 | 0 | 3 | 16 | The New York Times |
| oecd.org | 31 | 0 | 0 | 29 | 2 | top-websites gist (no active program match) |
| ok.ru | 33 | 0 | 0 | 5 | 28 | top-websites gist (no active program match) |
| online.wsj.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| open.spotify.com | 21 | 0 | 0 | 3 | 18 | [Spotify](https://hackerone.com/spotify) |
| opera.com | 20 | 0 | 0 | 4 | 16 | [Opera Public Bug Bounty](https://bugcrowd.com/opera) |
| opinionator.blogs.nytimes.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| oracle.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| otto.de | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| ouest-france.fr | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| overcast.fm | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| ow.ly | 14 | 0 | 0 | 2 | 12 | [Hootsuite](https://www.hootsuite.com/security) |
| pandora.com | 28 | 0 | 0 | 5 | 23 | top-websites gist (no active program match) |
| patents.google.com | 13 | 0 | 0 | 2 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| paypal.com | 20 | 0 | 0 | 5 | 15 | [PayPal](https://hackerone.com/paypal) |
| paypal.me | 22 | 0 | 0 | 4 | 18 | [PayPal](https://hackerone.com/paypal) |
| pbs.twimg.com | 14 | 0 | 0 | 2 | 12 | [Twitter](https://hackerone.com/twitter) |
| pcworld.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| penguinrandomhouse.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| periscope.tv | 20 | 0 | 0 | 4 | 16 | [Twitter](https://hackerone.com/twitter) |
| pewresearch.org | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| pexels.com | 22 | 0 | 0 | 4 | 18 | [Pexels](https://bugcrowd.com/pexels) |
| photos.app.goo.gl | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| photos.google.com | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| php.net | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| picasaweb.google.com | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pinterest.co.uk | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| pinterest.com | 16 | 0 | 0 | 4 | 12 | [Pinterest](https://bugcrowd.com/pinterest) |
| pipes.yahoo.com | 2 | 0 | 0 | 0 | 2 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| pitchfork.com | 26 | 0 | 0 | 2 | 24 | top-websites gist (no active program match) |
| pixabay.com | 24 | 0 | 0 | 2 | 22 | [Pixabay](https://bugcrowd.com/pixabay) |
| pixiv.net | 21 | 0 | 0 | 4 | 17 | [Pixiv](https://hackerone.com/pixiv) |
| pixlr.com | 32 | 0 | 0 | 4 | 28 | top-websites gist (no active program match) |
| pl.wikipedia.org | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| platform.twitter.com | 15 | 0 | 0 | 4 | 11 | [Twitter](https://hackerone.com/twitter) |
| play.google.com | 23 | 0 | 0 | 4 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| player.vimeo.com | 20 | 0 | 0 | 1 | 19 | [Vimeo](https://hackerone.com/vimeo) |
| plaza.rakuten.co.jp | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| plus.google.com | 22 | 0 | 0 | 6 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| podcasts.apple.com | 22 | 0 | 0 | 2 | 20 | [Apple](https://security.apple.com) |
| podcasts.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| poetryfoundation.org | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| policies.google.com | 24 | 0 | 0 | 5 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pond5.com | 30 | 0 | 0 | 7 | 23 | top-websites gist (no active program match) |
| popularmechanics.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| postmates.com | 34 | 0 | 0 | 4 | 30 | [Postmates](https://hackerone.com/postmates) |
| privacy.microsoft.com | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| prnewswire.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| prnt.sc | 28 | 0 | 0 | 6 | 22 | top-websites gist (no active program match) |
| productforums.google.com | 18 | 0 | 0 | 5 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| producthunt.com | 32 | 0 | 26 | 5 | 1 | top-websites gist (no active program match) |
| profiles.google.com | 24 | 0 | 0 | 8 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| psychologytoday.com | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| pt.slideshare.net | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| purl.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| puu.sh | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| python.org | 32 | 0 | 1 | 27 | 4 | PSF |
| quora.com | 22 | 0 | 0 | 5 | 17 | [Quora](https://hackerone.com/quora) |
| ranker.com | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| ravelry.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| raw.githubusercontent.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| reacts.ru | 16 | 0 | 3 | 2 | 11 | top-websites gist (no active program match) |
| realvnc.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| redbubble.com | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| redbull.com | 19 | 0 | 0 | 4 | 15 | [Redbull](https://app.intigriti.com/programs/redbull/redbull/detail) |
| reddit.com | 19 | 0 | 0 | 2 | 17 | [Reddit](https://hackerone.com/reddit) |
| redhat.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| researchgate.net | 22 | 0 | 0 | 4 | 18 | [Research Gate](https://explore.researchgate.net/display/support/Security+and+vulnerability) |
| residentadvisor.net | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| reuters.com | 25 | 0 | 0 | 6 | 19 | Reuters |
| reverbnation.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| rollingstone.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| rottentomatoes.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| ru.wikipedia.org | 22 | 0 | 2 | 18 | 2 | top-websites gist (no active program match) |
| s-media-cache-ak0.pinimg.com | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| s0.wp.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| salesforce.com | 19 | 0 | 0 | 6 | 13 | [Salesforce](https://www.salesforce.com/company/disclosure/) |
| samsung.com | 19 | 0 | 0 | 5 | 14 | [Samsung TV](https://samsungtvbounty.com) |
| sciencedaily.com | 25 | 0 | 0 | 5 | 20 | top-websites gist (no active program match) |
| scribd.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| search.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| secure.gravatar.com | 22 | 0 | 0 | 1 | 21 | top-websites gist (no active program match) |
| sellfy.com | 35 | 0 | 0 | 31 | 4 | top-websites gist (no active program match) |
| sendspace.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| seroundtable.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| services.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| shareasale.com | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| shopify.com | 26 | 0 | 0 | 5 | 21 | [Shopify](https://hackerone.com/shopify) |
| shutterstock.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| sites.google.com | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| sketchfab.com | 20 | 0 | 0 | 4 | 16 | [Epic Games](https://hackerone.com/epicgames) |
| skfb.ly | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| skillshare.com | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| skype.com | 19 | 0 | 0 | 4 | 15 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| slack.com | 27 | 0 | 0 | 4 | 23 | [Slack](https://hackerone.com/slack) |
| slashgear.com | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| slate.com | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| slideshare.net | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| smashingmagazine.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| smile.amazon.com | 21 | 0 | 0 | 5 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| smugmug.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| snapchat.com | 23 | 0 | 0 | 5 | 18 | [Snapchat](https://hackerone.com/snapchat) |
| snip.ly | 28 | 0 | 21 | 5 | 2 | top-websites gist (no active program match) |
| socialmediatoday.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| sophos.com | 17 | 0 | 0 | 5 | 12 | [Sophos](https://bugcrowd.com/sophos) |
| soundcloud.com | 31 | 0 | 0 | 5 | 26 | [SoundCloud](https://bugcrowd.com/soundcloud) |
| sourceforge.net | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| space.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| speakerdeck.com | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| spiegel.de | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| spotify.com | 25 | 0 | 0 | 3 | 22 | [Spotify](https://hackerone.com/spotify) |
| sproutsocial.com | 23 | 0 | 0 | 1 | 22 | [Sprout Social](https://bugcrowd.com/sproutsocial) |
| squareup.com | 25 | 0 | 0 | 3 | 22 | [Square](https://bugcrowd.com/square) |
| stackoverflow.com | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| startnext.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| starwars.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| stats.g.doubleclick.net | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| stats.wp.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| steamcommunity.com | 19 | 0 | 0 | 4 | 15 | [Valve Software](https://hackerone.com/valve) |
| stock.adobe.com | 20 | 0 | 0 | 4 | 16 | [Adobe](https://hackerone.com/adobe) |
| storage.googleapis.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| store.google.com | 20 | 0 | 0 | 2 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| store.steampowered.com | 16 | 0 | 0 | 4 | 12 | [Valve Software](https://hackerone.com/valve) |
| strava.com | 24 | 1 | 0 | 4 | 19 | top-websites gist (no active program match) |
| stripe.com | 20 | 0 | 0 | 1 | 19 | [Stripe](https://hackerone.com/stripe) |
| sublimetext.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| support.apple.com | 19 | 0 | 0 | 2 | 17 | [Apple](https://security.apple.com) |
| support.cloudflare.com | 20 | 0 | 0 | 5 | 15 | [Cloudflare](https://hackerone.com/cloudflare) |
| support.google.com | 22 | 0 | 0 | 2 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| support.microsoft.com | 12 | 0 | 0 | 2 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| support.office.com | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| surveymonkey.com | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| sutterhealth.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| sxsw.com | 30 | 0 | 0 | 5 | 25 | top-websites gist (no active program match) |
| t.co | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| t.ly | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| t.me | 25 | 0 | 0 | 7 | 18 | top-websites gist (no active program match) |
| t.qq.com | 2 | 0 | 0 | 0 | 2 | [Tencent](https://en.security.tencent.com) |
| techcrunch.com | 25 | 0 | 0 | 3 | 22 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| technet.microsoft.com | 15 | 0 | 0 | 4 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| telegram.me | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| telegram.org | 23 | 0 | 0 | 4 | 19 | Telegram |
| tesla.com | 21 | 0 | 0 | 5 | 16 | [Tesla](https://bugcrowd.com/tesla) |
| tf1.fr | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| theguardian.com | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| themarthablog.com | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| themify.me | 30 | 0 | 0 | 4 | 26 | top-websites gist (no active program match) |
| thinkgeek.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| thinkwithgoogle.com | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| ticketportal.cz | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| time.com | 24 | 0 | 0 | 4 | 20 | TIME |
| timesofindia.indiatimes.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| tools.google.com | 18 | 0 | 0 | 4 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tools.ietf.org | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| translate.google.com | 22 | 0 | 0 | 2 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| treasury.gov | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| trello.com | 30 | 0 | 0 | 5 | 25 | [Trello](https://bugcrowd.com/trello) |
| trends.google.com | 18 | 0 | 0 | 3 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tripadvisor.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| trustpilot.com | 20 | 0 | 0 | 4 | 16 | [Trustpilot](https://hackerone.com/trustpilot) |
| twitter.com | 22 | 0 | 0 | 2 | 20 | [Twitter](https://hackerone.com/twitter) |
| uber.com | 17 | 0 | 0 | 1 | 16 | [Uber](https://hackerone.com/uber) |
| udemy.com | 21 | 0 | 0 | 4 | 17 | [Udemy](https://hackerone.com/udemy) |
| un.org | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| united.com | 18 | 0 | 0 | 4 | 14 | [United Airlines](https://bugcrowd.com/united-vdp) |
| untappd.com | 21 | 0 | 0 | 2 | 19 | top-websites gist (no active program match) |
| upwork.com | 21 | 0 | 0 | 1 | 20 | [Upwork](https://bugcrowd.com/upwork) |
| us.battle.net | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| use.typekit.net | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| uspto.gov | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| validator.w3.org | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| verizon.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| vice.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| video.google.com | 19 | 0 | 0 | 5 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| vimeo.com | 28 | 0 | 0 | 1 | 27 | [Vimeo](https://hackerone.com/vimeo) |
| vine.co | 24 | 0 | 0 | 3 | 21 | [Twitter](https://hackerone.com/twitter) |
| vizio.com | 25 | 0 | 0 | 5 | 20 | top-websites gist (no active program match) |
| vk.com | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| vogue.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| vr.google.com | 20 | 0 | 0 | 4 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| w3schools.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| walmart.com | 20 | 0 | 0 | 5 | 15 | [Walmart Corporation](https://corporate.walmart.com/article/responsible-disclosure-policy) |
| washingtonpost.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| waze.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| web.facebook.com | 22 | 0 | 0 | 6 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| webmd.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| webroot.com | 49 | 0 | 6 | 12 | 31 | top-websites gist (no active program match) |
| weebly.com | 30 | 0 | 0 | 6 | 24 | top-websites gist (no active program match) |
| weforum.org | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| wetransfer.com | 25 | 0 | 0 | 2 | 23 | top-websites gist (no active program match) |
| whatsapp.com | 20 | 0 | 0 | 4 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| who.int | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| wikipedia.org | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| windows.microsoft.com | 18 | 0 | 0 | 5 | 13 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| wired.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| wix.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| wordpress.com | 24 | 0 | 0 | 7 | 17 | WordPress |
| wordpress.org | 30 | 0 | 0 | 7 | 23 | [WordPress](https://hackerone.com/wordpress) |
| wp.me | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| www-01.ibm.com | 17 | 0 | 0 | 5 | 12 | [IBM](https://hackerone.com/ibm) |
| www.ietf.org | 23 | 0 | 0 | 2 | 21 | IETF |
| xbox.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| xing.com | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| yadi.sk | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| yahoo.com | 18 | 0 | 0 | 5 | 13 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| yandex.com | 23 | 0 | 0 | 5 | 18 | [Yandex](https://yandex.com/bugbounty/index) |
| yandex.ru | 23 | 0 | 0 | 6 | 17 | [Yandex](https://yandex.com/bugbounty/index) |
| yelp.com | 22 | 0 | 0 | 5 | 17 | [Yelp](https://hackerone.com/yelp) |
| yoursite.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| youtube-nocookie.com | 7 | 0 | 1 | 1 | 5 | Google |
| youtube.com | 19 | 0 | 0 | 1 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| zalo.me | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| zdnet.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| zeit.de | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| zen.yandex.ru | 25 | 0 | 0 | 7 | 18 | [Yandex](https://yandex.com/bugbounty/index) |
| zillow.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| zoom.us | 49 | 0 | 9 | 5 | 35 | [Zoom](https://explore.zoom.us/docs/ent/h1.html) |
