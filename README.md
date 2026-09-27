# Bounty Hunt - Findings Index (Passive Re-audit)

Re-test date: 2026-09-27 (UTC; Asia/Taipei 2026-09-27). **635 of the 635 sites currently in this repo were passively re-audited (100% coverage after re-runs #8-#15; re-run #15 re-scanned ALL sites this pass with the extended passive suite + new #15 passive classes, branch codex/passive-redo)** with a non-aggressive methodology: passive reconnaissance (DNS records incl. wildcard/CNAME-chain detection, DNSSEC status, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomain logs) plus read-only checks (TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HTTP/HTTPS security headers, cookie flags incl. HttpOnly, CORS behavior with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection and sensitive-path probes, robots.txt asset map, TCP-connect port state, HSTS preload-list membership, certificate validity-window checks, CSP directive analysis, cacheable-document header analysis, compound Secure+SameSite cookie gaps, single-nameserver risk, PTR reverse-record fingerprint, cookie-flag surface (SameSite-without-Secure, long session lifetimes, framework-attributable cookies), cross-domain redirect handoff, plain-HTTP cookie surface, app-association well-known endpoints, error-page fingerprinting, CAA absence, multi-issuer CT footprint, OCSP-stapling observation, certificate hygiene from existing DER (short serial, self-signed leaf, CA:TRUE, X.509 v1/v2, CRL distribution-point reachability), HSTS subdomain coverage, deprecated X-Frame-Options ALLOW-FROM, Referrer-Policy unsafe-url, Server version disclosure, public-suffix cookie Domain, low-entropy session tokens, meta-tag security policies, SRI-less third-party scripts, third-party iframes, security.txt contact, sitemap inventory, observed-handshake hygiene (RFC 8996 deprecated TLS 1.0/1.1, RC4/3DES weak-primitive ciphers, static-RSA key exchange without forward secrecy), root-document surface (meta-generator disclosure, forms without anti-CSRF token, plain-HTTP form actions, insecure http:// references, CSP inline-script posture, cross-host canonical URLs, plaintext e-mail addresses, third-party domain inventory), HTTP/1.0 response versions, OIDC discovery publication). No injection, no fuzzing, no forms submitted, no authenticated sessions, no state changes.

Per the repo merge convention, where another agent's active findings exceed the passive count for a site, the index keeps the higher number (those findings remain in the agents' own repos/summaries); report files below are the passive re-audit baseline.
Supplemental non-passive reports carried from main: apache.org-deepdive, coursera.org-deepdive, edx.org-deepdive, freecodecamp.org-deepdive, go.dev-deepdive, khanacademy.org-deepdive, owasp.org-deepdive (agent-deepdive zero-day sweep; 7 files, 136 findings). Their findings are already included in the base-domain rows above per the main convention, so they are not double-counted in the total.

**Total findings across all sites: 12021** (High: 77, Medium: 79, Low: 2748, Info: 9117)

| Site | Findings | High | Med | Low | Info | Program |
|---|---|---|---|---|---|---|
| 1.bp.blogspot.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| 1.usa.gov | 12 | 0 | 0 | 3 | 9 | [TTS Bug Bounty](https://hackerone.com/tts) |
| 1drv.ms | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| 2.bp.blogspot.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| 3.bp.blogspot.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| 4.bp.blogspot.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| 7-zip.org | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| a.co | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| abc.com | 25 | 0 | 0 | 3 | 22 | [The Walt Disney Company](https://hackerone.com/disney) |
| abc.net.au | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| abcnews.go.com | 30 | 0 | 0 | 10 | 20 | top-websites gist (no active program match) |
| abebooks.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| about.fb.com | 19 | 0 | 0 | 5 | 14 | [Facebook](https://www.facebook.com/whitehat) |
| about.me | 29 | 0 | 0 | 7 | 22 | top-websites gist (no active program match) |
| aboutads.info | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| accenture.com | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| accessdata.fda.gov | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| accessify.com | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| accounts.google.com | 22 | 0 | 0 | 2 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| acm.org | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| activecampaign.com | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| ad.doubleclick.net | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| adage.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| addons.mozilla.org | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| addthis.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| adf.ly | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| adobe.com | 19 | 0 | 0 | 4 | 15 | [Adobe](https://hackerone.com/adobe) |
| adobe.ly | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| ads.google.com | 21 | 0 | 0 | 4 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adssettings.google.com | 15 | 0 | 0 | 4 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adwords.google.com | 21 | 0 | 0 | 5 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| affiliate-program.amazon.com | 27 | 0 | 0 | 7 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| airbnb.com | 19 | 0 | 0 | 4 | 15 | [Airbnb](https://hackerone.com/airbnb) |
| airtable.com | 23 | 0 | 0 | 4 | 19 | [Airtable](https://hackerone.com/airtable) |
| ajax.googleapis.com | 17 | 0 | 0 | 5 | 12 | Google |
| aliexpress.com | 25 | 0 | 0 | 8 | 17 | [Alibaba](https://hackerone.com/alibaba) |
| aljazeera.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| allmusic.com | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| amazon.ca | 22 | 0 | 0 | 5 | 17 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.jp | 21 | 0 | 0 | 5 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.uk | 21 | 0 | 0 | 5 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com | 19 | 0 | 0 | 4 | 15 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.au | 20 | 0 | 0 | 4 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.br | 20 | 0 | 0 | 4 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.de | 19 | 0 | 0 | 4 | 15 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.es | 20 | 0 | 0 | 4 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.fr | 21 | 0 | 0 | 4 | 17 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.in | 21 | 0 | 0 | 4 | 17 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.it | 20 | 0 | 0 | 4 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| ameblo.jp | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| amzn.asia | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| amzn.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| amzn.to | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| analytics.google.com | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ancestry.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| animoto.com | 18 | 0 | 0 | 1 | 17 | top-websites gist (no active program match) |
| api.whatsapp.com | 10 | 0 | 0 | 2 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| apis.google.com | 17 | 0 | 0 | 6 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| app.box.com | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| apple.com | 16 | 0 | 0 | 5 | 11 | [Apple](https://security.apple.com) |
| apps.apple.com | 20 | 0 | 0 | 2 | 18 | [Apple](https://security.apple.com) |
| apps.facebook.com | 17 | 0 | 0 | 7 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| archives.gov | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| arstechnica.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| artsandculture.google.com | 19 | 0 | 0 | 2 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| asus.com | 8 | 0 | 1 | 1 | 6 | top-websites gist (no active program match) |
| aub.edu.lb | 29 | 0 | 0 | 5 | 24 | top-websites gist (no active program match) |
| automattic.com | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| aws.amazon.com | 19 | 0 | 0 | 2 | 17 | [Amazon](https://hackerone.com/amazonvrp) |
| axios.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| azure.microsoft.com | 13 | 0 | 0 | 5 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| baidu.com | 15 | 0 | 0 | 4 | 11 | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| bandcamp.com | 22 | 0 | 0 | 5 | 17 | [Epic Games](https://hackerone.com/epicgames) |
| bandsintown.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| bbb.org | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| bbc.com | 19 | 0 | 0 | 4 | 15 | [BBC](https://www.bbc.com/backstage/security-disclosure-policy/) |
| beian.gov.cn | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| bhphotovideo.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| bigthink.com | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| bild.de | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| bing.com | 21 | 0 | 0 | 8 | 13 | top-websites gist (no active program match) |
| bizjournals.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| blockchain.info | 20 | 0 | 0 | 4 | 16 | [Blockchain](https://hackerone.com/blockchain) |
| blog.google | 24 | 0 | 0 | 5 | 19 | Google |
| blog.hubspot.com | 25 | 0 | 0 | 1 | 24 | [HubSpot](https://bugcrowd.com/hubspot) |
| blog.livedoor.jp | 10 | 0 | 1 | 1 | 8 | top-websites gist (no active program match) |
| blog.us.playstation.com | 18 | 0 | 0 | 5 | 13 | [Playstation](https://hackerone.com/playstation) |
| blogger.com | 21 | 0 | 0 | 6 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| blogs.adobe.com | 4 | 0 | 1 | 1 | 2 | [Adobe](https://hackerone.com/adobe) |
| blogs.msdn.com | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| blogs.scientificamerican.com | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| blogs.windows.com | 22 | 0 | 0 | 0 | 22 | top-websites gist (no active program match) |
| blogtalkradio.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| bloomberg.com | 16 | 0 | 0 | 2 | 14 | Bloomberg |
| bluehost.com | 21 | 0 | 0 | 5 | 16 | [Bluehost](https://bugcrowd.com/newfold-bluehostindia-vdp) |
| books.google.com | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| bookstackapp.com | 19 | 0 | 0 | 4 | 15 | None (open-source project; GitHub issue tracker) |
| boredpanda.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| breitbart.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| britannica.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| buffer.com | 30 | 0 | 0 | 5 | 25 | [Buffer](https://buffer.com/legal#security) |
| bugs.chromium.org | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| business.facebook.com | 15 | 0 | 0 | 3 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| business.google.com | 21 | 0 | 0 | 5 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| business.linkedin.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| businessinsider.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| buymeacoffee.com | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| buzzfeednews.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| buzzsprout.com | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| ca.linkedin.com | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| calendar.google.com | 21 | 0 | 0 | 4 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| calendly.com | 28 | 0 | 0 | 5 | 23 | top-websites gist (no active program match) |
| cambridge.org | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| canada.ca | 39 | 0 | 8 | 4 | 27 | top-websites gist (no active program match) |
| cancerresearchuk.org | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| canva.com | 20 | 0 | 0 | 5 | 15 | [Canva](https://bugcrowd.com/canva) |
| cargocollective.com | 24 | 0 | 0 | 7 | 17 | top-websites gist (no active program match) |
| cbs.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| cdc.gov | 17 | 0 | 0 | 4 | 13 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| cdn.shopify.com | 22 | 0 | 0 | 3 | 19 | [Shopify](https://hackerone.com/shopify) |
| cdnjs.cloudflare.com | 15 | 0 | 0 | 3 | 12 | [Cloudflare](https://hackerone.com/cloudflare) |
| cell.com | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| census.gov | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| chase.com | 17 | 0 | 0 | 5 | 12 | [Chase](https://responsibledisclosure.jpmorganchase.com) |
| checkpoint.com | 13 | 0 | 0 | 4 | 9 | [Check Point](https://www.checkpoint.com/white-hat/) |
| chicagotribune.com | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| chris.pirillo.com | 20 | 0 | 0 | 1 | 19 | top-websites gist (no active program match) |
| chrisjdavis.org | 36 | 0 | 8 | 25 | 3 | top-websites gist (no active program match) |
| chrome.google.com | 16 | 0 | 0 | 4 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| chronicle.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| cisco.com | 16 | 0 | 0 | 5 | 11 | [Cisco Meraki](https://bugcrowd.com/ciscomeraki) |
| click.linksynergy.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| cloud.google.com | 16 | 0 | 0 | 2 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| cloudflare.com | 19 | 0 | 0 | 5 | 14 | [Cloudflare](https://hackerone.com/cloudflare) |
| cnbc.com | 20 | 0 | 0 | 5 | 15 | Nasdaq |
| code.google.com | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| codecanyon.net | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| codepen.io | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| codeproject.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| codex.wordpress.org | 17 | 0 | 0 | 5 | 12 | [WordPress](https://hackerone.com/wordpress) |
| coinbase.com | 17 | 0 | 0 | 3 | 14 | [Coinbase](https://hackerone.com/coinbase) |
| coinmarketcap.com | 21 | 0 | 0 | 1 | 20 | top-websites gist (no active program match) |
| collegehumor.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| connect.facebook.net | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| constantcontact.com | 22 | 0 | 0 | 5 | 17 | [Constant Contact](https://bugcrowd.com/constantcontact) |
| copyright.gov | 21 | 0 | 0 | 1 | 20 | top-websites gist (no active program match) |
| coursera.org | 22 | 0 | 4 | 9 | 9 | [Coursera](https://hackerone.com/coursera) |
| createspace.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| creativecommons.org | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| creativemarket.com | 18 | 0 | 0 | 2 | 16 | top-websites gist (no active program match) |
| cse.google.com | 14 | 0 | 0 | 3 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| css-tricks.com | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| ctt.ec | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| cyber.law.harvard.edu | 21 | 0 | 0 | 5 | 16 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| dailycaller.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| dailymotion.com | 19 | 0 | 0 | 4 | 15 | [Dailymotion](https://yeswehack.com/programs/dailymotion-public-bug-bounty) |
| dashlane.com | 19 | 0 | 0 | 2 | 17 | [Dashlane](https://hackerone.com/dashlane) |
| data.worldbank.org | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| de-de.facebook.com | 16 | 0 | 0 | 4 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| de.linkedin.com | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| deezer.com | 17 | 0 | 0 | 4 | 13 | [Deezer](https://yeswehack.com/programs/deezer-bug-bounty-program-2019) |
| denverpost.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| design.google | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| desktop.github.com | 13 | 0 | 0 | 4 | 9 | [GitHub](https://hackerone.com/github) |
| developer.android.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| developer.apple.com | 18 | 0 | 0 | 1 | 17 | [Apple](https://security.apple.com) |
| developer.chrome.com | 18 | 0 | 0 | 1 | 17 | top-websites gist (no active program match) |
| developers.facebook.com | 11 | 0 | 0 | 3 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| developers.google.com | 20 | 0 | 0 | 2 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| digitalocean.com | 20 | 0 | 0 | 4 | 16 | [DigitalOcean](https://hackerone.com/digitalocean) |
| digitaltrends.com | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| diigo.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| discordapp.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| disqus.com | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| dl.dropbox.com | 12 | 0 | 0 | 3 | 9 | [DropBox](https://bugcrowd.com/dropbox) |
| dl.dropboxusercontent.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| docker.com | 17 | 0 | 0 | 4 | 13 | Docker |
| docs.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| docs.microsoft.com | 15 | 0 | 0 | 3 | 12 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| download.macromedia.com | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| download.microsoft.com | 16 | 0 | 0 | 5 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| dribbble.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| drift.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| drive.google.com | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| dropbox.com | 19 | 0 | 0 | 5 | 14 | [DropBox](https://bugcrowd.com/dropbox) |
| drupal.org | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| dw.com | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| dx.doi.org | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| ea.com | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| earth.google.com | 17 | 0 | 0 | 3 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ec.europa.eu | 20 | 0 | 0 | 5 | 15 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| economictimes.indiatimes.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| economist.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| edx.org | 24 | 0 | 4 | 13 | 7 | top-websites gist (no active program match) |
| eepurl.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| eff.org | 17 | 0 | 0 | 3 | 14 | [EFF](https://www.eff.org/security/) |
| elmundo.es | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| en-gb.facebook.com | 16 | 0 | 0 | 4 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| en.advertisercommunity.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| en.wikipedia.org | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| engadget.com | 18 | 0 | 0 | 4 | 14 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| envato.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| eonline.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| epa.gov | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| es.wikipedia.org | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| espn.com | 22 | 0 | 0 | 5 | 17 | [The Walt Disney Company](https://hackerone.com/disney) |
| etsy.com | 20 | 0 | 0 | 8 | 12 | [Etsy](https://bugcrowd.com/etsy) |
| eur-lex.europa.eu | 25 | 0 | 0 | 7 | 18 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europa.eu | 19 | 0 | 0 | 5 | 14 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europarl.europa.eu | 19 | 0 | 0 | 4 | 15 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| event.on24.com | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| eventbrite.com | 19 | 0 | 0 | 5 | 14 | [Eventbrite](https://www.eventbrite.com/security/) |
| eventim.de | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| events.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| evernote.com | 23 | 0 | 0 | 4 | 19 | [Evernote](https://hackerone.com/evernote) |
| expedia.com | 18 | 0 | 0 | 4 | 14 | [Expedia Group](https://hackerone.com/expediagroup) |
| faa.gov | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| facebook.com | 18 | 0 | 0 | 7 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| families.google.com | 16 | 0 | 0 | 3 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fastcompany.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| fb.com | 17 | 0 | 0 | 4 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| fb.me | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| fbi.gov | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| feeds.feedburner.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| filezilla-project.org | 18 | 0 | 1 | 4 | 13 | [FileZilla](https://hackerone.com/filezilla) |
| finance.yahoo.com | 18 | 0 | 0 | 3 | 15 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| firstdata.com | 16 | 0 | 0 | 7 | 9 | top-websites gist (no active program match) |
| fiverr.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| flavors.me | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| flic.kr | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| flickr.com | 18 | 0 | 0 | 3 | 15 | [Flickr](https://hackerone.com/flickr) |
| flipboard.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| flow.microsoft.com | 11 | 0 | 0 | 5 | 6 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| fonts.google.com | 15 | 0 | 0 | 2 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fonts.googleapis.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| forbes.com | 15 | 0 | 0 | 3 | 12 | Forbes |
| forms.gle | 13 | 0 | 0 | 4 | 9 | Google |
| forms.office.com | 18 | 0 | 0 | 5 | 13 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| foxnews.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| fr.wikipedia.org | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| france24.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| franchising.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| freelancer.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| freewebs.com | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| ftc.gov | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| funnyordie.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| g.co | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| g.page | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| g1.globo.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| gartner.com | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| geni.us | 34 | 26 | 1 | 4 | 3 | top-websites gist (no active program match) |
| get.adobe.com | 14 | 0 | 0 | 5 | 9 | [Adobe](https://hackerone.com/adobe) |
| get.google.com | 16 | 0 | 0 | 4 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| getpocket.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| getresponse.com | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| giphy.com | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| gist.github.com | 16 | 0 | 0 | 3 | 13 | [GitHub](https://hackerone.com/github) |
| github.com | 19 | 0 | 0 | 2 | 17 | [GitHub](https://hackerone.com/github) |
| gitlab.com | 38 | 0 | 9 | 2 | 27 | [GitLab](https://hackerone.com/gitlab) |
| gitter.im | 18 | 0 | 0 | 5 | 13 | [GitLab](https://hackerone.com/gitlab) |
| gleam.io | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| globalnews.ca | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| gmpg.org | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| gofundme.com | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| golang.org | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| goo.gle | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| google-analytics.com | 15 | 0 | 0 | 4 | 11 | Google |
| google.be | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| google.ca | 18 | 0 | 0 | 4 | 14 | Google |
| google.co.uk | 18 | 0 | 0 | 4 | 14 | Google |
| google.co.za | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| google.com | 19 | 0 | 0 | 5 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| google.com.br | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| google.de | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| google.it | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| google.nl | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| google.se | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| googleadservices.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| googletagmanager.com | 15 | 0 | 0 | 4 | 11 | Google |
| googlewebmastercentral.blogspot.com | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| gov.uk | 15 | 0 | 0 | 4 | 11 | [NCSC UK](https://hackerone.com/ncsc_uk) |
| greenpeace.org | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| groups.google.com | 18 | 0 | 0 | 5 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gsuite.google.com | 18 | 0 | 0 | 4 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gumroad.com | 32 | 0 | 0 | 7 | 25 | top-websites gist (no active program match) |
| hangouts.google.com | 17 | 0 | 0 | 5 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| hbo.com | 22 | 0 | 0 | 7 | 15 | top-websites gist (no active program match) |
| hbr.org | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| health.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| health.harvard.edu | 20 | 0 | 0 | 4 | 16 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| healthline.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| heise.de | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| help.apple.com | 15 | 0 | 0 | 1 | 14 | [Apple](https://security.apple.com) |
| helpx.adobe.com | 15 | 0 | 0 | 4 | 11 | [Adobe](https://hackerone.com/adobe) |
| hkrsa.asia | 39 | 0 | 2 | 5 | 32 | top-websites gist (no active program match) |
| homedepot.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| hostgator.com | 23 | 0 | 0 | 6 | 17 | [Host Gator](https://bugcrowd.com/hostgator) |
| hostinger.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| hp.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| humblebundle.com | 21 | 0 | 0 | 4 | 17 | [Humble Bundle](https://bugcrowd.com/humblebundle) |
| i.imgur.com | 19 | 0 | 0 | 5 | 14 | [Imgur](https://hackerone.com/imgur) |
| i.redd.it | 15 | 0 | 0 | 4 | 11 | [Reddit](https://hackerone.com/reddit) |
| i0.wp.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| i2.wp.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| ibm.com | 21 | 0 | 0 | 6 | 15 | [IBM](https://hackerone.com/ibm) |
| iconfinder.com | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| idealo.de | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| ietf.org | 25 | 0 | 0 | 5 | 20 | IETF |
| ifttt.com | 19 | 0 | 0 | 0 | 19 | top-websites gist (no active program match) |
| ikea.com | 19 | 0 | 0 | 6 | 13 | [IKEA](https://bugs.ikea.com/) |
| imdb.com | 18 | 0 | 0 | 3 | 15 | [IMDB](https://help.imdb.com/article/imdb/general-information/how-to-report-security-issues-and-vulnerabilities/G99J5YVB8SBBMJ73?ref_=helpart_nav_14#) |
| img.youtube.com | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| imgur.com | 26 | 0 | 0 | 5 | 21 | [Imgur](https://hackerone.com/imgur) |
| in.linkedin.com | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| inc.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| indiewire.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| infusionsoft.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| inkscape.org | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| instagram.com | 15 | 0 | 0 | 4 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| institutvajrayogini.fr | 25 | 0 | 1 | 4 | 20 | top-websites gist (no active program match) |
| instructables.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| intel.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| irs.gov | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| is.gd | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| issuu.com | 15 | 0 | 0 | 3 | 12 | [Issuu](https://issuu.com/responsible-disclosure) |
| istockphoto.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| it.linkedin.com | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| itunes.apple.com | 21 | 0 | 0 | 3 | 18 | [Apple](https://security.apple.com) |
| j.mp | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| ja-jp.facebook.com | 16 | 0 | 0 | 4 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| ja.wikipedia.org | 25 | 1 | 1 | 21 | 2 | top-websites gist (no active program match) |
| japantimes.co.jp | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| jetbrains.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| join.slack.com | 22 | 0 | 0 | 6 | 16 | [Slack](https://hackerone.com/slack) |
| journals.sagepub.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| jstor.org | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| justgiving.com | 20 | 0 | 0 | 1 | 19 | top-websites gist (no active program match) |
| keep.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| khanacademy.org | 27 | 0 | 4 | 13 | 10 | [Khan Academy](https://hackerone.com/khanacademy) |
| kiva.org | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| kobo.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| kraken.com | 18 | 0 | 0 | 3 | 15 | [Kraken](https://www.kraken.com/en-us/features/security/bug-bounty) |
| l.facebook.com | 15 | 0 | 0 | 6 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| laughingsquid.com | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| launchpad.net | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| lemonde.fr | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| lenovo.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| lh3.googleusercontent.com | 17 | 0 | 0 | 4 | 13 | Google |
| lh4.googleusercontent.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| lh5.ggpht.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| lifehack.org | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| line.me | 19 | 0 | 0 | 4 | 15 | [LINE](https://hackerone.com/line) |
| link.springer.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| linkedin.com | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| linktr.ee | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| livestream.com | 21 | 0 | 0 | 5 | 16 | [Livestream](https://hackerone.com/livestream) |
| lmgtfy.com | 29 | 0 | 0 | 5 | 24 | top-websites gist (no active program match) |
| login.microsoftonline.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| logitech.com | 22 | 0 | 0 | 5 | 17 | [Logitech](https://hackerone.com/logitech) |
| lulu.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| lynda.com | 22 | 0 | 0 | 7 | 15 | top-websites gist (no active program match) |
| m.facebook.com | 16 | 0 | 0 | 6 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| m.me | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| m.youtube.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mail.google.com | 15 | 0 | 0 | 1 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mailchimp.com | 18 | 0 | 0 | 5 | 13 | [Intuit](https://hackerone.com/intuit_rdp) |
| makeuseof.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| maps.google.co.jp | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| maps.google.co.nz | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| maps.google.com | 16 | 0 | 0 | 4 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| maps.googleapis.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| maps.gstatic.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| market.android.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| marketingplatform.google.com | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| marketwatch.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| marriott.com | 19 | 0 | 0 | 6 | 13 | [Marriott](https://hackerone.com/marriott) |
| mashable.com | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| medium.com | 18 | 0 | 0 | 2 | 16 | top-websites gist (no active program match) |
| meet.google.com | 13 | 0 | 0 | 2 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| meetup.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| mega.nz | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| mentalfloss.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| messenger.com | 17 | 0 | 0 | 8 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| meta.wikimedia.org | 25 | 2 | 1 | 20 | 2 | top-websites gist (no active program match) |
| metmuseum.org | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| microsoft.com | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| mixcloud.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| mlb.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| mobile.twitter.com | 20 | 0 | 0 | 3 | 17 | [Twitter](https://hackerone.com/twitter) |
| moma.org | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| money.yandex.ru | 4 | 0 | 0 | 2 | 2 | [Yandex](https://yandex.com/bugbounty/index) |
| monster.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| moz.com | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| mp.weixin.qq.com | 20 | 0 | 0 | 5 | 15 | [Tencent](https://en.security.tencent.com) |
| msdn.microsoft.com | 13 | 0 | 0 | 4 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| msn.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| music.apple.com | 20 | 0 | 0 | 2 | 18 | [Apple](https://security.apple.com) |
| myaccount.google.com | 15 | 0 | 0 | 2 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| myfitnesspal.com | 22 | 0 | 0 | 6 | 16 | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| myspace.com | 27 | 0 | 0 | 9 | 18 | top-websites gist (no active program match) |
| nasa.gov | 16 | 0 | 0 | 3 | 13 | [Nasa VDP](https://bugcrowd.com/engagements/nasa-vdp) |
| nature.com | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| ncbi.nlm.nih.gov | 22 | 0 | 0 | 2 | 20 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| neilpatel.com | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| nejm.org | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| netbeans.org | 21 | 0 | 0 | 7 | 14 | top-websites gist (no active program match) |
| netflix.com | 20 | 0 | 0 | 4 | 16 | [Netflix](https://bugcrowd.com/netflix) |
| networkadvertising.org | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| newegg.com | 17 | 0 | 0 | 3 | 14 | [Newegg](https://hackerone.com/newegg) |
| news.google.com | 15 | 0 | 0 | 2 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| news.harvard.edu | 12 | 0 | 0 | 2 | 10 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| news.mit.edu | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| news.yahoo.com | 16 | 0 | 0 | 5 | 11 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| note.mu | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| notion.so | 38 | 0 | 9 | 2 | 27 | top-websites gist (no active program match) |
| nvidia.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| nydailynews.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| nypost.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| nytimes.com | 17 | 0 | 0 | 3 | 14 | The New York Times |
| oecd.org | 31 | 0 | 0 | 29 | 2 | top-websites gist (no active program match) |
| ok.ru | 29 | 0 | 0 | 5 | 24 | top-websites gist (no active program match) |
| online.wsj.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| open.spotify.com | 18 | 0 | 0 | 3 | 15 | [Spotify](https://hackerone.com/spotify) |
| opera.com | 17 | 0 | 0 | 4 | 13 | [Opera Public Bug Bounty](https://bugcrowd.com/opera) |
| opinionator.blogs.nytimes.com | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| oracle.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| otto.de | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| ouest-france.fr | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| overcast.fm | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| ow.ly | 12 | 0 | 0 | 2 | 10 | [Hootsuite](https://www.hootsuite.com/security) |
| pandora.com | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| patents.google.com | 10 | 0 | 0 | 2 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| paypal.com | 20 | 0 | 0 | 5 | 15 | [PayPal](https://hackerone.com/paypal) |
| paypal.me | 19 | 0 | 0 | 4 | 15 | [PayPal](https://hackerone.com/paypal) |
| pbs.twimg.com | 11 | 0 | 0 | 2 | 9 | [Twitter](https://hackerone.com/twitter) |
| pcworld.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| penguinrandomhouse.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| periscope.tv | 17 | 0 | 0 | 4 | 13 | [Twitter](https://hackerone.com/twitter) |
| pewresearch.org | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| pexels.com | 20 | 0 | 0 | 4 | 16 | [Pexels](https://bugcrowd.com/pexels) |
| photos.app.goo.gl | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| photos.google.com | 16 | 0 | 0 | 3 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| php.net | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| picasaweb.google.com | 17 | 0 | 0 | 5 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pinterest.co.uk | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| pinterest.com | 14 | 0 | 0 | 4 | 10 | [Pinterest](https://bugcrowd.com/pinterest) |
| pipes.yahoo.com | 2 | 0 | 0 | 0 | 2 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| pitchfork.com | 21 | 0 | 0 | 2 | 19 | top-websites gist (no active program match) |
| pixabay.com | 19 | 0 | 0 | 2 | 17 | [Pixabay](https://bugcrowd.com/pixabay) |
| pixiv.net | 18 | 0 | 0 | 4 | 14 | [Pixiv](https://hackerone.com/pixiv) |
| pixlr.com | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| pl.wikipedia.org | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| platform.twitter.com | 13 | 0 | 0 | 4 | 9 | [Twitter](https://hackerone.com/twitter) |
| play.google.com | 21 | 0 | 0 | 4 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| player.vimeo.com | 16 | 0 | 0 | 1 | 15 | [Vimeo](https://hackerone.com/vimeo) |
| plaza.rakuten.co.jp | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| plus.google.com | 19 | 0 | 0 | 6 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| podcasts.apple.com | 20 | 0 | 0 | 2 | 18 | [Apple](https://security.apple.com) |
| podcasts.google.com | 16 | 0 | 0 | 4 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| poetryfoundation.org | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| policies.google.com | 19 | 0 | 0 | 5 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pond5.com | 24 | 0 | 0 | 7 | 17 | top-websites gist (no active program match) |
| popularmechanics.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| postmates.com | 28 | 0 | 0 | 4 | 24 | [Postmates](https://hackerone.com/postmates) |
| privacy.microsoft.com | 13 | 0 | 0 | 5 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| prnewswire.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| prnt.sc | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| productforums.google.com | 16 | 0 | 0 | 5 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| producthunt.com | 32 | 26 | 0 | 5 | 1 | top-websites gist (no active program match) |
| profiles.google.com | 21 | 0 | 0 | 8 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| psychologytoday.com | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| pt.slideshare.net | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| purl.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| puu.sh | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| python.org | 32 | 0 | 1 | 27 | 4 | PSF |
| quora.com | 19 | 0 | 0 | 5 | 14 | [Quora](https://hackerone.com/quora) |
| ranker.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| ravelry.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| raw.githubusercontent.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| reacts.ru | 16 | 0 | 3 | 2 | 11 | top-websites gist (no active program match) |
| realvnc.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| redbubble.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| redbull.com | 17 | 0 | 0 | 4 | 13 | [Redbull](https://app.intigriti.com/programs/redbull/redbull/detail) |
| reddit.com | 15 | 0 | 0 | 2 | 13 | [Reddit](https://hackerone.com/reddit) |
| redhat.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| researchgate.net | 18 | 0 | 0 | 4 | 14 | [Research Gate](https://explore.researchgate.net/display/support/Security+and+vulnerability) |
| residentadvisor.net | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| reuters.com | 22 | 0 | 0 | 6 | 16 | Reuters |
| reverbnation.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| rollingstone.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| rottentomatoes.com | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| ru.wikipedia.org | 22 | 1 | 1 | 18 | 2 | top-websites gist (no active program match) |
| s-media-cache-ak0.pinimg.com | 12 | 0 | 0 | 6 | 6 | top-websites gist (no active program match) |
| s0.wp.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| salesforce.com | 19 | 0 | 0 | 6 | 13 | [Salesforce](https://www.salesforce.com/company/disclosure/) |
| samsung.com | 16 | 0 | 0 | 5 | 11 | [Samsung TV](https://samsungtvbounty.com) |
| sciencedaily.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| scribd.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| search.google.com | 16 | 0 | 0 | 4 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| secure.gravatar.com | 20 | 0 | 0 | 1 | 19 | top-websites gist (no active program match) |
| sellfy.com | 35 | 0 | 0 | 31 | 4 | top-websites gist (no active program match) |
| sendspace.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| seroundtable.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| services.google.com | 16 | 0 | 0 | 4 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| shareasale.com | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| shopify.com | 22 | 0 | 0 | 5 | 17 | [Shopify](https://hackerone.com/shopify) |
| shutterstock.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| sites.google.com | 16 | 0 | 0 | 3 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| sketchfab.com | 17 | 0 | 0 | 4 | 13 | [Epic Games](https://hackerone.com/epicgames) |
| skfb.ly | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| skillshare.com | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| skype.com | 17 | 0 | 0 | 4 | 13 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| slack.com | 21 | 0 | 0 | 4 | 17 | [Slack](https://hackerone.com/slack) |
| slashgear.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| slate.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| slideshare.net | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| smashingmagazine.com | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| smile.amazon.com | 18 | 0 | 0 | 5 | 13 | [Amazon](https://hackerone.com/amazonvrp) |
| smugmug.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| snapchat.com | 21 | 0 | 0 | 5 | 16 | [Snapchat](https://hackerone.com/snapchat) |
| snip.ly | 28 | 21 | 0 | 5 | 2 | top-websites gist (no active program match) |
| socialmediatoday.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| sophos.com | 15 | 0 | 0 | 5 | 10 | [Sophos](https://bugcrowd.com/sophos) |
| soundcloud.com | 25 | 0 | 0 | 5 | 20 | [SoundCloud](https://bugcrowd.com/soundcloud) |
| sourceforge.net | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| space.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| speakerdeck.com | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| spiegel.de | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| spotify.com | 22 | 0 | 0 | 3 | 19 | [Spotify](https://hackerone.com/spotify) |
| sproutsocial.com | 20 | 0 | 0 | 1 | 19 | [Sprout Social](https://bugcrowd.com/sproutsocial) |
| squareup.com | 24 | 0 | 0 | 3 | 21 | [Square](https://bugcrowd.com/square) |
| stackoverflow.com | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| startnext.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| starwars.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| stats.g.doubleclick.net | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| stats.wp.com | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| steamcommunity.com | 17 | 0 | 0 | 4 | 13 | [Valve Software](https://hackerone.com/valve) |
| stock.adobe.com | 17 | 0 | 0 | 4 | 13 | [Adobe](https://hackerone.com/adobe) |
| storage.googleapis.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| store.google.com | 17 | 0 | 0 | 2 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| store.steampowered.com | 14 | 0 | 0 | 4 | 10 | [Valve Software](https://hackerone.com/valve) |
| strava.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| stripe.com | 18 | 0 | 0 | 1 | 17 | [Stripe](https://hackerone.com/stripe) |
| sublimetext.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| support.apple.com | 17 | 0 | 0 | 2 | 15 | [Apple](https://security.apple.com) |
| support.cloudflare.com | 18 | 0 | 0 | 5 | 13 | [Cloudflare](https://hackerone.com/cloudflare) |
| support.google.com | 19 | 0 | 0 | 2 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| support.microsoft.com | 10 | 0 | 0 | 3 | 7 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| support.office.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| surveymonkey.com | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| sutterhealth.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| sxsw.com | 28 | 0 | 0 | 5 | 23 | top-websites gist (no active program match) |
| t.co | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| t.ly | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| t.me | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| t.qq.com | 2 | 0 | 0 | 0 | 2 | [Tencent](https://en.security.tencent.com) |
| techcrunch.com | 23 | 0 | 0 | 3 | 20 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| technet.microsoft.com | 13 | 0 | 0 | 4 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| telegram.me | 21 | 0 | 0 | 7 | 14 | top-websites gist (no active program match) |
| telegram.org | 19 | 0 | 0 | 4 | 15 | Telegram |
| tesla.com | 19 | 0 | 0 | 5 | 14 | [Tesla](https://bugcrowd.com/tesla) |
| tf1.fr | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| theguardian.com | 19 | 0 | 0 | 7 | 12 | top-websites gist (no active program match) |
| themarthablog.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| themify.me | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| thinkgeek.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| thinkwithgoogle.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| ticketportal.cz | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| time.com | 20 | 0 | 0 | 4 | 16 | TIME |
| timesofindia.indiatimes.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| tools.google.com | 15 | 0 | 0 | 4 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tools.ietf.org | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| translate.google.com | 17 | 0 | 0 | 2 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| treasury.gov | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| trello.com | 23 | 0 | 0 | 5 | 18 | [Trello](https://bugcrowd.com/trello) |
| trends.google.com | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tripadvisor.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| trustpilot.com | 17 | 0 | 0 | 4 | 13 | [Trustpilot](https://hackerone.com/trustpilot) |
| twitter.com | 18 | 0 | 0 | 2 | 16 | [Twitter](https://hackerone.com/twitter) |
| uber.com | 13 | 0 | 0 | 1 | 12 | [Uber](https://hackerone.com/uber) |
| udemy.com | 17 | 0 | 0 | 4 | 13 | [Udemy](https://hackerone.com/udemy) |
| un.org | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| united.com | 16 | 0 | 0 | 4 | 12 | [United Airlines](https://bugcrowd.com/united-vdp) |
| untappd.com | 18 | 0 | 0 | 2 | 16 | top-websites gist (no active program match) |
| upwork.com | 17 | 0 | 0 | 1 | 16 | [Upwork](https://bugcrowd.com/upwork) |
| us.battle.net | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| use.typekit.net | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| uspto.gov | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| validator.w3.org | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| verizon.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| vice.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| video.google.com | 15 | 0 | 0 | 5 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| vimeo.com | 22 | 0 | 0 | 1 | 21 | [Vimeo](https://hackerone.com/vimeo) |
| vine.co | 19 | 0 | 0 | 3 | 16 | [Twitter](https://hackerone.com/twitter) |
| vizio.com | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| vk.com | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| vogue.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| vr.google.com | 17 | 0 | 0 | 4 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| w3schools.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| walmart.com | 17 | 0 | 0 | 5 | 12 | [Walmart Corporation](https://corporate.walmart.com/article/responsible-disclosure-policy) |
| washingtonpost.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| waze.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| web.facebook.com | 16 | 0 | 0 | 4 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| webmd.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| webroot.com | 47 | 0 | 6 | 12 | 29 | top-websites gist (no active program match) |
| weebly.com | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| weforum.org | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| wetransfer.com | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| whatsapp.com | 18 | 0 | 0 | 4 | 14 | [Facebook](https://www.facebook.com/whitehat) |
| who.int | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| wikipedia.org | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| windows.microsoft.com | 15 | 0 | 0 | 5 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| wired.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| wix.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| wordpress.com | 22 | 0 | 0 | 7 | 15 | WordPress |
| wordpress.org | 27 | 0 | 0 | 7 | 20 | [WordPress](https://hackerone.com/wordpress) |
| wp.me | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| www-01.ibm.com | 16 | 0 | 0 | 5 | 11 | [IBM](https://hackerone.com/ibm) |
| www.ietf.org | 19 | 0 | 0 | 2 | 17 | IETF |
| xbox.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| xing.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| yadi.sk | 18 | 0 | 1 | 16 | 1 | top-websites gist (no active program match) |
| yahoo.com | 17 | 0 | 0 | 5 | 12 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| yandex.com | 20 | 0 | 0 | 5 | 15 | [Yandex](https://yandex.com/bugbounty/index) |
| yandex.ru | 21 | 0 | 0 | 6 | 15 | [Yandex](https://yandex.com/bugbounty/index) |
| yelp.com | 18 | 0 | 0 | 5 | 13 | [Yelp](https://hackerone.com/yelp) |
| yoursite.com | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| youtube-nocookie.com | 6 | 0 | 1 | 1 | 4 | Google |
| youtube.com | 16 | 0 | 0 | 1 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| zalo.me | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| zdnet.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| zeit.de | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| zen.yandex.ru | 21 | 0 | 0 | 7 | 14 | [Yandex](https://yandex.com/bugbounty/index) |
| zillow.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| zoom.us | 44 | 0 | 9 | 5 | 30 | [Zoom](https://explore.zoom.us/docs/ent/h1.html) |
