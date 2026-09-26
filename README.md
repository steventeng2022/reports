# Bounty Hunt - Findings Index (Passive Re-audit)

Re-test date: 2026-09-27 (UTC; Asia/Taipei 2026-09-27). **635 of the 635 sites currently in this repo were passively re-audited (100% coverage after re-runs #8-#11; re-run #11 re-scanned ALL sites this pass with the extended passive suite, branch codex/passive-redo)** with a non-aggressive methodology: passive reconnaissance (DNS records incl. wildcard/CNAME-chain detection, DNSSEC status, SPF/DMARC/MTA-STS/TLS-RPT mail-policy analysis, certificate-transparency subdomain logs) plus read-only checks (TLS protocol/cipher/certificate DER analysis incl. OCSP revocation status and SNI fallback, HTTP/HTTPS security headers, cookie flags incl. HttpOnly, CORS behavior with Origin header, GET-only open-redirect/redirect-loop/Host-header-reflection and sensitive-path probes, robots.txt asset map, TCP-connect port state, HSTS preload-list membership). No injection, no fuzzing, no forms submitted, no authenticated sessions, no state changes.

Per the repo merge convention, where another agent's active findings exceed the passive count for a site, the index keeps the higher number (those findings remain in the agents' own repos/summaries); report files below are the passive re-audit baseline.
Supplemental non-passive reports carried from main: apache.org-deepdive, coursera.org-deepdive, edx.org-deepdive, freecodecamp.org-deepdive, go.dev-deepdive, khanacademy.org-deepdive, owasp.org-deepdive (agent-deepdive zero-day sweep; 7 files, 136 findings). Their findings are already included in the base-domain rows above per the main convention, so they are not double-counted in the total.

**Total findings across all sites: 9827** (High: 79, Medium: 82, Low: 2474, Info: 7192)

| Site | Findings | High | Med | Low | Info | Program |
|---|---|---|---|---|---|---|
| 1.bp.blogspot.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| 1.usa.gov | 9 | 0 | 0 | 1 | 8 | [TTS Bug Bounty](https://hackerone.com/tts) |
| 1drv.ms | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| 2.bp.blogspot.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| 3.bp.blogspot.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| 4.bp.blogspot.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| 7-zip.org | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| a.co | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| abc.com | 18 | 0 | 0 | 3 | 15 | [The Walt Disney Company](https://hackerone.com/disney) |
| abc.net.au | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| abcnews.go.com | 23 | 0 | 0 | 8 | 15 | top-websites gist (no active program match) |
| abebooks.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| about.fb.com | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| about.me | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| aboutads.info | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| accenture.com | 12 | 0 | 0 | 0 | 12 | top-websites gist (no active program match) |
| accessdata.fda.gov | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| accessify.com | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| accounts.google.com | 15 | 0 | 0 | 1 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| acm.org | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| activecampaign.com | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| ad.doubleclick.net | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| adage.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| addons.mozilla.org | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| addthis.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| adf.ly | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| adobe.com | 16 | 0 | 0 | 4 | 12 | [Adobe](https://hackerone.com/adobe) |
| adobe.ly | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| ads.google.com | 17 | 0 | 0 | 3 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adssettings.google.com | 11 | 0 | 0 | 2 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adwords.google.com | 16 | 0 | 0 | 3 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| affiliate-program.amazon.com | 17 | 0 | 0 | 5 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| airbnb.com | 17 | 0 | 0 | 4 | 13 | [Airbnb](https://hackerone.com/airbnb) |
| airtable.com | 12 | 0 | 0 | 1 | 11 | [Airtable](https://hackerone.com/airtable) |
| ajax.googleapis.com | 15 | 0 | 0 | 4 | 11 | Google |
| aliexpress.com | 22 | 0 | 0 | 8 | 14 | [Alibaba](https://hackerone.com/alibaba) |
| aljazeera.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| allmusic.com | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| amazon.ca | 18 | 0 | 0 | 5 | 13 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.jp | 18 | 0 | 0 | 5 | 13 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.uk | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.au | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.br | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.de | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.es | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.fr | 17 | 0 | 0 | 4 | 13 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.in | 17 | 0 | 0 | 4 | 13 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.it | 16 | 0 | 0 | 4 | 12 | [Amazon](https://hackerone.com/amazonvrp) |
| ameblo.jp | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| amzn.asia | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| amzn.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| amzn.to | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| analytics.google.com | 12 | 0 | 0 | 3 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ancestry.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| animoto.com | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| api.whatsapp.com | 8 | 0 | 0 | 1 | 7 | [Facebook](https://www.facebook.com/whitehat) |
| apis.google.com | 15 | 0 | 0 | 6 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| app.box.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| apple.com | 14 | 0 | 0 | 5 | 9 | [Apple](https://security.apple.com) |
| apps.apple.com | 14 | 0 | 0 | 1 | 13 | [Apple](https://security.apple.com) |
| apps.facebook.com | 16 | 0 | 0 | 6 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| archives.gov | 11 | 0 | 0 | 0 | 11 | top-websites gist (no active program match) |
| arstechnica.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| artsandculture.google.com | 12 | 0 | 0 | 1 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| asus.com | 8 | 0 | 1 | 1 | 6 | top-websites gist (no active program match) |
| aub.edu.lb | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| automattic.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| aws.amazon.com | 13 | 0 | 0 | 2 | 11 | [Amazon](https://hackerone.com/amazonvrp) |
| axios.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| azure.microsoft.com | 13 | 0 | 0 | 5 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| baidu.com | 14 | 0 | 0 | 4 | 10 | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| bandcamp.com | 15 | 0 | 0 | 4 | 11 | [Epic Games](https://hackerone.com/epicgames) |
| bandsintown.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| bbb.org | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| bbc.com | 17 | 0 | 0 | 3 | 14 | [BBC](https://www.bbc.com/backstage/security-disclosure-policy/) |
| beian.gov.cn | 5 | 0 | 0 | 1 | 4 | top-websites gist (no active program match) |
| bhphotovideo.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| bigthink.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| bild.de | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| bing.com | 18 | 0 | 0 | 7 | 11 | top-websites gist (no active program match) |
| bizjournals.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| blockchain.info | 18 | 0 | 0 | 3 | 15 | [Blockchain](https://hackerone.com/blockchain) |
| blog.google | 18 | 0 | 0 | 4 | 14 | Google |
| blog.hubspot.com | 12 | 0 | 0 | 0 | 12 | [HubSpot](https://bugcrowd.com/hubspot) |
| blog.livedoor.jp | 5 | 0 | 1 | 0 | 4 | top-websites gist (no active program match) |
| blog.us.playstation.com | 14 | 0 | 0 | 4 | 10 | [Playstation](https://hackerone.com/playstation) |
| blogger.com | 19 | 0 | 0 | 6 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| blogs.adobe.com | 4 | 0 | 1 | 1 | 2 | [Adobe](https://hackerone.com/adobe) |
| blogs.msdn.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| blogs.scientificamerican.com | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| blogs.windows.com | 14 | 0 | 0 | 0 | 14 | top-websites gist (no active program match) |
| blogtalkradio.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| bloomberg.com | 14 | 0 | 0 | 4 | 10 | Bloomberg |
| bluehost.com | 21 | 0 | 0 | 5 | 16 | [Bluehost](https://bugcrowd.com/newfold-bluehostindia-vdp) |
| books.google.com | 16 | 0 | 0 | 3 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| bookstackapp.com | 16 | 0 | 0 | 4 | 12 | None (open-source project; GitHub issue tracker) |
| boredpanda.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| breitbart.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| britannica.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| buffer.com | 24 | 0 | 0 | 5 | 19 | [Buffer](https://buffer.com/legal#security) |
| bugs.chromium.org | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| business.facebook.com | 12 | 0 | 0 | 2 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| business.google.com | 15 | 0 | 0 | 2 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| business.linkedin.com | 15 | 0 | 0 | 0 | 15 | top-websites gist (no active program match) |
| businessinsider.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| buymeacoffee.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| buzzfeednews.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| buzzsprout.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| ca.linkedin.com | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| calendar.google.com | 18 | 0 | 0 | 4 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| calendly.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| cambridge.org | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| canada.ca | 39 | 0 | 8 | 4 | 27 | top-websites gist (no active program match) |
| cancerresearchuk.org | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| canva.com | 18 | 0 | 0 | 5 | 13 | [Canva](https://bugcrowd.com/canva) |
| cargocollective.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| cbs.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| cdc.gov | 15 | 0 | 0 | 4 | 11 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| cdn.shopify.com | 16 | 0 | 0 | 3 | 13 | [Shopify](https://hackerone.com/shopify) |
| cdnjs.cloudflare.com | 15 | 0 | 0 | 3 | 12 | [Cloudflare](https://hackerone.com/cloudflare) |
| cell.com | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| census.gov | 5 | 0 | 0 | 1 | 4 | top-websites gist (no active program match) |
| chase.com | 15 | 0 | 0 | 5 | 10 | [Chase](https://responsibledisclosure.jpmorganchase.com) |
| checkpoint.com | 13 | 0 | 0 | 4 | 9 | [Check Point](https://www.checkpoint.com/white-hat/) |
| chicagotribune.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| chris.pirillo.com | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| chrisjdavis.org | 36 | 0 | 8 | 25 | 3 | top-websites gist (no active program match) |
| chrome.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| chronicle.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| cisco.com | 15 | 0 | 0 | 5 | 10 | [Cisco Meraki](https://bugcrowd.com/ciscomeraki) |
| click.linksynergy.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| cloud.google.com | 9 | 0 | 0 | 0 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| cloudflare.com | 17 | 0 | 0 | 5 | 12 | [Cloudflare](https://hackerone.com/cloudflare) |
| cnbc.com | 15 | 0 | 0 | 5 | 10 | Nasdaq |
| code.google.com | 11 | 0 | 0 | 2 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| codecanyon.net | 16 | 0 | 0 | 8 | 8 | top-websites gist (no active program match) |
| codepen.io | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| codeproject.com | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| codex.wordpress.org | 15 | 0 | 0 | 6 | 9 | [WordPress](https://hackerone.com/wordpress) |
| coinbase.com | 15 | 0 | 0 | 3 | 12 | [Coinbase](https://hackerone.com/coinbase) |
| coinmarketcap.com | 11 | 0 | 0 | 0 | 11 | top-websites gist (no active program match) |
| collegehumor.com | 5 | 0 | 0 | 1 | 4 | top-websites gist (no active program match) |
| connect.facebook.net | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| constantcontact.com | 17 | 0 | 0 | 4 | 13 | [Constant Contact](https://bugcrowd.com/constantcontact) |
| copyright.gov | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| coursera.org | 22 | 0 | 4 | 9 | 9 | [Coursera](https://hackerone.com/coursera) |
| createspace.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| creativecommons.org | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| creativemarket.com | 12 | 0 | 0 | 1 | 11 | top-websites gist (no active program match) |
| cse.google.com | 10 | 0 | 0 | 1 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| css-tricks.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| ctt.ec | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| cyber.law.harvard.edu | 18 | 0 | 0 | 4 | 14 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| dailycaller.com | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| dailymotion.com | 16 | 0 | 0 | 4 | 12 | [Dailymotion](https://yeswehack.com/programs/dailymotion-public-bug-bounty) |
| dashlane.com | 16 | 0 | 0 | 2 | 14 | [Dashlane](https://hackerone.com/dashlane) |
| data.worldbank.org | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| de-de.facebook.com | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| de.linkedin.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| deezer.com | 15 | 0 | 0 | 4 | 11 | [Deezer](https://yeswehack.com/programs/deezer-bug-bounty-program-2019) |
| denverpost.com | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| design.google | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| desktop.github.com | 12 | 0 | 0 | 4 | 8 | [GitHub](https://hackerone.com/github) |
| developer.android.com | 10 | 0 | 0 | 0 | 10 | top-websites gist (no active program match) |
| developer.apple.com | 11 | 0 | 0 | 0 | 11 | [Apple](https://security.apple.com) |
| developer.chrome.com | 11 | 0 | 0 | 0 | 11 | top-websites gist (no active program match) |
| developers.facebook.com | 9 | 0 | 0 | 2 | 7 | [Facebook](https://www.facebook.com/whitehat) |
| developers.google.com | 13 | 0 | 0 | 1 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| digitalocean.com | 18 | 0 | 0 | 4 | 14 | [DigitalOcean](https://hackerone.com/digitalocean) |
| digitaltrends.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| diigo.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| discordapp.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| disqus.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| dl.dropbox.com | 12 | 0 | 0 | 3 | 9 | [DropBox](https://bugcrowd.com/dropbox) |
| dl.dropboxusercontent.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| docker.com | 16 | 0 | 0 | 4 | 12 | Docker |
| docs.google.com | 13 | 0 | 0 | 1 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| docs.microsoft.com | 12 | 0 | 0 | 3 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| download.macromedia.com | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| download.microsoft.com | 12 | 0 | 0 | 4 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| dribbble.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| drift.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| drive.google.com | 14 | 0 | 0 | 2 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| dropbox.com | 18 | 0 | 0 | 5 | 13 | [DropBox](https://bugcrowd.com/dropbox) |
| drupal.org | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| dw.com | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| dx.doi.org | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| ea.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| earth.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ec.europa.eu | 16 | 0 | 0 | 4 | 12 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| economictimes.indiatimes.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| economist.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| edx.org | 24 | 0 | 4 | 13 | 7 | top-websites gist (no active program match) |
| eepurl.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| eff.org | 15 | 0 | 0 | 3 | 12 | [EFF](https://www.eff.org/security/) |
| elmundo.es | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| en-gb.facebook.com | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| en.advertisercommunity.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| en.wikipedia.org | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| engadget.com | 15 | 0 | 0 | 4 | 11 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| envato.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| eonline.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| epa.gov | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| es.wikipedia.org | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| espn.com | 21 | 0 | 0 | 5 | 16 | [The Walt Disney Company](https://hackerone.com/disney) |
| etsy.com | 18 | 0 | 0 | 8 | 10 | [Etsy](https://bugcrowd.com/etsy) |
| eur-lex.europa.eu | 14 | 0 | 0 | 4 | 10 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europa.eu | 17 | 0 | 0 | 5 | 12 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europarl.europa.eu | 16 | 0 | 0 | 4 | 12 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| event.on24.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| eventbrite.com | 17 | 0 | 0 | 5 | 12 | [Eventbrite](https://www.eventbrite.com/security/) |
| eventim.de | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| events.google.com | 12 | 0 | 0 | 3 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| evernote.com | 17 | 0 | 0 | 4 | 13 | [Evernote](https://hackerone.com/evernote) |
| expedia.com | 16 | 0 | 0 | 4 | 12 | [Expedia Group](https://hackerone.com/expediagroup) |
| faa.gov | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| facebook.com | 17 | 0 | 0 | 7 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| families.google.com | 10 | 0 | 0 | 0 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fastcompany.com | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| fb.com | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| fb.me | 10 | 0 | 0 | 3 | 7 | [Facebook](https://www.facebook.com/whitehat) |
| fbi.gov | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| feeds.feedburner.com | 12 | 0 | 0 | 2 | 10 | top-websites gist (no active program match) |
| filezilla-project.org | 17 | 0 | 1 | 4 | 12 | [FileZilla](https://hackerone.com/filezilla) |
| finance.yahoo.com | 11 | 0 | 0 | 3 | 8 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| firstdata.com | 16 | 0 | 0 | 7 | 9 | top-websites gist (no active program match) |
| fiverr.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| flavors.me | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| flic.kr | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| flickr.com | 12 | 0 | 0 | 2 | 10 | [Flickr](https://hackerone.com/flickr) |
| flipboard.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| flow.microsoft.com | 10 | 0 | 0 | 4 | 6 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| fonts.google.com | 10 | 0 | 0 | 1 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fonts.googleapis.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| forbes.com | 14 | 0 | 0 | 3 | 11 | Forbes |
| forms.gle | 9 | 0 | 0 | 3 | 6 | Google |
| forms.office.com | 14 | 0 | 0 | 4 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| foxnews.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| fr.wikipedia.org | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| france24.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| franchising.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| freelancer.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| freewebs.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| ftc.gov | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| funnyordie.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| g.co | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| g.page | 12 | 0 | 0 | 0 | 12 | top-websites gist (no active program match) |
| g1.globo.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| gartner.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| geni.us | 34 | 26 | 1 | 4 | 3 | top-websites gist (no active program match) |
| get.adobe.com | 12 | 0 | 0 | 4 | 8 | [Adobe](https://hackerone.com/adobe) |
| get.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| getpocket.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| getresponse.com | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| giphy.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| gist.github.com | 15 | 0 | 0 | 2 | 13 | [GitHub](https://hackerone.com/github) |
| github.com | 12 | 0 | 0 | 1 | 11 | [GitHub](https://hackerone.com/github) |
| gitlab.com | 32 | 0 | 9 | 0 | 23 | [GitLab](https://hackerone.com/gitlab) |
| gitter.im | 16 | 0 | 0 | 5 | 11 | [GitLab](https://hackerone.com/gitlab) |
| gleam.io | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| globalnews.ca | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| gmpg.org | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| gofundme.com | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| golang.org | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| goo.gle | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google-analytics.com | 13 | 0 | 0 | 3 | 10 | Google |
| google.be | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| google.ca | 15 | 0 | 0 | 4 | 11 | Google |
| google.co.uk | 15 | 0 | 0 | 4 | 11 | Google |
| google.co.za | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| google.com | 15 | 0 | 0 | 5 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| google.com.br | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| google.de | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| google.it | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| google.nl | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| google.se | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| googleadservices.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| googletagmanager.com | 13 | 0 | 0 | 4 | 9 | Google |
| googlewebmastercentral.blogspot.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| gov.uk | 13 | 0 | 0 | 3 | 10 | [NCSC UK](https://hackerone.com/ncsc_uk) |
| greenpeace.org | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| groups.google.com | 14 | 0 | 0 | 3 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gsuite.google.com | 14 | 0 | 0 | 3 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gumroad.com | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| hangouts.google.com | 15 | 0 | 0 | 4 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| hbo.com | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| hbr.org | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| health.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| health.harvard.edu | 17 | 0 | 0 | 4 | 13 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| healthline.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| heise.de | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| help.apple.com | 13 | 0 | 0 | 1 | 12 | [Apple](https://security.apple.com) |
| helpx.adobe.com | 13 | 0 | 0 | 6 | 7 | [Adobe](https://hackerone.com/adobe) |
| hkrsa.asia | 29 | 0 | 2 | 5 | 22 | top-websites gist (no active program match) |
| homedepot.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| hostgator.com | 22 | 0 | 0 | 6 | 16 | [Host Gator](https://bugcrowd.com/hostgator) |
| hostinger.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| hp.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| humblebundle.com | 18 | 0 | 0 | 4 | 14 | [Humble Bundle](https://bugcrowd.com/humblebundle) |
| i.imgur.com | 17 | 0 | 0 | 5 | 12 | [Imgur](https://hackerone.com/imgur) |
| i.redd.it | 14 | 0 | 0 | 4 | 10 | [Reddit](https://hackerone.com/reddit) |
| i0.wp.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| i2.wp.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| ibm.com | 18 | 0 | 0 | 6 | 12 | [IBM](https://hackerone.com/ibm) |
| iconfinder.com | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| idealo.de | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| ietf.org | 22 | 0 | 0 | 5 | 17 | IETF |
| ifttt.com | 12 | 0 | 0 | 0 | 12 | top-websites gist (no active program match) |
| ikea.com | 19 | 0 | 0 | 6 | 13 | [IKEA](https://bugs.ikea.com/) |
| imdb.com | 15 | 0 | 0 | 3 | 12 | [IMDB](https://help.imdb.com/article/imdb/general-information/how-to-report-security-issues-and-vulnerabilities/G99J5YVB8SBBMJ73?ref_=helpart_nav_14#) |
| img.youtube.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| imgur.com | 18 | 0 | 0 | 5 | 13 | [Imgur](https://hackerone.com/imgur) |
| in.linkedin.com | 17 | 0 | 0 | 10 | 7 | top-websites gist (no active program match) |
| inc.com | 14 | 0 | 0 | 2 | 12 | top-websites gist (no active program match) |
| indiewire.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| infusionsoft.com | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| inkscape.org | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| instagram.com | 14 | 0 | 0 | 4 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| institutvajrayogini.fr | 22 | 0 | 1 | 4 | 17 | top-websites gist (no active program match) |
| instructables.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| intel.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| irs.gov | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| is.gd | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| issuu.com | 11 | 0 | 0 | 3 | 8 | [Issuu](https://issuu.com/responsible-disclosure) |
| istockphoto.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| it.linkedin.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| itunes.apple.com | 15 | 0 | 0 | 2 | 13 | [Apple](https://security.apple.com) |
| j.mp | 15 | 0 | 1 | 7 | 7 | top-websites gist (no active program match) |
| ja-jp.facebook.com | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| ja.wikipedia.org | 25 | 1 | 1 | 21 | 2 | top-websites gist (no active program match) |
| japantimes.co.jp | 13 | 0 | 0 | 2 | 11 | top-websites gist (no active program match) |
| jetbrains.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| join.slack.com | 16 | 0 | 0 | 6 | 10 | [Slack](https://hackerone.com/slack) |
| journals.sagepub.com | 13 | 0 | 0 | 2 | 11 | top-websites gist (no active program match) |
| jstor.org | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| justgiving.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| keep.google.com | 14 | 0 | 0 | 2 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| khanacademy.org | 27 | 0 | 4 | 13 | 10 | [Khan Academy](https://hackerone.com/khanacademy) |
| kiva.org | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| kobo.com | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| kraken.com | 16 | 0 | 0 | 3 | 13 | [Kraken](https://www.kraken.com/en-us/features/security/bug-bounty) |
| l.facebook.com | 13 | 0 | 0 | 5 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| laughingsquid.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| launchpad.net | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| lemonde.fr | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| lenovo.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| lh3.googleusercontent.com | 16 | 0 | 0 | 4 | 12 | Google |
| lh4.googleusercontent.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| lh5.ggpht.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| lifehack.org | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| line.me | 17 | 0 | 0 | 4 | 13 | [LINE](https://hackerone.com/line) |
| link.springer.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| linkedin.com | 11 | 0 | 0 | 0 | 11 | top-websites gist (no active program match) |
| linktr.ee | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| livestream.com | 18 | 0 | 0 | 4 | 14 | [Livestream](https://hackerone.com/livestream) |
| lmgtfy.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| login.microsoftonline.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| logitech.com | 17 | 0 | 0 | 5 | 12 | [Logitech](https://hackerone.com/logitech) |
| lulu.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| lynda.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| m.facebook.com | 14 | 0 | 0 | 5 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| m.me | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| m.youtube.com | 13 | 0 | 0 | 1 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mail.google.com | 12 | 0 | 0 | 1 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mailchimp.com | 16 | 0 | 0 | 5 | 11 | [Intuit](https://hackerone.com/intuit_rdp) |
| makeuseof.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| maps.google.co.jp | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| maps.google.co.nz | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| maps.google.com | 14 | 0 | 0 | 4 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| maps.googleapis.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| maps.gstatic.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| market.android.com | 12 | 0 | 0 | 2 | 10 | top-websites gist (no active program match) |
| marketingplatform.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| marketwatch.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| marriott.com | 17 | 0 | 0 | 6 | 11 | [Marriott](https://hackerone.com/marriott) |
| mashable.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| medium.com | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| meet.google.com | 9 | 0 | 0 | 0 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| meetup.com | 14 | 0 | 0 | 2 | 12 | top-websites gist (no active program match) |
| mega.nz | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| mentalfloss.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| messenger.com | 16 | 0 | 0 | 8 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| meta.wikimedia.org | 25 | 2 | 1 | 20 | 2 | top-websites gist (no active program match) |
| metmuseum.org | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| microsoft.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| mixcloud.com | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| mlb.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| mobile.twitter.com | 17 | 0 | 0 | 3 | 14 | [Twitter](https://hackerone.com/twitter) |
| moma.org | 15 | 0 | 0 | 2 | 13 | top-websites gist (no active program match) |
| money.yandex.ru | 3 | 0 | 0 | 2 | 1 | [Yandex](https://yandex.com/bugbounty/index) |
| monster.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| moz.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| mp.weixin.qq.com | 14 | 0 | 0 | 5 | 9 | [Tencent](https://en.security.tencent.com) |
| msdn.microsoft.com | 11 | 0 | 0 | 3 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| msn.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| music.apple.com | 13 | 0 | 0 | 1 | 12 | [Apple](https://security.apple.com) |
| myaccount.google.com | 12 | 0 | 0 | 1 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| myfitnesspal.com | 19 | 0 | 0 | 6 | 13 | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| myspace.com | 20 | 0 | 0 | 8 | 12 | top-websites gist (no active program match) |
| nasa.gov | 14 | 0 | 0 | 3 | 11 | [Nasa VDP](https://bugcrowd.com/engagements/nasa-vdp) |
| nature.com | 20 | 0 | 0 | 7 | 13 | top-websites gist (no active program match) |
| ncbi.nlm.nih.gov | 15 | 0 | 0 | 2 | 13 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| neilpatel.com | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| nejm.org | 19 | 0 | 0 | 7 | 12 | top-websites gist (no active program match) |
| netbeans.org | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| netflix.com | 17 | 0 | 0 | 4 | 13 | [Netflix](https://bugcrowd.com/netflix) |
| networkadvertising.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| newegg.com | 16 | 0 | 0 | 3 | 13 | [Newegg](https://hackerone.com/newegg) |
| news.google.com | 10 | 0 | 0 | 0 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| news.harvard.edu | 10 | 0 | 0 | 2 | 8 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| news.mit.edu | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| news.yahoo.com | 12 | 0 | 0 | 3 | 9 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| note.mu | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| notion.so | 35 | 0 | 9 | 2 | 24 | top-websites gist (no active program match) |
| nvidia.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| nydailynews.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| nypost.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| nytimes.com | 15 | 0 | 0 | 2 | 13 | The New York Times |
| oecd.org | 31 | 0 | 0 | 29 | 2 | top-websites gist (no active program match) |
| ok.ru | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| online.wsj.com | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| open.spotify.com | 12 | 0 | 0 | 1 | 11 | [Spotify](https://hackerone.com/spotify) |
| opera.com | 14 | 0 | 0 | 3 | 11 | [Opera Public Bug Bounty](https://bugcrowd.com/opera) |
| opinionator.blogs.nytimes.com | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| oracle.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| otto.de | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| ouest-france.fr | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| overcast.fm | 13 | 0 | 0 | 2 | 11 | top-websites gist (no active program match) |
| ow.ly | 9 | 0 | 0 | 2 | 7 | [Hootsuite](https://www.hootsuite.com/security) |
| pandora.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| patents.google.com | 9 | 0 | 0 | 2 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| paypal.com | 19 | 0 | 0 | 5 | 14 | [PayPal](https://hackerone.com/paypal) |
| paypal.me | 16 | 0 | 0 | 4 | 12 | [PayPal](https://hackerone.com/paypal) |
| pbs.twimg.com | 11 | 0 | 0 | 2 | 9 | [Twitter](https://hackerone.com/twitter) |
| pcworld.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| penguinrandomhouse.com | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| periscope.tv | 12 | 0 | 0 | 3 | 9 | [Twitter](https://hackerone.com/twitter) |
| pewresearch.org | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| pexels.com | 19 | 0 | 0 | 4 | 15 | [Pexels](https://bugcrowd.com/pexels) |
| photos.app.goo.gl | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| photos.google.com | 10 | 0 | 0 | 0 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| php.net | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| picasaweb.google.com | 14 | 0 | 0 | 4 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pinterest.co.uk | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| pinterest.com | 14 | 0 | 0 | 4 | 10 | [Pinterest](https://bugcrowd.com/pinterest) |
| pipes.yahoo.com | 2 | 0 | 0 | 0 | 2 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| pitchfork.com | 17 | 0 | 0 | 9 | 8 | top-websites gist (no active program match) |
| pixabay.com | 13 | 0 | 0 | 1 | 12 | [Pixabay](https://bugcrowd.com/pixabay) |
| pixiv.net | 16 | 0 | 0 | 3 | 13 | [Pixiv](https://hackerone.com/pixiv) |
| pixlr.com | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| pl.wikipedia.org | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| platform.twitter.com | 12 | 0 | 0 | 4 | 8 | [Twitter](https://hackerone.com/twitter) |
| play.google.com | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| player.vimeo.com | 14 | 0 | 0 | 1 | 13 | [Vimeo](https://hackerone.com/vimeo) |
| plaza.rakuten.co.jp | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| plus.google.com | 16 | 0 | 0 | 5 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| podcasts.apple.com | 13 | 0 | 0 | 1 | 12 | [Apple](https://security.apple.com) |
| podcasts.google.com | 12 | 0 | 0 | 3 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| poetryfoundation.org | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| policies.google.com | 15 | 0 | 0 | 4 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pond5.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| popularmechanics.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| postmates.com | 18 | 0 | 0 | 2 | 16 | [Postmates](https://hackerone.com/postmates) |
| privacy.microsoft.com | 13 | 0 | 0 | 3 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| prnewswire.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| prnt.sc | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| productforums.google.com | 15 | 0 | 0 | 5 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| producthunt.com | 32 | 26 | 0 | 5 | 1 | top-websites gist (no active program match) |
| profiles.google.com | 14 | 0 | 0 | 4 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| psychologytoday.com | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| pt.slideshare.net | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| purl.org | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| puu.sh | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| python.org | 32 | 0 | 1 | 27 | 4 | PSF |
| quora.com | 17 | 0 | 0 | 5 | 12 | [Quora](https://hackerone.com/quora) |
| ranker.com | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| ravelry.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| raw.githubusercontent.com | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| reacts.ru | 15 | 0 | 3 | 2 | 10 | top-websites gist (no active program match) |
| realvnc.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| redbubble.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| redbull.com | 15 | 0 | 0 | 4 | 11 | [Redbull](https://app.intigriti.com/programs/redbull/redbull/detail) |
| reddit.com | 14 | 0 | 0 | 2 | 12 | [Reddit](https://hackerone.com/reddit) |
| redhat.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| researchgate.net | 18 | 0 | 0 | 4 | 14 | [Research Gate](https://explore.researchgate.net/display/support/Security+and+vulnerability) |
| residentadvisor.net | 17 | 0 | 0 | 1 | 16 | top-websites gist (no active program match) |
| reuters.com | 19 | 0 | 0 | 6 | 13 | Reuters |
| reverbnation.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| rollingstone.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| rottentomatoes.com | 13 | 0 | 0 | 2 | 11 | top-websites gist (no active program match) |
| ru.wikipedia.org | 22 | 1 | 1 | 18 | 2 | top-websites gist (no active program match) |
| s-media-cache-ak0.pinimg.com | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| s0.wp.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| salesforce.com | 19 | 0 | 0 | 6 | 13 | [Salesforce](https://www.salesforce.com/company/disclosure/) |
| samsung.com | 15 | 0 | 0 | 5 | 10 | [Samsung TV](https://samsungtvbounty.com) |
| sciencedaily.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| scribd.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| search.google.com | 12 | 0 | 0 | 3 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| secure.gravatar.com | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| sellfy.com | 35 | 0 | 0 | 31 | 4 | top-websites gist (no active program match) |
| sendspace.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| seroundtable.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| services.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| shareasale.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| shopify.com | 18 | 0 | 0 | 5 | 13 | [Shopify](https://hackerone.com/shopify) |
| shutterstock.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| sites.google.com | 13 | 0 | 0 | 2 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| sketchfab.com | 15 | 0 | 0 | 4 | 11 | [Epic Games](https://hackerone.com/epicgames) |
| skfb.ly | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| skillshare.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| skype.com | 15 | 0 | 0 | 3 | 12 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| slack.com | 13 | 0 | 0 | 4 | 9 | [Slack](https://hackerone.com/slack) |
| slashgear.com | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| slate.com | 12 | 0 | 0 | 2 | 10 | top-websites gist (no active program match) |
| slideshare.net | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| smashingmagazine.com | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| smile.amazon.com | 13 | 0 | 0 | 4 | 9 | [Amazon](https://hackerone.com/amazonvrp) |
| smugmug.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| snapchat.com | 15 | 0 | 0 | 5 | 10 | [Snapchat](https://hackerone.com/snapchat) |
| snip.ly | 28 | 21 | 0 | 5 | 2 | top-websites gist (no active program match) |
| socialmediatoday.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| sophos.com | 13 | 0 | 0 | 5 | 8 | [Sophos](https://bugcrowd.com/sophos) |
| soundcloud.com | 17 | 0 | 0 | 5 | 12 | [SoundCloud](https://bugcrowd.com/soundcloud) |
| sourceforge.net | 14 | 0 | 0 | 2 | 12 | top-websites gist (no active program match) |
| space.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| speakerdeck.com | 15 | 0 | 0 | 1 | 14 | top-websites gist (no active program match) |
| spiegel.de | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| spotify.com | 16 | 0 | 0 | 2 | 14 | [Spotify](https://hackerone.com/spotify) |
| sproutsocial.com | 12 | 0 | 0 | 0 | 12 | [Sprout Social](https://bugcrowd.com/sproutsocial) |
| squareup.com | 18 | 0 | 0 | 3 | 15 | [Square](https://bugcrowd.com/square) |
| stackoverflow.com | 16 | 0 | 0 | 2 | 14 | top-websites gist (no active program match) |
| startnext.com | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| starwars.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| stats.g.doubleclick.net | 13 | 2 | 1 | 7 | 3 | top-websites gist (no active program match) |
| stats.wp.com | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| steamcommunity.com | 15 | 0 | 0 | 4 | 11 | [Valve Software](https://hackerone.com/valve) |
| stock.adobe.com | 15 | 0 | 0 | 4 | 11 | [Adobe](https://hackerone.com/adobe) |
| storage.googleapis.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| store.google.com | 11 | 0 | 0 | 0 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| store.steampowered.com | 12 | 0 | 0 | 4 | 8 | [Valve Software](https://hackerone.com/valve) |
| strava.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| stripe.com | 9 | 0 | 0 | 0 | 9 | [Stripe](https://hackerone.com/stripe) |
| sublimetext.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| support.apple.com | 10 | 0 | 0 | 1 | 9 | [Apple](https://security.apple.com) |
| support.cloudflare.com | 15 | 0 | 0 | 4 | 11 | [Cloudflare](https://hackerone.com/cloudflare) |
| support.google.com | 15 | 0 | 0 | 2 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| support.microsoft.com | 10 | 0 | 0 | 3 | 7 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| support.office.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| surveymonkey.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| sutterhealth.org | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| sxsw.com | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| t.co | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| t.ly | 18 | 0 | 0 | 2 | 16 | top-websites gist (no active program match) |
| t.me | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| t.qq.com | 2 | 0 | 0 | 0 | 2 | [Tencent](https://en.security.tencent.com) |
| techcrunch.com | 14 | 0 | 0 | 2 | 12 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| technet.microsoft.com | 11 | 0 | 0 | 3 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| telegram.me | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| telegram.org | 13 | 0 | 0 | 4 | 9 | Telegram |
| tesla.com | 16 | 0 | 0 | 5 | 11 | [Tesla](https://bugcrowd.com/tesla) |
| tf1.fr | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| theguardian.com | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| themarthablog.com | 16 | 0 | 1 | 6 | 9 | top-websites gist (no active program match) |
| themify.me | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| thinkgeek.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| thinkwithgoogle.com | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| ticketportal.cz | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| time.com | 16 | 0 | 0 | 4 | 12 | TIME |
| timesofindia.indiatimes.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| tools.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tools.ietf.org | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| translate.google.com | 11 | 0 | 0 | 1 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| treasury.gov | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| trello.com | 15 | 0 | 0 | 4 | 11 | [Trello](https://bugcrowd.com/trello) |
| trends.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tripadvisor.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| trustpilot.com | 14 | 0 | 0 | 4 | 10 | [Trustpilot](https://hackerone.com/trustpilot) |
| twitter.com | 12 | 0 | 0 | 0 | 12 | [Twitter](https://hackerone.com/twitter) |
| uber.com | 13 | 0 | 0 | 1 | 12 | [Uber](https://hackerone.com/uber) |
| udemy.com | 11 | 0 | 0 | 3 | 8 | [Udemy](https://hackerone.com/udemy) |
| un.org | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| united.com | 16 | 0 | 0 | 5 | 11 | [United Airlines](https://bugcrowd.com/united-vdp) |
| untappd.com | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| upwork.com | 12 | 0 | 0 | 1 | 11 | [Upwork](https://bugcrowd.com/upwork) |
| us.battle.net | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| use.typekit.net | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| uspto.gov | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| validator.w3.org | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| verizon.com | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| vice.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| video.google.com | 12 | 0 | 0 | 4 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| vimeo.com | 15 | 0 | 0 | 1 | 14 | [Vimeo](https://hackerone.com/vimeo) |
| vine.co | 10 | 0 | 0 | 1 | 9 | [Twitter](https://hackerone.com/twitter) |
| vizio.com | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| vk.com | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| vogue.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| vr.google.com | 13 | 0 | 0 | 3 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| w3schools.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| walmart.com | 16 | 0 | 0 | 4 | 12 | [Walmart Corporation](https://corporate.walmart.com/article/responsible-disclosure-policy) |
| washingtonpost.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| waze.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| web.facebook.com | 13 | 0 | 0 | 3 | 10 | [Facebook](https://www.facebook.com/whitehat) |
| webmd.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| webroot.com | 42 | 0 | 6 | 8 | 28 | top-websites gist (no active program match) |
| weebly.com | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| weforum.org | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| wetransfer.com | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| whatsapp.com | 17 | 0 | 0 | 4 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| who.int | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| wikipedia.org | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| windows.microsoft.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| wired.com | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| wix.com | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| wordpress.com | 20 | 0 | 0 | 6 | 14 | WordPress |
| wordpress.org | 19 | 0 | 0 | 7 | 12 | [WordPress](https://hackerone.com/wordpress) |
| wp.me | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| www-01.ibm.com | 15 | 0 | 0 | 3 | 12 | [IBM](https://hackerone.com/ibm) |
| www.ietf.org | 13 | 0 | 0 | 2 | 11 | IETF |
| xbox.com | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| xing.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| yadi.sk | 18 | 0 | 1 | 16 | 1 | top-websites gist (no active program match) |
| yahoo.com | 13 | 0 | 0 | 4 | 9 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| yandex.com | 13 | 0 | 0 | 4 | 9 | [Yandex](https://yandex.com/bugbounty/index) |
| yandex.ru | 15 | 0 | 0 | 5 | 10 | [Yandex](https://yandex.com/bugbounty/index) |
| yelp.com | 17 | 0 | 0 | 5 | 12 | [Yelp](https://hackerone.com/yelp) |
| yoursite.com | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| youtube-nocookie.com | 6 | 0 | 1 | 1 | 4 | Google |
| youtube.com | 11 | 0 | 0 | 0 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| zalo.me | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| zdnet.com | 17 | 0 | 0 | 5 | 12 | top-websites gist (no active program match) |
| zeit.de | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| zen.yandex.ru | 18 | 0 | 0 | 6 | 12 | [Yandex](https://yandex.com/bugbounty/index) |
| zillow.com | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| zoom.us | 38 | 0 | 9 | 4 | 25 | [Zoom](https://explore.zoom.us/docs/ent/h1.html) |
