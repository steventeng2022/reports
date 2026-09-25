# Bounty Hunt - Findings Index

Hunt dates: 2026-09-24 to 2026-09-25 (Asia/Taipei). This repository combines the original scan results with the 2026-09-25 **passive / non-intrusive re-audit**. Passive checks used TLS, HTTP headers, cookie attributes, redirects, well-known files, DNS, and certificate SAN data without parameter injection, form submission, or authenticated sessions. Where a passive report replaced an active scan, the latest pre-merge active report is preserved in a collapsible appendix.

<<<<<<< HEAD
**Indexed reports: 567**

**Total primary findings across all sites: 5499** (High: 0, Medium: 9, Low: 1535, Info: 3955)

| Site | Findings | High | Med | Low | Info | Program |
|---|---:|---:|---:|---:|---:|---|
| 1.usa.gov | 9 | 0 | 0 | 1 | 8 | [TTS Bug Bounty](https://hackerone.com/tts) |
| 1drv.ms | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| 3.bp.blogspot.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| 4.bp.blogspot.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| 7-zip.org | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| abc.com | 13 | 0 | 0 | 5 | 8 | [The Walt Disney Company](https://hackerone.com/disney) |
| abcnews.go.com | 15 | 0 | 0 | 7 | 8 | top-websites gist (no active program match) |
| abebooks.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| about.fb.com | 11 | 0 | 0 | 0 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| about.me | 13 | 0 | 0 | 6 | 7 | top-websites gist (no active program match) |
| aboutads.info | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| accenture.com | 5 | 0 | 0 | 0 | 5 | top-websites gist (no active program match) |
| accessify.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| accounts.google.com | 6 | 0 | 0 | 0 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| acm.org | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| activecampaign.com | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| ad.doubleclick.net | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| adage.com | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| addons.mozilla.org | 9 | 0 | 0 | 0 | 9 | top-websites gist (no active program match) |
| adobe.com | 2 | 0 | 0 | 0 | 2 | [Adobe](https://hackerone.com/adobe) |
| adobe.ly | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| ads.google.com | 9 | 0 | 0 | 0 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adssettings.google.com | 7 | 0 | 0 | 2 | 5 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| adwords.google.com | 9 | 0 | 0 | 0 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| affiliate-program.amazon.com | 8 | 0 | 0 | 4 | 4 | [Amazon](https://hackerone.com/amazonvrp) |
| airbnb.com | 14 | 0 | 0 | 7 | 7 | [Airbnb](https://hackerone.com/airbnb) |
| airtable.com | 10 | 0 | 0 | 5 | 5 | [Airtable](https://hackerone.com/airtable) |
| ajax.googleapis.com | 10 | 0 | 0 | 0 | 10 | Google |
| aliexpress.com | 14 | 0 | 0 | 7 | 7 | [Alibaba](https://hackerone.com/alibaba) |
| aljazeera.com | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| amazon.ca | 11 | 0 | 0 | 6 | 5 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.jp | 13 | 0 | 0 | 4 | 9 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.co.uk | 12 | 0 | 0 | 4 | 8 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.au | 13 | 0 | 0 | 4 | 9 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com.br | 9 | 0 | 0 | 4 | 5 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.com | 13 | 0 | 0 | 4 | 9 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.de | 13 | 0 | 0 | 4 | 9 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.es | 10 | 0 | 0 | 4 | 6 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.fr | 9 | 0 | 0 | 4 | 5 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.in | 10 | 0 | 0 | 4 | 6 | [Amazon](https://hackerone.com/amazonvrp) |
| amazon.it | 12 | 0 | 0 | 6 | 6 | [Amazon](https://hackerone.com/amazonvrp) |
| ameblo.jp | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| amzn.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| amzn.to | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| analytics.google.com | 8 | 0 | 0 | 3 | 5 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ancestry.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| animoto.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| api.whatsapp.com | 8 | 0 | 0 | 1 | 7 | [Facebook](https://www.facebook.com/whitehat) |
| apis.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| app.box.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| apple.com | 8 | 0 | 0 | 3 | 5 | [Apple](https://security.apple.com) |
| apps.apple.com | 8 | 0 | 0 | 0 | 8 | [Apple](https://security.apple.com) |
| apps.facebook.com | 10 | 0 | 0 | 1 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| archives.gov | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| arstechnica.com | 9 | 0 | 0 | 0 | 9 | top-websites gist (no active program match) |
| artsandculture.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| asus.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| aub.edu.lb | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| aws.amazon.com | 13 | 0 | 0 | 4 | 9 | [Amazon](https://hackerone.com/amazonvrp) |
| axios.com | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| azure.microsoft.com | 13 | 0 | 0 | 5 | 8 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| baidu.com | 14 | 0 | 0 | 7 | 7 | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| bandcamp.com | 9 | 0 | 0 | 2 | 7 | [Epic Games](https://hackerone.com/epicgames) |
| bandsintown.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| bbc.com | 8 | 0 | 0 | 1 | 7 | [BBC](https://www.bbc.com/backstage/security-disclosure-policy/) |
| beian.gov.cn | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| bhphotovideo.com | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| bigthink.com | 11 | 0 | 0 | 5 | 6 | top-websites gist (no active program match) |
| bild.de | 12 | 0 | 0 | 1 | 11 | top-websites gist (no active program match) |
| bing.com | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| bizjournals.com | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| blockchain.info | 7 | 0 | 0 | 0 | 7 | [Blockchain](https://hackerone.com/blockchain) |
| blog.google | 9 | 0 | 0 | 3 | 6 | Google |
| blog.hubspot.com | 7 | 0 | 0 | 1 | 6 | [HubSpot](https://bugcrowd.com/hubspot) |
| blog.livedoor.jp | 2 | 0 | 1 | 0 | 1 | top-websites gist (no active program match) |
| blog.us.playstation.com | 10 | 0 | 0 | 0 | 10 | [Playstation](https://hackerone.com/playstation) |
| blogger.com | 7 | 0 | 0 | 2 | 5 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| blogs.adobe.com | 2 | 0 | 1 | 0 | 1 | [Adobe](https://hackerone.com/adobe) |
| blogs.msdn.com | 8 | 0 | 0 | 3 | 5 | top-websites gist (no active program match) |
| blogs.windows.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| blogtalkradio.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| bloomberg.com | 14 | 0 | 0 | 4 | 10 | Bloomberg |
| bluehost.com | 9 | 0 | 0 | 3 | 6 | [Bluehost](https://bugcrowd.com/newfold-bluehostindia-vdp) |
| books.google.com | 11 | 0 | 0 | 2 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| bookstackapp.com | 5 | 0 | 0 | 0 | 5 | None (open-source project; GitHub issue tracker) |
| breitbart.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| buffer.com | 15 | 0 | 0 | 4 | 11 | [Buffer](https://buffer.com/legal#security) |
| bugs.chromium.org | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| business.facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| business.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| businessinsider.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| buymeacoffee.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| buzzsprout.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| ca.linkedin.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| calendar.google.com | 7 | 0 | 0 | 1 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| cambridge.org | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| canada.ca | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| canva.com | 6 | 0 | 0 | 2 | 4 | [Canva](https://bugcrowd.com/canva) |
| cargocollective.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| cbs.com | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| cdc.gov | 12 | 0 | 0 | 5 | 7 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| cdn.shopify.com | 7 | 0 | 0 | 2 | 5 | [Shopify](https://hackerone.com/shopify) |
| cdnjs.cloudflare.com | 9 | 0 | 0 | 2 | 7 | [Cloudflare](https://hackerone.com/cloudflare) |
| cell.com | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| census.gov | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| chase.com | 13 | 0 | 0 | 4 | 9 | [Chase](https://responsibledisclosure.jpmorganchase.com) |
| checkpoint.com | 5 | 0 | 0 | 0 | 5 | [Check Point](https://www.checkpoint.com/white-hat/) |
| chicagotribune.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| chris.pirillo.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| chrome.google.com | 9 | 0 | 0 | 2 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| chronicle.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| cisco.com | 14 | 0 | 0 | 3 | 11 | [Cisco Meraki](https://bugcrowd.com/ciscomeraki) |
| click.linksynergy.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| cloud.google.com | 9 | 0 | 0 | 1 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| cloudflare.com | 11 | 0 | 0 | 3 | 8 | [Cloudflare](https://hackerone.com/cloudflare) |
| cnbc.com | 13 | 0 | 0 | 5 | 8 | Nasdaq |
| code.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| codepen.io | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| codeproject.com | 11 | 0 | 0 | 5 | 6 | top-websites gist (no active program match) |
| codex.wordpress.org | 15 | 0 | 0 | 6 | 9 | [WordPress](https://hackerone.com/wordpress) |
| coinbase.com | 5 | 0 | 0 | 0 | 5 | [Coinbase](https://hackerone.com/coinbase) |
| coinmarketcap.com | 6 | 0 | 0 | 0 | 6 | top-websites gist (no active program match) |
| collegehumor.com | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| constantcontact.com | 11 | 0 | 0 | 2 | 9 | [Constant Contact](https://bugcrowd.com/constantcontact) |
| copyright.gov | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| coursera.org | 8 | 0 | 0 | 1 | 7 | [Coursera](https://hackerone.com/coursera) |
| createspace.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| creativecommons.org | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| creativemarket.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| cse.google.com | 10 | 0 | 0 | 3 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| css-tricks.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| ctt.ec | 15 | 0 | 0 | 8 | 7 | top-websites gist (no active program match) |
| cyber.law.harvard.edu | 11 | 0 | 0 | 0 | 11 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| dailymotion.com | 11 | 0 | 0 | 4 | 7 | [Dailymotion](https://yeswehack.com/programs/dailymotion-public-bug-bounty) |
| dashlane.com | 8 | 0 | 0 | 3 | 5 | [Dashlane](https://hackerone.com/dashlane) |
| data.worldbank.org | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| de-de.facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| de.linkedin.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| deezer.com | 11 | 0 | 0 | 4 | 7 | [Deezer](https://yeswehack.com/programs/deezer-bug-bounty-program-2019) |
| denverpost.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| desktop.github.com | 6 | 0 | 0 | 1 | 5 | [GitHub](https://hackerone.com/github) |
| developer.android.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| developer.apple.com | 6 | 0 | 0 | 0 | 6 | [Apple](https://security.apple.com) |
| developer.chrome.com | 10 | 0 | 0 | 0 | 10 | top-websites gist (no active program match) |
| developers.facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| developers.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| digitalocean.com | 9 | 0 | 0 | 2 | 7 | [DigitalOcean](https://hackerone.com/digitalocean) |
| diigo.com | 12 | 0 | 0 | 6 | 6 | top-websites gist (no active program match) |
| discordapp.com | 6 | 0 | 0 | 0 | 6 | top-websites gist (no active program match) |
| dl.dropbox.com | 12 | 0 | 0 | 3 | 9 | [DropBox](https://bugcrowd.com/dropbox) |
| docker.com | 8 | 0 | 0 | 1 | 7 | Docker |
| docs.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| docs.microsoft.com | 9 | 0 | 0 | 3 | 6 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| download.microsoft.com | 12 | 0 | 0 | 3 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| dribbble.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| drift.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| drive.google.com | 8 | 0 | 0 | 1 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| dropbox.com | 10 | 0 | 0 | 4 | 6 | [DropBox](https://bugcrowd.com/dropbox) |
| drupal.org | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| dx.doi.org | 8 | 0 | 0 | 3 | 5 | top-websites gist (no active program match) |
| earth.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| ec.europa.eu | 9 | 0 | 0 | 1 | 8 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| economist.com | 8 | 0 | 0 | 3 | 5 | top-websites gist (no active program match) |
| edx.org | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| eepurl.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| eff.org | 8 | 0 | 0 | 2 | 6 | [EFF](https://www.eff.org/security/) |
| elmundo.es | 10 | 0 | 0 | 5 | 5 | top-websites gist (no active program match) |
| en-gb.facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| en.advertisercommunity.com | 14 | 0 | 0 | 1 | 13 | top-websites gist (no active program match) |
| en.wikipedia.org | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| engadget.com | 9 | 0 | 0 | 3 | 6 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| envato.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| eonline.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| epa.gov | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| es.wikipedia.org | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| espn.com | 11 | 0 | 0 | 4 | 7 | [The Walt Disney Company](https://hackerone.com/disney) |
| etsy.com | 14 | 0 | 0 | 7 | 7 | [Etsy](https://bugcrowd.com/etsy) |
| eur-lex.europa.eu | 8 | 0 | 0 | 4 | 4 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europa.eu | 7 | 0 | 0 | 1 | 6 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| europarl.europa.eu | 9 | 0 | 0 | 3 | 6 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| event.on24.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| eventbrite.com | 11 | 0 | 0 | 5 | 6 | [Eventbrite](https://www.eventbrite.com/security/) |
| eventim.de | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| events.google.com | 9 | 0 | 0 | 3 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| evernote.com | 9 | 0 | 0 | 4 | 5 | [Evernote](https://hackerone.com/evernote) |
| expedia.com | 11 | 0 | 0 | 5 | 6 | [Expedia Group](https://hackerone.com/expediagroup) |
| faa.gov | 13 | 0 | 0 | 7 | 6 | top-websites gist (no active program match) |
| facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| families.google.com | 9 | 0 | 0 | 2 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fb.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| fb.me | 6 | 0 | 0 | 1 | 5 | [Facebook](https://www.facebook.com/whitehat) |
| feeds.feedburner.com | 12 | 0 | 0 | 2 | 10 | top-websites gist (no active program match) |
| filezilla-project.org | 6 | 0 | 0 | 0 | 6 | [FileZilla](https://hackerone.com/filezilla) |
| finance.yahoo.com | 11 | 0 | 0 | 3 | 8 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| firstdata.com | 16 | 0 | 0 | 7 | 9 | top-websites gist (no active program match) |
| flavors.me | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| flic.kr | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| flickr.com | 7 | 0 | 0 | 2 | 5 | [Flickr](https://hackerone.com/flickr) |
| flipboard.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| flow.microsoft.com | 10 | 0 | 0 | 1 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| fonts.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| fonts.googleapis.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| forbes.com | 7 | 0 | 0 | 4 | 3 | Forbes |
| forms.gle | 6 | 0 | 0 | 3 | 3 | Google |
| forms.office.com | 14 | 0 | 0 | 4 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| foxnews.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| fr.wikipedia.org | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| franchising.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| freelancer.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| freewebs.com | 17 | 0 | 0 | 6 | 11 | top-websites gist (no active program match) |
| ftc.gov | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| g.co | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| g.page | 12 | 0 | 0 | 0 | 12 | top-websites gist (no active program match) |
| get.adobe.com | 2 | 0 | 0 | 0 | 2 | [Adobe](https://hackerone.com/adobe) |
| get.google.com | 13 | 0 | 0 | 5 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| getpocket.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| getresponse.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| gist.github.com | 5 | 0 | 0 | 0 | 5 | [GitHub](https://hackerone.com/github) |
| github.com | 6 | 0 | 0 | 1 | 5 | [GitHub](https://hackerone.com/github) |
| gitlab.com | 14 | 0 | 0 | 3 | 11 | [GitLab](https://hackerone.com/gitlab) |
| gitter.im | 8 | 0 | 0 | 3 | 5 | [GitLab](https://hackerone.com/gitlab) |
| gleam.io | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| globalnews.ca | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| golang.org | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| goo.gle | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google.com.br | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google.com | 12 | 0 | 0 | 5 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| google.de | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google.nl | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google.se | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| googleadservices.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| googlewebmastercentral.blogspot.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| gov.uk | 6 | 0 | 0 | 0 | 6 | [NCSC UK](https://hackerone.com/ncsc_uk) |
| greenpeace.org | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| groups.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| gsuite.google.com | 10 | 0 | 0 | 1 | 9 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| hangouts.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| hbo.com | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| health.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| health.harvard.edu | 8 | 0 | 0 | 2 | 6 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| healthline.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| heise.de | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| help.apple.com | 6 | 0 | 0 | 1 | 5 | [Apple](https://security.apple.com) |
| helpx.adobe.com | 13 | 0 | 0 | 6 | 7 | [Adobe](https://hackerone.com/adobe) |
| hkrsa.asia | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| homedepot.com | 14 | 0 | 0 | 7 | 7 | top-websites gist (no active program match) |
| hostgator.com | 8 | 0 | 0 | 3 | 5 | [Host Gator](https://bugcrowd.com/hostgator) |
| hp.com | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| humblebundle.com | 14 | 0 | 0 | 7 | 7 | [Humble Bundle](https://bugcrowd.com/humblebundle) |
| i.imgur.com | 14 | 0 | 0 | 4 | 10 | [Imgur](https://hackerone.com/imgur) |
| i.redd.it | 12 | 0 | 0 | 2 | 10 | [Reddit](https://hackerone.com/reddit) |
| i0.wp.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| ibm.com | 14 | 0 | 0 | 4 | 10 | [IBM](https://hackerone.com/ibm) |
| iconfinder.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| idealo.de | 14 | 0 | 0 | 7 | 7 | top-websites gist (no active program match) |
| ifttt.com | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| ikea.com | 9 | 0 | 0 | 2 | 7 | [IKEA](https://bugs.ikea.com/) |
| imdb.com | 10 | 0 | 0 | 3 | 7 | [IMDB](https://help.imdb.com/article/imdb/general-information/how-to-report-security-issues-and-vulnerabilities/G99J5YVB8SBBMJ73?ref_=helpart_nav_14#) |
| img.youtube.com | 10 | 0 | 0 | 3 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| imgur.com | 14 | 0 | 0 | 4 | 10 | [Imgur](https://hackerone.com/imgur) |
| indiewire.com | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| infusionsoft.com | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| inkscape.org | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| instagram.com | 12 | 0 | 0 | 3 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| institutvajrayogini.fr | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| instructables.com | 8 | 0 | 0 | 0 | 8 | top-websites gist (no active program match) |
| intel.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| irs.gov | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| is.gd | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| issuu.com | 11 | 0 | 0 | 1 | 10 | [Issuu](https://issuu.com/responsible-disclosure) |
| istockphoto.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| it.linkedin.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| itunes.apple.com | 10 | 0 | 0 | 3 | 7 | [Apple](https://security.apple.com) |
| ja-jp.facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| japantimes.co.jp | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| jetbrains.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| join.slack.com | 10 | 0 | 0 | 4 | 6 | [Slack](https://hackerone.com/slack) |
| journals.sagepub.com | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| jstor.org | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| keep.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| khanacademy.org | 14 | 0 | 0 | 6 | 8 | [Khan Academy](https://hackerone.com/khanacademy) |
| kiva.org | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| kobo.com | 8 | 0 | 0 | 3 | 5 | top-websites gist (no active program match) |
| kraken.com | 7 | 0 | 0 | 3 | 4 | [Kraken](https://www.kraken.com/en-us/features/security/bug-bounty) |
| l.facebook.com | 10 | 0 | 0 | 1 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| laughingsquid.com | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| launchpad.net | 9 | 0 | 0 | 0 | 9 | top-websites gist (no active program match) |
| lh5.ggpht.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| lifehack.org | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| line.me | 10 | 0 | 0 | 2 | 8 | [LINE](https://hackerone.com/line) |
| link.springer.com | 13 | 0 | 0 | 6 | 7 | top-websites gist (no active program match) |
| linkedin.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| livestream.com | 11 | 0 | 0 | 2 | 9 | [Livestream](https://hackerone.com/livestream) |
| login.microsoftonline.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| logitech.com | 6 | 0 | 0 | 1 | 5 | [Logitech](https://hackerone.com/logitech) |
| lulu.com | 12 | 0 | 0 | 6 | 6 | top-websites gist (no active program match) |
| lynda.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| m.facebook.com | 10 | 0 | 0 | 1 | 9 | [Facebook](https://www.facebook.com/whitehat) |
| m.youtube.com | 9 | 0 | 0 | 1 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mail.google.com | 6 | 0 | 0 | 0 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mailchimp.com | 10 | 0 | 0 | 4 | 6 | [Intuit](https://hackerone.com/intuit_rdp) |
| makeuseof.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| maps.google.co.jp | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| maps.google.co.nz | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| maps.google.com | 9 | 0 | 0 | 3 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| maps.gstatic.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| market.android.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| marketingplatform.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| marketwatch.com | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| marriott.com | 15 | 0 | 0 | 5 | 10 | [Marriott](https://hackerone.com/marriott) |
| mashable.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| medium.com | 5 | 0 | 0 | 0 | 5 | top-websites gist (no active program match) |
| meet.google.com | 9 | 0 | 0 | 1 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| mentalfloss.com | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| messenger.com | 11 | 0 | 0 | 4 | 7 | [Facebook](https://www.facebook.com/whitehat) |
| metmuseum.org | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| microsoft.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| mobile.twitter.com | 10 | 0 | 0 | 2 | 8 | [Twitter](https://hackerone.com/twitter) |
| moma.org | 8 | 0 | 0 | 0 | 8 | top-websites gist (no active program match) |
| money.yandex.ru | 2 | 0 | 0 | 0 | 2 | [Yandex](https://yandex.com/bugbounty/index) |
| monster.com | 2 | 0 | 1 | 0 | 1 | top-websites gist (no active program match) |
| moz.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| mp.weixin.qq.com | 13 | 0 | 0 | 4 | 9 | [Tencent](https://en.security.tencent.com) |
| msdn.microsoft.com | 9 | 0 | 0 | 3 | 6 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| msn.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| music.apple.com | 8 | 0 | 0 | 0 | 8 | [Apple](https://security.apple.com) |
| myaccount.google.com | 10 | 0 | 0 | 3 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| myfitnesspal.com | 10 | 0 | 0 | 2 | 8 | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| nasa.gov | 9 | 0 | 0 | 2 | 7 | [Nasa VDP](https://bugcrowd.com/engagements/nasa-vdp) |
| nature.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| ncbi.nlm.nih.gov | 6 | 0 | 0 | 1 | 5 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| neilpatel.com | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| netbeans.org | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| netflix.com | 15 | 0 | 0 | 4 | 11 | [Netflix](https://bugcrowd.com/netflix) |
| networkadvertising.org | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| newegg.com | 9 | 0 | 0 | 2 | 7 | [Newegg](https://hackerone.com/newegg) |
| news.google.com | 9 | 0 | 0 | 1 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| news.harvard.edu | 6 | 0 | 0 | 2 | 4 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| news.mit.edu | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| news.yahoo.com | 11 | 0 | 0 | 1 | 10 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| note.mu | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| nvidia.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| nydailynews.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| nytimes.com | 11 | 0 | 0 | 4 | 7 | The New York Times |
| ok.ru | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| online.wsj.com | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| open.spotify.com | 10 | 0 | 0 | 3 | 7 | [Spotify](https://hackerone.com/spotify) |
| opera.com | 5 | 0 | 0 | 0 | 5 | [Opera Public Bug Bounty](https://bugcrowd.com/opera) |
| oracle.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| otto.de | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| ow.ly | 8 | 0 | 0 | 2 | 6 | [Hootsuite](https://www.hootsuite.com/security) |
| patents.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| paypal.com | 10 | 0 | 0 | 2 | 8 | [PayPal](https://hackerone.com/paypal) |
| paypal.me | 12 | 0 | 0 | 2 | 10 | [PayPal](https://hackerone.com/paypal) |
| pbs.twimg.com | 11 | 0 | 0 | 2 | 9 | [Twitter](https://hackerone.com/twitter) |
| pcworld.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| penguinrandomhouse.com | 8 | 0 | 0 | 3 | 5 | top-websites gist (no active program match) |
| periscope.tv | 5 | 0 | 0 | 1 | 4 | [Twitter](https://hackerone.com/twitter) |
| pewresearch.org | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| pexels.com | 8 | 0 | 0 | 2 | 6 | [Pexels](https://bugcrowd.com/pexels) |
| photos.app.goo.gl | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| photos.google.com | 9 | 0 | 0 | 2 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| php.net | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| picasaweb.google.com | 9 | 0 | 0 | 3 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| pinterest.co.uk | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| pinterest.com | 9 | 0 | 0 | 3 | 6 | [Pinterest](https://bugcrowd.com/pinterest) |
| pipes.yahoo.com | 2 | 0 | 0 | 0 | 2 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| pixabay.com | 7 | 0 | 0 | 2 | 5 | [Pixabay](https://bugcrowd.com/pixabay) |
| pixiv.net | 12 | 0 | 0 | 4 | 8 | [Pixiv](https://hackerone.com/pixiv) |
| pl.wikipedia.org | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| platform.twitter.com | 12 | 0 | 0 | 4 | 8 | [Twitter](https://hackerone.com/twitter) |
| play.google.com | 6 | 0 | 0 | 0 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| player.vimeo.com | 7 | 0 | 0 | 1 | 6 | [Vimeo](https://hackerone.com/vimeo) |
| plus.google.com | 10 | 0 | 0 | 0 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| podcasts.apple.com | 8 | 0 | 0 | 0 | 8 | [Apple](https://security.apple.com) |
| podcasts.google.com | 11 | 0 | 0 | 1 | 10 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| policies.google.com | 7 | 0 | 0 | 3 | 4 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| popularmechanics.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| postmates.com | 11 | 0 | 0 | 2 | 9 | [Postmates](https://hackerone.com/postmates) |
| privacy.microsoft.com | 13 | 0 | 0 | 3 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| prnewswire.com | 10 | 0 | 0 | 2 | 8 | top-websites gist (no active program match) |
| prnt.sc | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| productforums.google.com | 10 | 0 | 0 | 4 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| profiles.google.com | 8 | 0 | 0 | 3 | 5 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| psychologytoday.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| pt.slideshare.net | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| purl.org | 13 | 0 | 0 | 6 | 7 | top-websites gist (no active program match) |
| puu.sh | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| quora.com | 8 | 0 | 0 | 1 | 7 | [Quora](https://hackerone.com/quora) |
| ranker.com | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| ravelry.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| raw.githubusercontent.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| reacts.ru | 2 | 0 | 1 | 0 | 1 | top-websites gist (no active program match) |
| redbubble.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| redbull.com | 11 | 0 | 0 | 4 | 7 | [Redbull](https://app.intigriti.com/programs/redbull/redbull/detail) |
| reddit.com | 10 | 0 | 0 | 2 | 8 | [Reddit](https://hackerone.com/reddit) |
| redhat.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| researchgate.net | 9 | 0 | 0 | 3 | 6 | [Research Gate](https://explore.researchgate.net/display/support/Security+and+vulnerability) |
| rollingstone.com | 11 | 0 | 0 | 1 | 10 | top-websites gist (no active program match) |
| rottentomatoes.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| s-media-cache-ak0.pinimg.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| salesforce.com | 19 | 0 | 0 | 6 | 13 | [Salesforce](https://www.salesforce.com/company/disclosure/) |
| samsung.com | 15 | 0 | 0 | 8 | 7 | [Samsung TV](https://samsungtvbounty.com) |
| scribd.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| search.google.com | 12 | 0 | 0 | 5 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| secure.gravatar.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| sendspace.com | 6 | 0 | 0 | 0 | 6 | top-websites gist (no active program match) |
| seroundtable.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| services.google.com | 13 | 0 | 0 | 5 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| shareasale.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| shopify.com | 10 | 0 | 0 | 2 | 8 | [Shopify](https://hackerone.com/shopify) |
| shutterstock.com | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| sites.google.com | 7 | 0 | 0 | 0 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| sketchfab.com | 10 | 0 | 0 | 2 | 8 | [Epic Games](https://hackerone.com/epicgames) |
| skfb.ly | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| skype.com | 10 | 0 | 0 | 0 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| slack.com | 10 | 0 | 0 | 4 | 6 | [Slack](https://hackerone.com/slack) |
| slate.com | 5 | 0 | 0 | 1 | 4 | top-websites gist (no active program match) |
| slideshare.net | 13 | 0 | 0 | 6 | 7 | top-websites gist (no active program match) |
| smashingmagazine.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| smile.amazon.com | 10 | 0 | 0 | 4 | 6 | [Amazon](https://hackerone.com/amazonvrp) |
| smugmug.com | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| snapchat.com | 14 | 0 | 0 | 2 | 12 | [Snapchat](https://hackerone.com/snapchat) |
| socialmediatoday.com | 8 | 0 | 0 | 3 | 5 | top-websites gist (no active program match) |
| sophos.com | 11 | 0 | 0 | 4 | 7 | [Sophos](https://bugcrowd.com/sophos) |
| soundcloud.com | 12 | 0 | 0 | 5 | 7 | [SoundCloud](https://bugcrowd.com/soundcloud) |
| sourceforge.net | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| space.com | 13 | 0 | 0 | 4 | 9 | top-websites gist (no active program match) |
| speakerdeck.com | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| spotify.com | 11 | 0 | 0 | 2 | 9 | [Spotify](https://hackerone.com/spotify) |
| sproutsocial.com | 9 | 0 | 0 | 0 | 9 | [Sprout Social](https://bugcrowd.com/sproutsocial) |
| squareup.com | 10 | 0 | 0 | 4 | 6 | [Square](https://bugcrowd.com/square) |
| stackoverflow.com | 6 | 0 | 0 | 2 | 4 | top-websites gist (no active program match) |
| startnext.com | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| starwars.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| stats.wp.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| steamcommunity.com | 11 | 0 | 0 | 4 | 7 | [Valve Software](https://hackerone.com/valve) |
| stock.adobe.com | 11 | 0 | 0 | 3 | 8 | [Adobe](https://hackerone.com/adobe) |
| storage.googleapis.com | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| store.google.com | 9 | 0 | 0 | 1 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| store.steampowered.com | 10 | 0 | 0 | 4 | 6 | [Valve Software](https://hackerone.com/valve) |
| strava.com | 11 | 0 | 0 | 5 | 6 | top-websites gist (no active program match) |
| stripe.com | 5 | 0 | 0 | 0 | 5 | [Stripe](https://hackerone.com/stripe) |
| sublimetext.com | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| support.apple.com | 6 | 0 | 0 | 0 | 6 | [Apple](https://security.apple.com) |
| support.cloudflare.com | 9 | 0 | 0 | 1 | 8 | [Cloudflare](https://hackerone.com/cloudflare) |
| support.google.com | 10 | 0 | 0 | 2 | 8 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| support.microsoft.com | 10 | 0 | 0 | 3 | 7 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| support.office.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| surveymonkey.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| sutterhealth.org | 10 | 0 | 0 | 5 | 5 | top-websites gist (no active program match) |
| t.co | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| t.qq.com | 2 | 0 | 0 | 0 | 2 | [Tencent](https://en.security.tencent.com) |
| techcrunch.com | 7 | 0 | 0 | 0 | 7 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| technet.microsoft.com | 9 | 0 | 0 | 3 | 6 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| telegram.me | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| tesla.com | 11 | 0 | 0 | 3 | 8 | [Tesla](https://bugcrowd.com/tesla) |
| tf1.fr | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| theguardian.com | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| themify.me | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| thinkwithgoogle.com | 12 | 0 | 0 | 1 | 11 | top-websites gist (no active program match) |
| ticketportal.cz | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| time.com | 10 | 0 | 0 | 3 | 7 | TIME |
| timesofindia.indiatimes.com | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| tools.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| tools.ietf.org | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| translate.google.com | 8 | 0 | 0 | 2 | 6 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| treasury.gov | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| trello.com | 11 | 0 | 0 | 1 | 10 | [Trello](https://bugcrowd.com/trello) |
| trends.google.com | 7 | 0 | 0 | 2 | 5 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| trustpilot.com | 11 | 0 | 0 | 4 | 7 | [Trustpilot](https://hackerone.com/trustpilot) |
| twitter.com | 10 | 0 | 0 | 2 | 8 | [Twitter](https://hackerone.com/twitter) |
| uber.com | 12 | 0 | 0 | 2 | 10 | [Uber](https://hackerone.com/uber) |
| udemy.com | 7 | 0 | 0 | 2 | 5 | [Udemy](https://hackerone.com/udemy) |
| un.org | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| united.com | 16 | 0 | 0 | 5 | 11 | [United Airlines](https://bugcrowd.com/united-vdp) |
| untappd.com | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| upwork.com | 7 | 0 | 0 | 2 | 5 | [Upwork](https://bugcrowd.com/upwork) |
| us.battle.net | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| use.typekit.net | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| validator.w3.org | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| verizon.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| vice.com | 13 | 0 | 0 | 6 | 7 | top-websites gist (no active program match) |
| video.google.com | 11 | 0 | 0 | 4 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| vimeo.com | 8 | 0 | 0 | 2 | 6 | [Vimeo](https://hackerone.com/vimeo) |
| vine.co | 8 | 0 | 0 | 0 | 8 | [Twitter](https://hackerone.com/twitter) |
| vizio.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| vk.com | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| vogue.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| vr.google.com | 9 | 0 | 0 | 2 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| w3schools.com | 7 | 0 | 0 | 0 | 7 | top-websites gist (no active program match) |
| walmart.com | 13 | 0 | 0 | 4 | 9 | [Walmart Corporation](https://corporate.walmart.com/article/responsible-disclosure-policy) |
| washingtonpost.com | 11 | 0 | 0 | 4 | 7 | top-websites gist (no active program match) |
| waze.com | 6 | 0 | 0 | 0 | 6 | top-websites gist (no active program match) |
| web.facebook.com | 9 | 0 | 0 | 1 | 8 | [Facebook](https://www.facebook.com/whitehat) |
| webroot.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| weebly.com | 14 | 0 | 0 | 6 | 8 | top-websites gist (no active program match) |
| weforum.org | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| wetransfer.com | 6 | 0 | 0 | 0 | 6 | top-websites gist (no active program match) |
| whatsapp.com | 7 | 0 | 0 | 1 | 6 | [Facebook](https://www.facebook.com/whitehat) |
| who.int | 5 | 0 | 0 | 0 | 5 | top-websites gist (no active program match) |
| wikipedia.org | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| windows.microsoft.com | 14 | 0 | 0 | 3 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| wired.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| wix.com | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| wordpress.org | 12 | 0 | 0 | 2 | 10 | [WordPress](https://hackerone.com/wordpress) |
| wp.me | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| www-01.ibm.com | 15 | 0 | 0 | 3 | 12 | [IBM](https://hackerone.com/ibm) |
| yahoo.com | 13 | 0 | 0 | 3 | 10 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| yandex.com | 9 | 0 | 0 | 2 | 7 | [Yandex](https://yandex.com/bugbounty/index) |
| yandex.ru | 9 | 0 | 0 | 2 | 7 | [Yandex](https://yandex.com/bugbounty/index) |
| yelp.com | 12 | 0 | 0 | 5 | 7 | [Yelp](https://hackerone.com/yelp) |
| youtube.com | 8 | 0 | 0 | 1 | 7 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| zdnet.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| zeit.de | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| zen.yandex.ru | 12 | 0 | 0 | 2 | 10 | [Yandex](https://yandex.com/bugbounty/index) |
| zillow.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| zoom.us | 15 | 0 | 0 | 4 | 11 | [Zoom](https://explore.zoom.us/docs/ent/h1.html) |
| googletagmanager.com | 10 | 0 | 0 | 4 | 6 | Google |
| dailycaller.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| lenovo.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| webmd.com | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| youtube-nocookie.com | 2 | 0 | 1 | 0 | 1 | Google |
| thinkgeek.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| funnyordie.com | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| overcast.fm | 4 | 0 | 0 | 0 | 4 | top-websites gist (no active program match) |
| allmusic.com | 7 | 0 | 0 | 1 | 6 | top-websites gist (no active program match) |
| pond5.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| linktr.ee | 5 | 0 | 0 | 1 | 4 | top-websites gist (no active program match) |
| disqus.com | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| gofundme.com | 13 | 0 | 0 | 6 | 7 | top-websites gist (no active program match) |
| pixlr.com | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| design.google | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| mlb.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| france24.com | 16 | 0 | 0 | 6 | 10 | top-websites gist (no active program match) |
| gartner.com | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| 2.bp.blogspot.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| digitaltrends.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| s0.wp.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| mega.nz | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| ea.com | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| connect.facebook.net | 10 | 0 | 0 | 1 | 9 | top-websites gist (no active program match) |
| 1.bp.blogspot.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| bbb.org | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| britannica.com | 8 | 0 | 0 | 2 | 6 | top-websites gist (no active program match) |
| calendly.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| g1.globo.com | 9 | 0 | 0 | 2 | 7 | top-websites gist (no active program match) |
| gmpg.org | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| google.be | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google.co.za | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| google.it | 14 | 0 | 0 | 5 | 9 | top-websites gist (no active program match) |
| inc.com | 10 | 0 | 0 | 3 | 7 | top-websites gist (no active program match) |
| myspace.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| plaza.rakuten.co.jp | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| telegram.org | 8 | 0 | 0 | 3 | 5 | Telegram |
=======
| 1.usa.gov | 4 | 0 | 0 | 2 | 2 | TTS Bug Bounty |
| 1drv.ms | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| 3.bp.blogspot.com | 4 | 0 | 0 | 3 | 1 | top-websites gist (no active program match) |
| 4.bp.blogspot.com | 12 | 0 | 1 | 7 | 4 | top-websites gist (no active program match) |
| 7-zip.org | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| abc.com | 13 | 0 | 0 | 8 | 5 | The Walt Disney Company |
| abcnews.go.com | 21 | 0 | 0 | 16 | 5 | top-websites gist (no active program match) |
| abebooks.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| about.fb.com | 12 | 0 | 0 | 7 | 5 | Facebook |
| about.me | 14 | 0 | 0 | 9 | 5 | top-websites gist (no active program match) |
| aboutads.info | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| accenture.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| accessify.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| accounts.google.com | 6 | 0 | 0 | 1 | 5 | Google |
| acm.org | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| activecampaign.com | 16 | 0 | 10 | 4 | 2 | top-websites gist (no active program match) |
| ad.doubleclick.net | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| adage.com | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| addons.mozilla.org | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| adobe.com | 11 | 0 | 0 | 7 | 4 | Adobe |
| adobe.ly | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| ads.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| adssettings.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| adwords.google.com | 9 | 0 | 0 | 5 | 4 | Google |
| affiliate-program.amazon.com | 16 | 0 | 0 | 11 | 5 | Amazon |
| airbnb.com | 11 | 0 | 0 | 7 | 4 | Airbnb |
| airtable.com | 13 | 0 | 0 | 10 | 3 | Airtable |
| ajax.googleapis.com | 2 | 0 | 1 | 0 | 1 | Google |
| aliexpress.com | 16 | 0 | 1 | 10 | 5 | Alibaba |
| aljazeera.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| amazon.ca | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.co.jp | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.co.uk | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.com.au | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.com.br | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.com | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.de | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.es | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.fr | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.in | 12 | 0 | 0 | 8 | 4 | Amazon |
| amazon.it | 12 | 0 | 0 | 8 | 4 | Amazon |
| ameblo.jp | 17 | 0 | 0 | 16 | 1 | top-websites gist (no active program match) |
| amzn.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| amzn.to | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| analytics.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| ancestry.com | 10 | 0 | 1 | 6 | 3 | top-websites gist (no active program match) |
| animoto.com | 11 | 0 | 0 | 5 | 6 | top-websites gist (no active program match) |
| api.whatsapp.com | 11 | 0 | 1 | 5 | 5 | Facebook |
| apis.google.com | 12 | 0 | 1 | 6 | 5 | Google |
| app.box.com | 16 | 0 | 0 | 12 | 4 | top-websites gist (no active program match) |
| apple.com | 10 | 0 | 0 | 8 | 2 | Apple |
| apps.apple.com | 12 | 0 | 0 | 8 | 4 | Apple |
| apps.facebook.com | 10 | 0 | 0 | 7 | 3 | Facebook |
| archives.gov | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| arstechnica.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| artsandculture.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| asus.com | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| aub.edu.lb | 15 | 0 | 0 | 14 | 1 | top-websites gist (no active program match) |
| aws.amazon.com | 12 | 0 | 0 | 8 | 4 | Amazon |
| axios.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| azure.microsoft.com | 10 | 0 | 0 | 7 | 3 | Microsoft Online Services |
| baidu.com | 10 | 0 | 0 | 8 | 2 | Baidu |
| bandcamp.com | 13 | 0 | 0 | 8 | 5 | Epic Games |
| bandsintown.com | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| bbc.com | 11 | 0 | 0 | 7 | 4 | BBC |
| beian.gov.cn | 1 | 0 | 0 | 1 | 0 | top-websites gist (no active program match) |
| bhphotovideo.com | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| bigthink.com | 15 | 0 | 0 | 8 | 7 | top-websites gist (no active program match) |
| bild.de | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| bing.com | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| bizjournals.com | 32 | 0 | 0 | 29 | 3 | top-websites gist (no active program match) |
| blockchain.info | 9 | 0 | 0 | 5 | 4 | Blockchain |
| blog.google | 34 | 0 | 9 | 23 | 2 | Google |
| blog.hubspot.com | 7 | 0 | 0 | 4 | 3 | HubSpot |
| blog.livedoor.jp | 18 | 0 | 1 | 12 | 5 | top-websites gist (no active program match) |
| blog.us.playstation.com | 12 | 0 | 0 | 8 | 4 | Playstation |
| blogger.com | 11 | 0 | 0 | 6 | 5 | Google |
| blogs.adobe.com | 13 | 0 | 1 | 9 | 3 | Adobe |
| blogs.msdn.com | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| blogs.windows.com | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| blogtalkradio.com | 1 | 0 | 0 | 1 | 0 | top-websites gist (no active program match) |
| bloomberg.com | 23 | 0 | 0 | 22 | 1 | Bloomberg |
| bluehost.com | 11 | 0 | 1 | 7 | 3 | Bluehost |
| books.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| bookstackapp.com | 12 | 4 | 4 | 4 | 0 | None (open-source project; GitHub issue tracker) |
| breitbart.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| buffer.com | 15 | 0 | 0 | 9 | 6 | Buffer |
| bugs.chromium.org | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| business.facebook.com | 11 | 0 | 0 | 7 | 4 | Facebook |
| business.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| businessinsider.com | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| buymeacoffee.com | 35 | 0 | 1 | 31 | 3 | top-websites gist (no active program match) |
| buzzsprout.com | 11 | 0 | 0 | 2 | 9 | top-websites gist (no active program match) |
| ca.linkedin.com | 8 | 0 | 0 | 1 | 7 | top-websites gist (no active program match) |
| calendar.google.com | 11 | 0 | 1 | 6 | 4 | Google |
| cambridge.org | 9 | 0 | 0 | 5 | 4 | top-websites gist (no active program match) |
| canada.ca | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| canva.com | 12 | 0 | 0 | 8 | 4 | Canva |
| cargocollective.com | 16 | 0 | 0 | 8 | 8 | top-websites gist (no active program match) |
| cbs.com | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| cdc.gov | 16 | 0 | 0 | 11 | 5 | U.S. Dept of Health & Human Services (HHS) |
| cdn.shopify.com | 11 | 0 | 1 | 5 | 5 | Shopify |
| cdnjs.cloudflare.com | 10 | 0 | 1 | 5 | 4 | Cloudflare |
| cell.com | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| census.gov | 1 | 0 | 0 | 1 | 0 | top-websites gist (no active program match) |
| chase.com | 12 | 0 | 0 | 8 | 4 | Chase |
| checkpoint.com | 8 | 0 | 0 | 5 | 3 | Check Point |
| chicagotribune.com | 15 | 1 | 1 | 7 | 6 | [top-websites gist (no active program match)]() |
| chris.pirillo.com | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| chrome.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| chronicle.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| cisco.com | 10 | 0 | 0 | 8 | 2 | Cisco Meraki |
| click.linksynergy.com | 11 | 0 | 0 | 8 | 3 | top-websites gist (no active program match) |
| cloud.google.com | 10 | 0 | 0 | 4 | 6 | Google |
| cloudflare.com | 12 | 0 | 0 | 8 | 4 | Cloudflare |
| cnbc.com | 7 | 0 | 0 | 5 | 2 | Nasdaq |
| code.google.com | 10 | 0 | 1 | 4 | 5 | Google |
| codepen.io | 9 | 0 | 0 | 5 | 4 | top-websites gist (no active program match) |
| codeproject.com | 15 | 0 | 1 | 8 | 6 | top-websites gist (no active program match) |
| codex.wordpress.org | 13 | 0 | 0 | 9 | 4 | WordPress |
| coinbase.com | 11 | 0 | 0 | 7 | 4 | Coinbase |
| coinmarketcap.com | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| collegehumor.com | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| constantcontact.com | 11 | 0 | 0 | 7 | 4 | Constant Contact |
| copyright.gov | 12 | 0 | 0 | 5 | 7 | top-websites gist (no active program match) |
| coursera.org | 11 | 0 | 0 | 8 | 3 | Coursera |
| createspace.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| creativecommons.org | 15 | 0 | 0 | 8 | 7 | top-websites gist (no active program match) |
| creativemarket.com | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| cse.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| css-tricks.com | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| ctt.ec | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| cyber.law.harvard.edu | 1 | 0 | 0 | 1 | 0 | Harvard |
| dailymotion.com | 10 | 0 | 0 | 7 | 3 | Dailymotion |
| dashlane.com | 10 | 0 | 0 | 6 | 4 | Dashlane |
| data.worldbank.org | 13 | 0 | 0 | 7 | 6 | top-websites gist (no active program match) |
| de-de.facebook.com | 8 | 0 | 0 | 4 | 4 | Facebook |
| de.linkedin.com | 15 | 0 | 0 | 9 | 6 | top-websites gist (no active program match) |
| deezer.com | 12 | 0 | 0 | 8 | 4 | Deezer |
| denverpost.com | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| desktop.github.com | 13 | 0 | 0 | 8 | 5 | GitHub |
| developer.android.com | 10 | 0 | 0 | 4 | 6 | top-websites gist (no active program match) |
| developer.apple.com | 8 | 0 | 0 | 4 | 4 | Apple |
| developer.chrome.com | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| developers.facebook.com | 8 | 0 | 0 | 4 | 4 | Facebook |
| developers.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| digitalocean.com | 13 | 0 | 0 | 9 | 4 | DigitalOcean |
| diigo.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| discordapp.com | 32 | 0 | 3 | 25 | 4 | top-websites gist (no active program match) |
| dl.dropbox.com | 12 | 0 | 0 | 7 | 5 | DropBox |
| docker.com | 9 | 0 | 5 | 2 | 2 | Docker |
| docs.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| docs.microsoft.com | 10 | 0 | 0 | 6 | 4 | Microsoft Online Services |
| download.microsoft.com | 13 | 0 | 0 | 8 | 5 | Microsoft Online Services |
| dribbble.com | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| drift.com | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| drive.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| dropbox.com | 11 | 0 | 0 | 7 | 4 | DropBox |
| drupal.org | 13 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| dx.doi.org | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| earth.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| ec.europa.eu | 11 | 0 | 0 | 8 | 3 | European Central Bank |
| economist.com | 16 | 0 | 0 | 11 | 5 | top-websites gist (no active program match) |
| edx.org | 7 | 0 | 3 | 2 | 2 | top-websites gist (no active program match) |
| eepurl.com | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| eff.org | 10 | 0 | 0 | 6 | 4 | EFF |
| elmundo.es | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| en-gb.facebook.com | 8 | 0 | 0 | 4 | 4 | Facebook |
| en.advertisercommunity.com | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| en.wikipedia.org | 13 | 0 | 0 | 12 | 1 | top-websites gist (no active program match) |
| engadget.com | 12 | 0 | 0 | 8 | 4 | Yahoo! |
| envato.com | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| eonline.com | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| epa.gov | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| es.wikipedia.org | 20 | 1 | 1 | 16 | 2 | top-websites gist (no active program match) |
| espn.com | 12 | 0 | 0 | 8 | 4 | The Walt Disney Company |
| etsy.com | 12 | 0 | 0 | 8 | 4 | Etsy |
| eur-lex.europa.eu | 18 | 0 | 0 | 14 | 4 | European Central Bank |
| europa.eu | 11 | 0 | 0 | 8 | 3 | European Central Bank |
| europarl.europa.eu | 10 | 0 | 0 | 6 | 4 | European Central Bank |
| event.on24.com | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| eventbrite.com | 11 | 0 | 0 | 7 | 4 | Eventbrite |
| eventim.de | 1 | 0 | 0 | 1 | 0 | top-websites gist (no active program match) |
| events.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| evernote.com | 12 | 0 | 0 | 9 | 3 | Evernote |
| expedia.com | 10 | 0 | 0 | 6 | 4 | Expedia Group |
| faa.gov | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| facebook.com | 10 | 0 | 0 | 7 | 3 | Facebook |
| families.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| fb.com | 10 | 0 | 0 | 7 | 3 | Facebook |
| fb.me | 10 | 0 | 0 | 7 | 3 | Facebook |
| feeds.feedburner.com | 12 | 0 | 1 | 4 | 7 | top-websites gist (no active program match) |
| filezilla-project.org | 9 | 0 | 0 | 4 | 5 | FileZilla |
| finance.yahoo.com | 2 | 0 | 0 | 1 | 1 | Yahoo! |
| firstdata.com | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| flavors.me | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| flic.kr | 9 | 0 | 1 | 6 | 2 | top-websites gist (no active program match) |
| flickr.com | 9 | 0 | 1 | 6 | 2 | Flickr |
| flipboard.com | 11 | 0 | 1 | 10 | 0 | top-websites gist (no active program match) |
| flow.microsoft.com | 10 | 0 | 0 | 8 | 2 | Microsoft Online Services |
| fonts.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| fonts.googleapis.com | 12 | 0 | 1 | 6 | 5 | top-websites gist (no active program match) |
| forbes.com | 3 | 0 | 0 | 2 | 1 | Forbes |
| forms.gle | 6 | 0 | 0 | 4 | 2 | Google |
| forms.office.com | 10 | 0 | 0 | 7 | 3 | Microsoft Online Services |
| foxnews.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| fr.wikipedia.org | 14 | 0 | 0 | 8 | 6 | top-websites gist (no active program match) |
| franchising.com | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| freelancer.com | 16 | 0 | 0 | 13 | 3 | top-websites gist (no active program match) |
| freewebs.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| ftc.gov | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| g.co | 9 | 0 | 0 | 5 | 4 | top-websites gist (no active program match) |
| g.page | 7 | 0 | 0 | 2 | 5 | top-websites gist (no active program match) |
| get.adobe.com | 12 | 0 | 0 | 10 | 2 | Adobe |
| get.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| getpocket.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| getresponse.com | 11 | 0 | 0 | 8 | 3 | top-websites gist (no active program match) |
| gist.github.com | 8 | 0 | 0 | 5 | 3 | GitHub |
| github.com | 7 | 0 | 0 | 5 | 2 | GitHub |
| gitlab.com | 7 | 0 | 0 | 3 | 4 | GitLab |
| gitter.im | 10 | 0 | 0 | 7 | 3 | GitLab |
| gleam.io | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| globalnews.ca | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| golang.org | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| goo.gle | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| google.com.br | 11 | 0 | 0 | 9 | 2 | top-websites gist (no active program match) |
| google.com | 11 | 0 | 0 | 7 | 4 | Google |
| google.de | 12 | 0 | 0 | 6 | 6 | top-websites gist (no active program match) |
| google.nl | 13 | 0 | 1 | 8 | 4 | top-websites gist (no active program match) |
| google.se | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| googleadservices.com | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| googlewebmastercentral.blogspot.com | 8 | 0 | 1 | 2 | 5 | top-websites gist (no active program match) |
| gov.uk | 11 | 0 | 0 | 7 | 4 | NCSC UK |
| greenpeace.org | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| groups.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| gsuite.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| hangouts.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| hbo.com | 22 | 0 | 0 | 18 | 4 | top-websites gist (no active program match) |
| health.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| health.harvard.edu | 10 | 0 | 0 | 6 | 4 | Harvard |
| healthline.com | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| heise.de | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| help.apple.com | 9 | 0 | 1 | 5 | 3 | Apple |
| helpx.adobe.com | 16 | 0 | 0 | 11 | 5 | Adobe |
| hkrsa.asia | 16 | 0 | 1 | 8 | 7 | top-websites gist (no active program match) |
| homedepot.com | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| hostgator.com | 11 | 0 | 1 | 7 | 3 | Host Gator |
| hp.com | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| humblebundle.com | 13 | 0 | 0 | 9 | 4 | Humble Bundle |
| i.imgur.com | 11 | 0 | 0 | 7 | 4 | Imgur |
| i.redd.it | 14 | 0 | 0 | 9 | 5 | Reddit |
| i0.wp.com | 13 | 0 | 1 | 8 | 4 | top-websites gist (no active program match) |
| ibm.com | 11 | 0 | 0 | 7 | 4 | IBM |
| iconfinder.com | 11 | 0 | 0 | 8 | 3 | top-websites gist (no active program match) |
| idealo.de | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| ifttt.com | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| ikea.com | 12 | 0 | 0 | 8 | 4 | IKEA |
| imdb.com | 11 | 0 | 0 | 7 | 4 | IMDB |
| img.youtube.com | 12 | 0 | 0 | 7 | 5 | Google |
| imgur.com | 11 | 0 | 0 | 5 | 6 | Imgur |
| indiewire.com | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| infusionsoft.com | 38 | 0 | 0 | 35 | 3 | top-websites gist (no active program match) |
| inkscape.org | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| instagram.com | 10 | 0 | 0 | 7 | 3 | Facebook |
| institutvajrayogini.fr | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| instructables.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| intel.com | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| irs.gov | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| is.gd | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| issuu.com | 6 | 0 | 0 | 3 | 3 | Issuu |
| istockphoto.com | 11 | 0 | 0 | 8 | 3 | top-websites gist (no active program match) |
| it.linkedin.com | 15 | 0 | 0 | 9 | 6 | top-websites gist (no active program match) |
| itunes.apple.com | 11 | 0 | 0 | 7 | 4 | Apple |
| ja-jp.facebook.com | 8 | 0 | 0 | 4 | 4 | Facebook |
| japantimes.co.jp | 9 | 0 | 0 | 5 | 4 | top-websites gist (no active program match) |
| jetbrains.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| join.slack.com | 12 | 0 | 0 | 8 | 4 | Slack |
| journals.sagepub.com | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| jstor.org | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| keep.google.com | 7 | 0 | 0 | 2 | 5 | Google |
| khanacademy.org | 12 | 0 | 0 | 8 | 4 | Khan Academy |
| kiva.org | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| kobo.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| kraken.com | 9 | 0 | 0 | 5 | 4 | Kraken |
| l.facebook.com | 11 | 0 | 0 | 8 | 3 | Facebook |
| laughingsquid.com | 14 | 0 | 0 | 8 | 6 | top-websites gist (no active program match) |
| launchpad.net | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| lh5.ggpht.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| lifehack.org | 8 | 0 | 0 | 5 | 3 | top-websites gist (no active program match) |
| line.me | 11 | 0 | 0 | 7 | 4 | LINE |
| link.springer.com | 17 | 0 | 0 | 15 | 2 | top-websites gist (no active program match) |
| linkedin.com | 9 | 0 | 1 | 1 | 7 | top-websites gist (no active program match) |
| livestream.com | 13 | 0 | 0 | 9 | 4 | Livestream |
| login.microsoftonline.com | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| logitech.com | 12 | 0 | 0 | 8 | 4 | Logitech |
| lulu.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| lynda.com | 16 | 0 | 0 | 12 | 4 | top-websites gist (no active program match) |
| m.facebook.com | 9 | 0 | 0 | 5 | 4 | Facebook |
| m.youtube.com | 6 | 0 | 0 | 2 | 4 | Google |
| mail.google.com | 6 | 0 | 0 | 2 | 4 | Google |
| mailchimp.com | 17 | 0 | 0 | 13 | 4 | Intuit |
| makeuseof.com | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| maps.google.co.jp | 13 | 0 | 0 | 11 | 2 | top-websites gist (no active program match) |
| maps.google.co.nz | 13 | 0 | 0 | 11 | 2 | top-websites gist (no active program match) |
| maps.google.com | 16 | 0 | 0 | 10 | 6 | Google |
| maps.gstatic.com | 13 | 0 | 1 | 6 | 6 | top-websites gist (no active program match) |
| market.android.com | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| marketingplatform.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| marketwatch.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| marriott.com | 24 | 0 | 0 | 20 | 4 | Marriott |
| mashable.com | 13 | 0 | 1 | 8 | 4 | top-websites gist (no active program match) |
| medium.com | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| meet.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| mentalfloss.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| messenger.com | 10 | 0 | 0 | 7 | 3 | Facebook |
| metmuseum.org | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| microsoft.com | 9 | 0 | 0 | 7 | 2 | Microsoft Online Services |
| mobile.twitter.com | 16 | 0 | 1 | 11 | 4 | Twitter |
| moma.org | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| money.yandex.ru | 1 | 0 | 0 | 1 | 0 | Yandex |
| monster.com | 15 | 0 | 0 | 11 | 4 | top-websites gist (no active program match) |
| moz.com | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| mp.weixin.qq.com | 10 | 0 | 0 | 7 | 3 | Tencent |
| msdn.microsoft.com | 8 | 0 | 0 | 6 | 2 | Microsoft Online Services |
| msn.com | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| music.apple.com | 12 | 0 | 0 | 8 | 4 | Apple |
| myaccount.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| myfitnesspal.com | 14 | 0 | 1 | 9 | 4 | UNDER ARMOUR |
| nasa.gov | 11 | 0 | 0 | 7 | 4 | Nasa VDP |
| nature.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| ncbi.nlm.nih.gov | 8 | 0 | 0 | 5 | 3 | U.S. Dept of Health & Human Services (HHS) |
| neilpatel.com | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| netbeans.org | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| netflix.com | 8 | 0 | 0 | 5 | 3 | Netflix |
| networkadvertising.org | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| newegg.com | 11 | 0 | 0 | 7 | 4 | Newegg |
| news.google.com | 9 | 0 | 0 | 5 | 4 | Google |
| news.harvard.edu | 10 | 0 | 0 | 6 | 4 | Harvard |
| news.mit.edu | 10 | 0 | 0 | 5 | 5 | top-websites gist (no active program match) |
| news.yahoo.com | 7 | 0 | 0 | 5 | 2 | Yahoo! |
| note.mu | 28 | 0 | 0 | 27 | 1 | top-websites gist (no active program match) |
| nvidia.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| nydailynews.com | 14 | 0 | 1 | 7 | 6 | top-websites gist (no active program match) |
| nytimes.com | 4 | 0 | 0 | 2 | 2 | The New York Times |
| ok.ru | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| online.wsj.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| open.spotify.com | 12 | 0 | 0 | 7 | 5 | Spotify |
| opera.com | 11 | 0 | 0 | 7 | 4 | Opera Public Bug Bounty |
| oracle.com | 10 | 0 | 0 | 8 | 2 | top-websites gist (no active program match) |
| otto.de | 5 | 0 | 1 | 2 | 2 | top-websites gist (no active program match) |
| ow.ly | 6 | 0 | 0 | 5 | 1 | Hootsuite |
| patents.google.com | 7 | 0 | 0 | 4 | 3 | Google |
| paypal.com | 10 | 0 | 0 | 6 | 4 | PayPal |
| paypal.me | 10 | 0 | 0 | 6 | 4 | PayPal |
| pbs.twimg.com | 9 | 0 | 0 | 6 | 3 | Twitter |
| pcworld.com | 11 | 0 | 1 | 7 | 3 | top-websites gist (no active program match) |
| penguinrandomhouse.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| periscope.tv | 3 | 0 | 0 | 3 | 0 | Twitter |
| pewresearch.org | 8 | 0 | 1 | 4 | 3 | top-websites gist (no active program match) |
| pexels.com | 13 | 0 | 0 | 9 | 4 | Pexels |
| photos.app.goo.gl | 4 | 0 | 0 | 3 | 1 | top-websites gist (no active program match) |
| photos.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| php.net | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| picasaweb.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| pinterest.co.uk | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| pinterest.com | 9 | 0 | 0 | 7 | 2 | Pinterest |
| pipes.yahoo.com | 1 | 0 | 0 | 1 | 0 | Yahoo! |
| pixabay.com | 9 | 0 | 0 | 6 | 3 | Pixabay |
| pixiv.net | 11 | 0 | 0 | 7 | 4 | Pixiv |
| pl.wikipedia.org | 14 | 0 | 0 | 8 | 6 | top-websites gist (no active program match) |
| platform.twitter.com | 12 | 0 | 2 | 8 | 2 | Twitter |
| play.google.com | 12 | 0 | 0 | 6 | 6 | Google |
| player.vimeo.com | 11 | 0 | 0 | 6 | 5 | Vimeo |
| plus.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| podcasts.apple.com | 12 | 0 | 0 | 8 | 4 | Apple |
| podcasts.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| policies.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| popularmechanics.com | 12 | 0 | 0 | 10 | 2 | top-websites gist (no active program match) |
| postmates.com | 14 | 0 | 0 | 9 | 5 | Postmates |
| privacy.microsoft.com | 9 | 0 | 0 | 7 | 2 | Microsoft Online Services |
| prnewswire.com | 14 | 0 | 0 | 9 | 5 | top-websites gist (no active program match) |
| prnt.sc | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| productforums.google.com | 10 | 0 | 0 | 9 | 1 | Google |
| profiles.google.com | 13 | 0 | 1 | 6 | 6 | Google |
| psychologytoday.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| pt.slideshare.net | 16 | 0 | 0 | 11 | 5 | top-websites gist (no active program match) |
| purl.org | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| puu.sh | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| quora.com | 10 | 0 | 0 | 6 | 4 | Quora |
| ranker.com | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| ravelry.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| raw.githubusercontent.com | 15 | 1 | 3 | 7 | 4 | top-websites gist (no active program match) |
| reacts.ru | 9 | 0 | 2 | 4 | 3 | top-websites gist (no active program match) |
| redbubble.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| redbull.com | 12 | 0 | 0 | 8 | 4 | Redbull |
| reddit.com | 7 | 0 | 0 | 3 | 4 | Reddit |
| redhat.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| researchgate.net | 11 | 0 | 0 | 7 | 4 | Research Gate |
| rollingstone.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| rottentomatoes.com | 17 | 1 | 0 | 13 | 3 | top-websites gist (no active program match) |
| s-media-cache-ak0.pinimg.com | 11 | 0 | 1 | 8 | 2 | top-websites gist (no active program match) |
| salesforce.com | 11 | 0 | 0 | 7 | 4 | Salesforce |
| samsung.com | 12 | 0 | 0 | 8 | 4 | Samsung TV |
| scribd.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| search.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| secure.gravatar.com | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| sendspace.com | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| seroundtable.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| services.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| shareasale.com | 18 | 0 | 0 | 14 | 4 | top-websites gist (no active program match) |
| shopify.com | 10 | 0 | 0 | 6 | 4 | Shopify |
| shutterstock.com | 13 | 1 | 0 | 8 | 4 | top-websites gist (no active program match) |
| sites.google.com | 8 | 0 | 0 | 4 | 4 | Google |
| sketchfab.com | 10 | 0 | 0 | 6 | 4 | Epic Games |
| skfb.ly | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| skype.com | 10 | 0 | 0 | 6 | 4 | Microsoft Online Services |
| slack.com | 12 | 0 | 0 | 9 | 3 | Slack |
| slate.com | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| slideshare.net | 15 | 0 | 0 | 11 | 4 | top-websites gist (no active program match) |
| smashingmagazine.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| smile.amazon.com | 12 | 0 | 0 | 8 | 4 | Amazon |
| smugmug.com | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| snapchat.com | 10 | 0 | 0 | 8 | 2 | Snapchat |
| socialmediatoday.com | 10 | 0 | 0 | 7 | 3 | top-websites gist (no active program match) |
| sophos.com | 12 | 0 | 0 | 10 | 2 | Sophos |
| soundcloud.com | 11 | 0 | 0 | 8 | 3 | SoundCloud |
| sourceforge.net | 10 | 0 | 0 | 5 | 5 | top-websites gist (no active program match) |
| space.com | 14 | 0 | 0 | 10 | 4 | top-websites gist (no active program match) |
| speakerdeck.com | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| spotify.com | 10 | 0 | 0 | 6 | 4 | Spotify |
| sproutsocial.com | 6 | 0 | 0 | 1 | 5 | Sprout Social |
| squareup.com | 15 | 0 | 0 | 10 | 5 | Square |
| stackoverflow.com | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| startnext.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| starwars.com | 14 | 0 | 0 | 8 | 6 | top-websites gist (no active program match) |
| stats.wp.com | 14 | 0 | 0 | 8 | 6 | top-websites gist (no active program match) |
| steamcommunity.com | 11 | 0 | 0 | 7 | 4 | Valve Software |
| stock.adobe.com | 10 | 0 | 0 | 8 | 2 | Adobe |
| storage.googleapis.com | 14 | 0 | 1 | 8 | 5 | top-websites gist (no active program match) |
| store.google.com | 9 | 0 | 0 | 4 | 5 | Google |
| store.steampowered.com | 11 | 0 | 0 | 7 | 4 | Valve Software |
| strava.com | 11 | 0 | 4 | 4 | 3 | top-websites gist (no active program match) |
| stripe.com | 6 | 0 | 0 | 3 | 3 | Stripe |
| sublimetext.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| support.apple.com | 8 | 0 | 0 | 4 | 4 | Apple |
| support.cloudflare.com | 13 | 0 | 0 | 9 | 4 | Cloudflare |
| support.google.com | 9 | 0 | 0 | 5 | 4 | Google |
| support.microsoft.com | 9 | 0 | 0 | 6 | 3 | Microsoft Online Services |
| support.office.com | 12 | 0 | 0 | 9 | 3 | Microsoft Online Services |
| surveymonkey.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| sutterhealth.org | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| t.co | 12 | 0 | 2 | 6 | 4 | top-websites gist (no active program match) |
| t.qq.com | 1 | 0 | 0 | 1 | 0 | Tencent |
| techcrunch.com | 9 | 0 | 0 | 4 | 5 | Yahoo! |
| technet.microsoft.com | 8 | 0 | 0 | 6 | 2 | Microsoft Online Services |
| telegram.me | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| tesla.com | 12 | 0 | 0 | 8 | 4 | Tesla |
| tf1.fr | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| theguardian.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| themify.me | 8 | 0 | 0 | 5 | 3 | top-websites gist (no active program match) |
| thinkwithgoogle.com | 10 | 0 | 0 | 6 | 4 | top-websites gist (no active program match) |
| ticketportal.cz | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| time.com | 15 | 0 | 1 | 7 | 7 | top-websites gist (no active program match) |
| timesofindia.indiatimes.com | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| tools.google.com | 11 | 0 | 0 | 6 | 5 | Google |
| tools.ietf.org | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| translate.google.com | 10 | 0 | 0 | 5 | 5 | Google |
| treasury.gov | 10 | 0 | 0 | 7 | 3 | top-websites gist (no active program match) |
| trello.com | 8 | 0 | 0 | 4 | 4 | Trello |
| trends.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| trustpilot.com | 10 | 0 | 0 | 8 | 2 | Trustpilot |
| twitter.com | 11 | 1 | 1 | 7 | 2 | Twitter |
| uber.com | 8 | 0 | 0 | 5 | 3 | Uber |
| udemy.com | 8 | 0 | 0 | 5 | 3 | Udemy |
| un.org | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| united.com | 10 | 0 | 0 | 6 | 4 | United Airlines |
| untappd.com | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| upwork.com | 10 | 0 | 0 | 6 | 4 | Upwork |
| us.battle.net | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| use.typekit.net | 7 | 0 | 1 | 5 | 1 | top-websites gist (no active program match) |
| validator.w3.org | 10 | 0 | 0 | 5 | 5 | top-websites gist (no active program match) |
| verizon.com | 12 | 0 | 1 | 8 | 3 | top-websites gist (no active program match) |
| vice.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| video.google.com | 12 | 0 | 0 | 6 | 6 | Google |
| vimeo.com | 11 | 0 | 0 | 6 | 5 | Vimeo |
| vine.co | 8 | 0 | 0 | 4 | 4 | Twitter |
| vizio.com | 29 | 24 | 1 | 2 | 2 | top-websites gist (no active program match) |
| vk.com | 20 | 0 | 0 | 11 | 9 | top-websites gist (no active program match) |
| vogue.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| vr.google.com | 10 | 0 | 0 | 6 | 4 | Google |
| w3schools.com | 8 | 0 | 2 | 5 | 1 | top-websites gist (no active program match) |
| walmart.com | 11 | 0 | 0 | 7 | 4 | Walmart Corporation |
| washingtonpost.com | 12 | 0 | 1 | 6 | 5 | top-websites gist (no active program match) |
| waze.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| web.facebook.com | 10 | 0 | 0 | 7 | 3 | Facebook |
| webroot.com | 20 | 0 | 0 | 16 | 4 | top-websites gist (no active program match) |
| weebly.com | 19 | 1 | 0 | 13 | 5 | [top-websites gist (no active program match)]() |
| weforum.org | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| wetransfer.com | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| whatsapp.com | 11 | 0 | 0 | 7 | 4 | Facebook |
| who.int | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| wikipedia.org | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| windows.microsoft.com | 12 | 0 | 0 | 8 | 4 | Microsoft Online Services |
| wired.com | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| wix.com | 12 | 0 | 3 | 7 | 2 | top-websites gist (no active program match) |
| wordpress.org | 10 | 0 | 0 | 6 | 4 | WordPress |
| wp.me | 14 | 0 | 0 | 8 | 6 | top-websites gist (no active program match) |
| www-01.ibm.com | 12 | 0 | 0 | 8 | 4 | IBM |
| yahoo.com | 7 | 0 | 0 | 4 | 3 | Yahoo! |
| yandex.com | 25 | 0 | 0 | 23 | 2 | Yandex |
| yandex.ru | 23 | 0 | 0 | 21 | 2 | Yandex |
| yelp.com | 11 | 0 | 0 | 7 | 4 | Yelp |
| youtube.com | 6 | 0 | 0 | 2 | 4 | Google |
| zdnet.com | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| zeit.de | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| zen.yandex.ru | 13 | 0 | 0 | 11 | 2 | Yandex |
| zillow.com | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| zoom.us | 12 | 0 | 0 | 8 | 4 | Zoom |

| googletagmanager.com | 7 | 0 | 0 | 5 | 2 | Google |
| dailycaller.com | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| lenovo.com | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| webmd.com | 36 | 0 | 0 | 5 | 31 | top-websites gist (no active program match) |
| youtube-nocookie.com | 3 | 0 | 0 | 2 | 1 | Google |
| thinkgeek.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| funnyordie.com | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| overcast.fm | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| allmusic.com | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| pond5.com | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| linktr.ee | 5 | 0 | 2 | 3 | 0 | top-websites gist (no active program match) |
| disqus.com | 9 | 0 | 1 | 4 | 4 | top-websites gist (no active program match) |
| gofundme.com | 15 | 0 | 5 | 7 | 3 | top-websites gist (no active program match) |
| pixlr.com | 38 | 0 | 0 | 29 | 9 | top-websites gist (no active program match) |
| design.google | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| mlb.com | 3 | 0 | 0 | 3 | 0 | top-websites gist (no active program match) |
| france24.com | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| gartner.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| 2.bp.blogspot.com | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| digitaltrends.com | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| s0.wp.com | 10 | 0 | 1 | 7 | 2 | top-websites gist (no active program match) |
| mega.nz | 12 | 0 | 0 | 4 | 8 | top-websites gist (no active program match) |
| ea.com | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| connect.facebook.net | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
>>>>>>> 856185b (verify pass: webmd 19x I1, typekit 4x I1, ca.linkedin I2+4xI5, vogue SSTI all REFUTED (token matrices); reports+README updated; wave 10 shipped (122); chat)
| xbox.com | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| gumroad.com | 10 | 0 | 0 | 9 | 1 | top-websites gist (no active program match) |
| oecd.org | 31 | 0 | 0 | 29 | 2 | top-websites gist (no active program match) |
| google.co.uk | 13 | 0 | 1 | 8 | 4 | Google |
| i2.wp.com | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| cancerresearchuk.org | 9 | 0 | 0 | 1 | 8 | top-websites gist (no active program match) |
| wordpress.com | 8 | 0 | 1 | 5 | 2 | WordPress |
| buzzfeednews.com | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| meetup.com | 9 | 0 | 1 | 7 | 1 | top-websites gist (no active program match) |
| automattic.com | 15 | 0 | 0 | 11 | 4 | top-websites gist (no active program match) |
| ietf.org | 6 | 0 | 1 | 4 | 1 | IETF |
| abc.net.au | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
