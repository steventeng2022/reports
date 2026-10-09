# 安全觀察報告索引

本儲存庫收錄網站安全觀察報告，以及部分獨立深度測試記錄。**這是歷史紀錄與索引，不代表目前仍存在的漏洞、已獲授權的測試範圍，或已由站方確認的風險。**請閱讀每份報告的日期、方法、證據與限制；不要把自動化指標或「High」標籤直接視為已驗證漏洞。

## 索引說明

- 下表以儲存庫目前的索引列計算：**1,018 個不同站點／主機名稱**，共 **18,322 個記錄項目**（High 56、Medium 139、Low 5,903、Info 12,224）。這些數字是表格彙總，**不是**重新逐份驗證後的發現數；各列總數與四級小計相符。
- 原首頁宣稱「635／635 站、100% 被動重審」與現有 1,018 列及部分報告記錄的主動測試不符，故不再沿用。部分記錄描述了 GET 參數注入等主動行為；[baihu-tw.com 深度報告](reports/baihu-tw.com-deepdive.md)亦記錄登入及 API 測試。更新本 README **沒有重新掃描任何網站**。
- 欄位 `Program` 是當時索引所載的來源或計畫參照，**不保證目前仍有有效的漏洞獎勵計畫或在範圍內**。例如 `top-websites gist (no active program match)` 明確不是有效計畫證明。
- 每列連至儲存庫中既有的報告；`baihu-tw.com` 連到其唯一的 `-deepdive` 報告。其他補充深度報告：[apache.org](reports/apache.org-deepdive.md), [coursera.org](reports/coursera.org-deepdive.md), [edx.org](reports/edx.org-deepdive.md), [freecodecamp.org](reports/freecodecamp.org-deepdive.md), [go.dev](reports/go.dev-deepdive.md), [khanacademy.org](reports/khanacademy.org-deepdive.md), [owasp.org](reports/owasp.org-deepdive.md)。補充文件不另加到索引總數，以免重複計算。
- 出現如 `5.stripe.com` 的名稱時保留原始索引識別字，不猜測或自動改成其他主機。報告可能含誤判、過期狀態或測試方法限制；高風險結論需獨立複核，並遵守目標的授權與揭露規範。

## 站點索引

| Site | Findings | High | Med | Low | Info | Program |
|---|---:|---:|---:|---:|---:|---|
| [ baihu-tw.com ](reports/baihu-tw.com-deepdive.md) | 11 | 0 | 2 | 3 | 6 | manual pentest (no program) |
| [ xyz566.com ](reports/xyz566.com.md) | 7 | 2 | 2 | 1 | 2 | top-websites gist (no active program match) |
| [ square.com ](reports/square.com.md) | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| [ 5.stripe.com ](reports/5.stripe.com.md) | 9 | 0 | 0 | 0 | 9 | [Stripe](https://hackerone.com/stripe) |
| [ 5.paypal.com ](reports/5.paypal.com.md) | 10 | 0 | 0 | 3 | 7 | [PayPal](https://hackerone.com/paypal) |
| [ adyen.com ](reports/adyen.com.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ bunq.com ](reports/bunq.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ n26.com ](reports/n26.com.md) | 6 | 0 | 0 | 2 | 4 | top-websites gist (no active program match) |
| [ citi.com ](reports/citi.com.md) | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| [ 5.chase.com ](reports/5.chase.com.md) | 5 | 0 | 0 | 1 | 4 | [Chase](https://responsibledisclosure.jpmorganchase.com) |
| [ kayak.com ](reports/kayak.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ 5.expedia.com ](reports/5.expedia.com.md) | 7 | 0 | 0 | 3 | 4 | [Expedia Group](https://hackerone.com/expediagroup) |
| [ trip.com ](reports/trip.com.md) | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| [ 5.tripadvisor.com ](reports/5.tripadvisor.com.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ sephora.com ](reports/sephora.com.md) | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| [ nike.com ](reports/nike.com.md) | 13 | 0 | 0 | 7 | 6 | top-websites gist (no active program match) |
| [ bestbuy.com ](reports/bestbuy.com.md) | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| [ hotels.com ](reports/hotels.com.md) | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| [ zara.com ](reports/zara.com.md) | 4 | 0 | 0 | 0 | 4 | top-websites gist (no active program match) |
| [ ing.com ](reports/ing.com.md) | 5 | 0 | 0 | 0 | 5 | top-websites gist (no active program match) |
| [ fidelity.com ](reports/fidelity.com.md) | 5 | 0 | 0 | 0 | 5 | top-websites gist (no active program match) |
| [ ibkr.com ](reports/ibkr.com.md) | 3 | 0 | 0 | 0 | 3 | top-websites gist (no active program match) |
| [ revolut.com ](reports/revolut.com.md) | 11 | 0 | 0 | 6 | 5 | top-websites gist (no active program match) |
| [ wise.com ](reports/wise.com.md) | 10 | 0 | 0 | 7 | 3 | top-websites gist (no active program match) |
| [ uniqlo.com ](reports/uniqlo.com.md) | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| [ barclays.co.uk ](reports/barclays.co.uk.md) | 6 | 0 | 0 | 2 | 4 | top-websites gist (no active program match) |
| [ monzo.com ](reports/monzo.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ robinhood.com ](reports/robinhood.com.md) | 60 | 46 | 0 | 9 | 5 | top-websites gist (no active program match) |
| [ binance.com ](reports/binance.com.md) | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| [ hsbc.com ](reports/hsbc.com.md) | 3 | 0 | 0 | 0 | 3 | top-websites gist (no active program match) |
| [ pnc.com ](reports/pnc.com.md) | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| [ wellsfargo.com ](reports/wellsfargo.com.md) | 6 | 0 | 0 | 2 | 4 | top-websites gist (no active program match) |
| [ capitalone.com ](reports/capitalone.com.md) | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| [ aol.com ](reports/aol.com.md) | 14 | 0 | 0 | 12 | 2 | top-websites gist (no active program match) |
| [ figma.com ](reports/figma.com.md) | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| [ yale.edu ](reports/yale.edu.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ duke.edu ](reports/duke.edu.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ harvard.edu ](reports/harvard.edu.md) | 12 | 0 | 0 | 9 | 3 | top-websites gist (no active program match) |
| [ nyu.edu ](reports/nyu.edu.md) | 9 | 0 | 0 | 4 | 5 | top-websites gist (no active program match) |
| [ caltech.edu ](reports/caltech.edu.md) | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| [ cornell.edu ](reports/cornell.edu.md) | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| [ princeton.edu ](reports/princeton.edu.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ stanford.edu ](reports/stanford.edu.md) | 8 | 0 | 0 | 5 | 3 | top-websites gist (no active program match) |
| [ mit.edu ](reports/mit.edu.md) | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| [ audible.com ](reports/audible.com.md) | 16 | 0 | 0 | 15 | 1 | top-websites gist (no active program match) |
| [ bitly.com ](reports/bitly.com.md) | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| [ leparisien.fr ](reports/leparisien.fr.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ static.googleusercontent.com ](reports/static.googleusercontent.com.md) | 34 | 0 | 0 | 33 | 1 | top-websites gist (no active program match) |
| [ vmware.com ](reports/vmware.com.md) | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| [ google.ch ](reports/google.ch.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ patheos.com ](reports/patheos.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ podbean.com ](reports/podbean.com.md) | 4 | 0 | 0 | 4 | 0 | top-websites gist (no active program match) |
| [ rakuten.com ](reports/rakuten.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ ko-fi.com ](reports/ko-fi.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ youcaring.com ](reports/youcaring.com.md) | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| [ aclu.org ](reports/aclu.org.md) | 14 | 0 | 0 | 2 | 12 | top-websites gist (no active program match) |
| [ freshbooks.com ](reports/freshbooks.com.md) | 27 | 0 | 0 | 26 | 1 | top-websites gist (no active program match) |
| [ thingiverse.com ](reports/thingiverse.com.md) | 40 | 0 | 0 | 37 | 3 | top-websites gist (no active program match) |
| [ cdbaby.com ](reports/cdbaby.com.md) | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| [ 4shared.com ](reports/4shared.com.md) | 10 | 0 | 0 | 8 | 2 | top-websites gist (no active program match) |
| [ npr.org ](reports/npr.org.md) | 9 | 0 | 0 | 8 | 1 | NPR |
| [ rt.com ](reports/rt.com.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ themeforest.net ](reports/themeforest.net.md) | 28 | 0 | 0 | 27 | 1 | top-websites gist (no active program match) |
| [ gizmodo.com ](reports/gizmodo.com.md) | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| [ 1.envato.market ](reports/1.envato.market.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ cafepress.com ](reports/cafepress.com.md) | 15 | 1 | 0 | 3 | 11 | top-websites gist (no active program match) |
| [ ocw.mit.edu ](reports/ocw.mit.edu.md) | 9 | 0 | 0 | 3 | 6 | top-websites gist (no active program match) |
| [ use.fontawesome.com ](reports/use.fontawesome.com.md) | 11 | 0 | 0 | 3 | 8 | top-websites gist (no active program match) |
| [ googleblog.blogspot.com ](reports/googleblog.blogspot.com.md) | 35 | 0 | 0 | 32 | 3 | top-websites gist (no active program match) |
| [ bitpay.com ](reports/bitpay.com.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ wa.me ](reports/wa.me.md) | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| [ michigan.gov ](reports/michigan.gov.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ statista.com ](reports/statista.com.md) | 35 | 0 | 0 | 35 | 0 | top-websites gist (no active program match) |
| [ rebrand.ly ](reports/rebrand.ly.md) | 31 | 0 | 0 | 31 | 0 | top-websites gist (no active program match) |
| [ ssl.gstatic.com ](reports/ssl.gstatic.com.md) | 34 | 0 | 0 | 33 | 1 | top-websites gist (no active program match) |
| [ repubblica.it ](reports/repubblica.it.md) | 8 | 0 | 0 | 7 | 1 | top-websites gist (no active program match) |
| [ geek.com ](reports/geek.com.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ boardgamegeek.com ](reports/boardgamegeek.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ sfgate.com ](reports/sfgate.com.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ dafont.com ](reports/dafont.com.md) | 11 | 0 | 0 | 8 | 3 | top-websites gist (no active program match) |
| [ material.io ](reports/material.io.md) | 8 | 0 | 0 | 5 | 3 | Google |
| [ raspberrypi.org ](reports/raspberrypi.org.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ help.ubuntu.com ](reports/help.ubuntu.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ pewinternet.org ](reports/pewinternet.org.md) | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| [ maxcdn.bootstrapcdn.com ](reports/maxcdn.bootstrapcdn.com.md) | 13 | 0 | 0 | 3 | 10 | BootstrapCDN |
| [ android.com ](reports/android.com.md) | 7 | 0 | 0 | 6 | 1 | Google |
| [ crowdrise.com ](reports/crowdrise.com.md) | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| [ amnestyusa.org ](reports/amnestyusa.org.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ guardian.co.uk ](reports/guardian.co.uk.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ ucl.ac.uk ](reports/ucl.ac.uk.md) | 28 | 0 | 0 | 25 | 3 | top-websites gist (no active program match) |
| [ archive.org ](reports/archive.org.md) | 4 | 0 | 0 | 2 | 2 | Internet Archive |
| [ behance.net ](reports/behance.net.md) | 5 | 0 | 0 | 3 | 2 | Adobe |
| [ zazzle.com ](reports/zazzle.com.md) | 2 | 0 | 0 | 1 | 1 | top-websites gist (no active program match) |
| [ imore.com ](reports/imore.com.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ last.fm ](reports/last.fm.md) | 20 | 0 | 0 | 17 | 3 | top-websites gist (no active program match) |
| [ s.ytimg.com ](reports/s.ytimg.com.md) | 4 | 0 | 0 | 3 | 1 | top-websites gist (no active program match) |
| [ sciencedirect.com ](reports/sciencedirect.com.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ springer.com ](reports/springer.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ arxiv.org ](reports/arxiv.org.md) | 4 | 0 | 0 | 1 | 3 | arXiv |
| [ variety.com ](reports/variety.com.md) | 4 | 0 | 0 | 1 | 3 | Variety |
| [ unsplash.com ](reports/unsplash.com.md) | 7 | 0 | 0 | 4 | 3 | Unsplash |
| [ 500px.com ](reports/500px.com.md) | 18 | 0 | 0 | 14 | 4 | top-websites gist (no active program match) |
| [ obsproject.com ](reports/obsproject.com.md) | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| [ goodreads.com ](reports/goodreads.com.md) | 9 | 0 | 0 | 8 | 1 | top-websites gist (no active program match) |
| [ marthastewart.com ](reports/marthastewart.com.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ nba.com ](reports/nba.com.md) | 16 | 0 | 0 | 15 | 1 | top-websites gist (no active program match) |
| [ fonts.gstatic.com ](reports/fonts.gstatic.com.md) | 34 | 0 | 0 | 33 | 1 | top-websites gist (no active program match) |
| [ change.org ](reports/change.org.md) | 16 | 0 | 0 | 12 | 4 | top-websites gist (no active program match) |
| [ 1.gravatar.com ](reports/1.gravatar.com.md) | 6 | 0 | 0 | 2 | 4 | top-websites gist (no active program match) |
| [ capterra.com ](reports/capterra.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ barnesandnoble.com ](reports/barnesandnoble.com.md) | 9 | 0 | 0 | 8 | 1 | top-websites gist (no active program match) |
| [ web.archive.org ](reports/web.archive.org.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ smashwords.com ](reports/smashwords.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ redcross.org ](reports/redcross.org.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ discord.gg ](reports/discord.gg.md) | 32 | 0 | 0 | 28 | 4 | top-websites gist (no active program match) |
| [ tandfonline.com ](reports/tandfonline.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ wattpad.com ](reports/wattpad.com.md) | 24 | 0 | 0 | 13 | 11 | top-websites gist (no active program match) |
| [ avvo.com ](reports/avvo.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ news.discovery.com ](reports/news.discovery.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ digiday.com ](reports/digiday.com.md) | 20 | 0 | 0 | 16 | 4 | top-websites gist (no active program match) |
| [ globalsign.com ](reports/globalsign.com.md) | 39 | 0 | 0 | 34 | 5 | top-websites gist (no active program match) |
| [ we.tl ](reports/we.tl.md) | 32 | 0 | 0 | 32 | 0 | top-websites gist (no active program match) |
| [ example.com ](reports/example.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ es.linkedin.com ](reports/es.linkedin.com.md) | 11 | 0 | 0 | 10 | 1 | top-websites gist (no active program match) |
| [ esa.int ](reports/esa.int.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ gum.co ](reports/gum.co.md) | 10 | 0 | 0 | 9 | 1 | top-websites gist (no active program match) |
| [ loc.gov ](reports/loc.gov.md) | 31 | 0 | 0 | 31 | 0 | top-websites gist (no active program match) |
| [ it.wikipedia.org ](reports/it.wikipedia.org.md) | 22 | 0 | 2 | 18 | 2 | top-websites gist (no active program match) |
| [ dev.to ](reports/dev.to.md) | 17 | 0 | 0 | 8 | 9 | top-websites gist (no active program match) |
| [ bol.com ](reports/bol.com.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ news.nationalgeographic.com ](reports/news.nationalgeographic.com.md) | 41 | 0 | 0 | 36 | 5 | top-websites gist (no active program match) |
| [ s.w.org ](reports/s.w.org.md) | 10 | 0 | 0 | 7 | 3 | WordPress |
| [ agoda.com ](reports/agoda.com.md) | 9 | 0 | 2 | 5 | 2 | top-websites gist (no active program match) |
| [ usatoday.com ](reports/usatoday.com.md) | 9 | 0 | 0 | 2 | 7 | USA Today |
| [ presseportal.de ](reports/presseportal.de.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ upload.wikimedia.org ](reports/upload.wikimedia.org.md) | 36 | 0 | 0 | 34 | 2 | top-websites gist (no active program match) |
| [ uk.linkedin.com ](reports/uk.linkedin.com.md) | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| [ lh3.ggpht.com ](reports/lh3.ggpht.com.md) | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| [ brookings.edu ](reports/brookings.edu.md) | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| [ theatlantic.com ](reports/theatlantic.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ squarespace.com ](reports/squarespace.com.md) | 13 | 0 | 0 | 11 | 2 | top-websites gist (no active program match) |
| [ 9to5mac.com ](reports/9to5mac.com.md) | 18 | 0 | 0 | 14 | 4 | top-websites gist (no active program match) |
| [ ft.com ](reports/ft.com.md) | 11 | 0 | 0 | 3 | 8 | Financial Times |
| [ elegantthemes.com ](reports/elegantthemes.com.md) | 33 | 0 | 0 | 31 | 2 | top-websites gist (no active program match) |
| [ google.ie ](reports/google.ie.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ xinhuanet.com ](reports/xinhuanet.com.md) | 8 | 0 | 0 | 5 | 3 | top-websites gist (no active program match) |
| [ tinyurl.com ](reports/tinyurl.com.md) | 9 | 0 | 0 | 9 | 0 | TinyURL |
| [ stocktwits.com ](reports/stocktwits.com.md) | 32 | 0 | 0 | 32 | 0 | top-websites gist (no active program match) |
| [ nfl.com ](reports/nfl.com.md) | 17 | 0 | 0 | 7 | 10 | top-websites gist (no active program match) |
| [ br.linkedin.com ](reports/br.linkedin.com.md) | 12 | 0 | 0 | 11 | 1 | top-websites gist (no active program match) |
| [ ubuntu.com ](reports/ubuntu.com.md) | 14 | 0 | 0 | 13 | 1 | top-websites gist (no active program match) |
| [ theglobeandmail.com ](reports/theglobeandmail.com.md) | 9 | 0 | 0 | 5 | 4 | top-websites gist (no active program match) |
| [ oprah.com ](reports/oprah.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ louvre.fr ](reports/louvre.fr.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ googleads.g.doubleclick.net ](reports/googleads.g.doubleclick.net.md) | 6 | 0 | 0 | 5 | 1 | Google |
| [ doi.org ](reports/doi.org.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ osha.gov ](reports/osha.gov.md) | 9 | 0 | 0 | 9 | 0 | top-websites gist (no active program match) |
| [ rockpapershotgun.com ](reports/rockpapershotgun.com.md) | 4 | 0 | 0 | 4 | 0 | top-websites gist (no active program match) |
| [ google.es ](reports/google.es.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ unesco.org ](reports/unesco.org.md) | 9 | 0 | 0 | 7 | 2 | top-websites gist (no active program match) |
| [ bmj.com ](reports/bmj.com.md) | 36 | 0 | 0 | 33 | 3 | top-websites gist (no active program match) |
| [ relapse.com ](reports/relapse.com.md) | 12 | 0 | 0 | 9 | 3 | top-websites gist (no active program match) |
| [ vsco.co ](reports/vsco.co.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ foursquare.com ](reports/foursquare.com.md) | 17 | 0 | 0 | 15 | 2 | top-websites gist (no active program match) |
| [ olympic.org ](reports/olympic.org.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ discord.me ](reports/discord.me.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ dev.mysql.com ](reports/dev.mysql.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ worldbank.org ](reports/worldbank.org.md) | 8 | 0 | 0 | 7 | 1 | top-websites gist (no active program match) |
| [ theverge.com ](reports/theverge.com.md) | 16 | 0 | 0 | 14 | 2 | top-websites gist (no active program match) |
| [ ted.com ](reports/ted.com.md) | 8 | 0 | 0 | 7 | 1 | top-websites gist (no active program match) |
| [ upi.com ](reports/upi.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ nhs.uk ](reports/nhs.uk.md) | 3 | 0 | 0 | 3 | 0 | top-websites gist (no active program match) |
| [ prntscr.com ](reports/prntscr.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ fortune.com ](reports/fortune.com.md) | 46 | 0 | 1 | 36 | 9 | Fortune |
| [ ustream.tv ](reports/ustream.tv.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ fas.org ](reports/fas.org.md) | 1 | 0 | 0 | 0 | 1 | top-websites gist (no active program match) |
| [ google.fr ](reports/google.fr.md) | 13 | 0 | 0 | 9 | 4 | Google |
| [ autodesk.com ](reports/autodesk.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ form.jotform.com ](reports/form.jotform.com.md) | 15 | 0 | 0 | 15 | 0 | top-websites gist (no active program match) |
| [ synology.com ](reports/synology.com.md) | 28 | 0 | 0 | 28 | 0 | top-websites gist (no active program match) |
| [ huffpost.com ](reports/huffpost.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ gmail.com ](reports/gmail.com.md) | 32 | 0 | 0 | 31 | 1 | Google |
| [ latimes.com ](reports/latimes.com.md) | 27 | 0 | 0 | 25 | 2 | top-websites gist (no active program match) |
| [ google.com.au ](reports/google.com.au.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ dailymail.co.uk ](reports/dailymail.co.uk.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ thelancet.com ](reports/thelancet.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ news.bbc.co.uk ](reports/news.bbc.co.uk.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ huffingtonpost.co.uk ](reports/huffingtonpost.co.uk.md) | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| [ steemit.com ](reports/steemit.com.md) | 53 | 0 | 0 | 49 | 4 | top-websites gist (no active program match) |
| [ warriorforum.com ](reports/warriorforum.com.md) | 8 | 0 | 0 | 5 | 3 | top-websites gist (no active program match) |
| [ examiner.com ](reports/examiner.com.md) | 4 | 0 | 0 | 4 | 0 | top-websites gist (no active program match) |
| [ kickstarter.com ](reports/kickstarter.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ booking.com ](reports/booking.com.md) | 12 | 0 | 0 | 7 | 5 | top-websites gist (no active program match) |
| [ thenextweb.com ](reports/thenextweb.com.md) | 6 | 0 | 2 | 3 | 1 | top-websites gist (no active program match) |
| [ godaddy.com ](reports/godaddy.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ schema.org ](reports/schema.org.md) | 39 | 0 | 0 | 36 | 3 | top-websites gist (no active program match) |
| [ science.sciencemag.org ](reports/science.sciencemag.org.md) | 32 | 0 | 0 | 31 | 1 | top-websites gist (no active program match) |
| [ pastebin.com ](reports/pastebin.com.md) | 26 | 0 | 0 | 25 | 1 | top-websites gist (no active program match) |
| [ i1.wp.com ](reports/i1.wp.com.md) | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| [ patreon.com ](reports/patreon.com.md) | 21 | 1 | 0 | 16 | 4 | top-websites gist (no active program match) |
| [ whc.unesco.org ](reports/whc.unesco.org.md) | 33 | 0 | 0 | 33 | 0 | top-websites gist (no active program match) |
| [ adweek.com ](reports/adweek.com.md) | 20 | 0 | 0 | 17 | 3 | top-websites gist (no active program match) |
| [ francetvinfo.fr ](reports/francetvinfo.fr.md) | 30 | 0 | 0 | 27 | 3 | top-websites gist (no active program match) |
| [ newyorker.com ](reports/newyorker.com.md) | 7 | 0 | 0 | 6 | 1 | top-websites gist (no active program match) |
| [ spectrum.ieee.org ](reports/spectrum.ieee.org.md) | 5 | 0 | 1 | 2 | 2 | top-websites gist (no active program match) |
| [ anchor.fm ](reports/anchor.fm.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ scoop.it ](reports/scoop.it.md) | 29 | 0 | 0 | 26 | 3 | top-websites gist (no active program match) |
| [ independent.co.uk ](reports/independent.co.uk.md) | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| [ sfexaminer.com ](reports/sfexaminer.com.md) | 9 | 0 | 0 | 8 | 1 | top-websites gist (no active program match) |
| [ git-scm.com ](reports/git-scm.com.md) | 12 | 0 | 0 | 3 | 9 | top-websites gist (no active program match) |
| [ bitcointalk.org ](reports/bitcointalk.org.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ google.pt ](reports/google.pt.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ de.wikipedia.org ](reports/de.wikipedia.org.md) | 19 | 0 | 1 | 16 | 2 | top-websites gist (no active program match) |
| [ pwc.com ](reports/pwc.com.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ i.ytimg.com ](reports/i.ytimg.com.md) | 4 | 0 | 0 | 3 | 1 | top-websites gist (no active program match) |
| [ tunein.com ](reports/tunein.com.md) | 32 | 0 | 0 | 31 | 1 | top-websites gist (no active program match) |
| [ discogs.com ](reports/discogs.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ flaticon.com ](reports/flaticon.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ google.co.nz ](reports/google.co.nz.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ faz.net ](reports/faz.net.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ box.net ](reports/box.net.md) | 31 | 0 | 0 | 30 | 1 | top-websites gist (no active program match) |
| [ telegraph.co.uk ](reports/telegraph.co.uk.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ google.gr ](reports/google.gr.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ thetimes.co.uk ](reports/thetimes.co.uk.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ qz.com ](reports/qz.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ media.giphy.com ](reports/media.giphy.com.md) | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| [ snopes.com ](reports/snopes.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ freepik.com ](reports/freepik.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ stitcher.com ](reports/stitcher.com.md) | 7 | 0 | 2 | 3 | 2 | top-websites gist (no active program match) |
| [ yummly.com ](reports/yummly.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ cnet.com ](reports/cnet.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ pinterest.ca ](reports/pinterest.ca.md) | 4 | 0 | 0 | 4 | 0 | top-websites gist (no active program match) |
| [ lh5.googleusercontent.com ](reports/lh5.googleusercontent.com.md) | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| [ audacityteam.org ](reports/audacityteam.org.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ neh.gov ](reports/neh.gov.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ npmjs.com ](reports/npmjs.com.md) | 34 | 0 | 0 | 33 | 1 | top-websites gist (no active program match) |
| [ geocities.com ](reports/geocities.com.md) | 21 | 0 | 0 | 20 | 1 | top-websites gist (no active program match) |
| [ cbsnews.com ](reports/cbsnews.com.md) | 5 | 0 | 0 | 3 | 2 | Paramount |
| [ copyblogger.com ](reports/copyblogger.com.md) | 5 | 0 | 0 | 5 | 0 | top-websites gist (no active program match) |
| [ pagead2.googlesyndication.com ](reports/pagead2.googlesyndication.com.md) | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| [ cnn.com ](reports/cnn.com.md) | 16 | 0 | 0 | 5 | 11 | CNN |
| [ foodnetwork.com ](reports/foodnetwork.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ bitbucket.org ](reports/bitbucket.org.md) | 12 | 0 | 0 | 5 | 7 | Atlassian |
| [ commons.wikimedia.org ](reports/commons.wikimedia.org.md) | 24 | 0 | 1 | 21 | 2 | top-websites gist (no active program match) |
| [ vanmiubeauty.com ](reports/vanmiubeauty.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ spreaker.com ](reports/spreaker.com.md) | 15 | 0 | 0 | 13 | 2 | top-websites gist (no active program match) |
| [ mixi.jp ](reports/mixi.jp.md) | 17 | 0 | 0 | 15 | 2 | top-websites gist (no active program match) |
| [ billboard.com ](reports/billboard.com.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ refinery29.com ](reports/refinery29.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ europe1.fr ](reports/europe1.fr.md) | 14 | 1 | 0 | 2 | 11 | top-websites gist (no active program match) |
| [ hulu.com ](reports/hulu.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ lh6.googleusercontent.com ](reports/lh6.googleusercontent.com.md) | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| [ searchengineland.com ](reports/searchengineland.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ google.cz ](reports/google.cz.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ apple.co ](reports/apple.co.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ bbc.co.uk ](reports/bbc.co.uk.md) | 2 | 0 | 0 | 2 | 0 | BBC |
| [ nodejs.org ](reports/nodejs.org.md) | 9 | 0 | 0 | 5 | 4 | OpenJS Foundation |
| [ livescience.com ](reports/livescience.com.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ colorado.edu ](reports/colorado.edu.md) | 11 | 0 | 0 | 7 | 4 | top-websites gist (no active program match) |
| [ appstore.com ](reports/appstore.com.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ cbc.ca ](reports/cbc.ca.md) | 30 | 0 | 0 | 26 | 4 | top-websites gist (no active program match) |
| [ hollywoodreporter.com ](reports/hollywoodreporter.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ code.jquery.com ](reports/code.jquery.com.md) | 5 | 0 | 0 | 2 | 3 | jQuery |
| [ law.cornell.edu ](reports/law.cornell.edu.md) | 15 | 0 | 0 | 12 | 3 | top-websites gist (no active program match) |
| [ thehill.com ](reports/thehill.com.md) | 7 | 0 | 0 | 4 | 3 | The Hill |
| [ huffingtonpost.com ](reports/huffingtonpost.com.md) | 6 | 0 | 0 | 5 | 1 | HuffPost |
| [ google.co.jp ](reports/google.co.jp.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ entrepreneur.com ](reports/entrepreneur.com.md) | 17 | 0 | 0 | 14 | 3 | top-websites gist (no active program match) |
| [ gopro.com ](reports/gopro.com.md) | 12 | 0 | 2 | 7 | 3 | top-websites gist (no active program match) |
| [ apnews.com ](reports/apnews.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ stadt-bremerhaven.de ](reports/stadt-bremerhaven.de.md) | 8 | 0 | 0 | 5 | 3 | top-websites gist (no active program match) |
| [ chiark.greenend.org.uk ](reports/chiark.greenend.org.uk.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ 0.gravatar.com ](reports/0.gravatar.com.md) | 4 | 0 | 0 | 0 | 4 | top-websites gist (no active program match) |
| [ google.pl ](reports/google.pl.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ lifehacker.com ](reports/lifehacker.com.md) | 28 | 0 | 0 | 27 | 1 | top-websites gist (no active program match) |
| [ onlinelibrary.wiley.com ](reports/onlinelibrary.wiley.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ philips.co.uk ](reports/philips.co.uk.md) | 11 | 0 | 0 | 9 | 2 | top-websites gist (no active program match) |
| [ ebay.com ](reports/ebay.com.md) | 4 | 0 | 0 | 2 | 2 | eBay |
| [ mtv.com ](reports/mtv.com.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ cia.gov ](reports/cia.gov.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ w3.org ](reports/w3.org.md) | 33 | 0 | 0 | 33 | 0 | W3C |
| [ pbs.org ](reports/pbs.org.md) | 17 | 1 | 0 | 14 | 2 | top-websites gist (no active program match) |
| [ openstreetmap.org ](reports/openstreetmap.org.md) | 13 | 0 | 0 | 8 | 5 | top-websites gist (no active program match) |
| [ money.cnn.com ](reports/money.cnn.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ techsmith.com ](reports/techsmith.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ buzzfeed.com ](reports/buzzfeed.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ blip.tv ](reports/blip.tv.md) | 8 | 0 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ flattr.com ](reports/flattr.com.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ problogger.net ](reports/problogger.net.md) | 17 | 0 | 1 | 14 | 2 | top-websites gist (no active program match) |
| [ fda.gov ](reports/fda.gov.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ androidauthority.com ](reports/androidauthority.com.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ ign.com ](reports/ign.com.md) | 20 | 0 | 0 | 9 | 11 | top-websites gist (no active program match) |
| [ lg.com ](reports/lg.com.md) | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| [ rtve.es ](reports/rtve.es.md) | 15 | 0 | 7 | 5 | 3 | top-websites gist (no active program match) |
| [ bit.ly ](reports/bit.ly.md) | 9 | 0 | 0 | 5 | 4 | Bitly |
| [ vanityfair.com ](reports/vanityfair.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ popsci.com ](reports/popsci.com.md) | 20 | 0 | 0 | 16 | 4 | top-websites gist (no active program match) |
| [ fao.org ](reports/fao.org.md) | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| [ unity3d.com ](reports/unity3d.com.md) | 22 | 0 | 0 | 20 | 2 | top-websites gist (no active program match) |
| [ ilpost.it ](reports/ilpost.it.md) | 9 | 1 | 0 | 6 | 2 | top-websites gist (no active program match) |
| [ static.wixstatic.com ](reports/static.wixstatic.com.md) | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| [ sony.net ](reports/sony.net.md) | 5 | 0 | 0 | 2 | 3 | top-websites gist (no active program match) |
| [ cdn.ampproject.org ](reports/cdn.ampproject.org.md) | 35 | 0 | 0 | 34 | 1 | top-websites gist (no active program match) |
| [ google.ru ](reports/google.ru.md) | 13 | 0 | 1 | 8 | 4 | top-websites gist (no active program match) |
| [ youtu.be ](reports/youtu.be.md) | 20 | 0 | 1 | 17 | 2 | Google |
| [ houzz.com ](reports/houzz.com.md) | 10 | 1 | 1 | 7 | 1 | top-websites gist (no active program match) |
| [ a2hosting.com ](reports/a2hosting.com.md) | 1 | 0 | 0 | 1 | 0 | top-websites gist (no active program match) |
| [ target.com ](reports/target.com.md) | 9 | 0 | 0 | 9 | 0 | Target |
| [ tensorflow.org ](reports/tensorflow.org.md) | 32 | 0 | 0 | 31 | 1 | top-websites gist (no active program match) |
| [ songkick.com ](reports/songkick.com.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ edition.cnn.com ](reports/edition.cnn.com.md) | 13 | 0 | 0 | 3 | 10 | top-websites gist (no active program match) |
| [ goo.gl ](reports/goo.gl.md) | 4 | 0 | 0 | 3 | 1 | Google |
| [ google.co.in ](reports/google.co.in.md) | 13 | 0 | 0 | 9 | 4 | top-websites gist (no active program match) |
| [ venturebeat.com ](reports/venturebeat.com.md) | 7 | 0 | 0 | 4 | 3 | top-websites gist (no active program match) |
| [ lesechos.fr ](reports/lesechos.fr.md) | 31 | 0 | 0 | 30 | 1 | top-websites gist (no active program match) |
| [ gnu.org ](reports/gnu.org.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ namecheap.com ](reports/namecheap.com.md) | 4 | 0 | 0 | 2 | 2 | top-websites gist (no active program match) |
| [ ticketmaster.com ](reports/ticketmaster.com.md) | 6 | 0 | 0 | 5 | 1 | top-websites gist (no active program match) |
| [ whitehouse.gov ](reports/whitehouse.gov.md) | 3 | 0 | 0 | 1 | 2 | White House |
| [ eventbrite.co.uk ](reports/eventbrite.co.uk.md) | 12 | 0 | 0 | 10 | 2 | top-websites gist (no active program match) |
| [ symfony.com ](reports/symfony.com.md) | 27 | 0 | 0 | 25 | 2 | top-websites gist (no active program match) |
| [ thumbtack.com ](reports/thumbtack.com.md) | 13 | 0 | 0 | 5 | 8 | top-websites gist (no active program match) |
| [ jamanetwork.com ](reports/jamanetwork.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ dol.gov ](reports/dol.gov.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ docs.wixstatic.com ](reports/docs.wixstatic.com.md) | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| [ mozilla.org ](reports/mozilla.org.md) | 10 | 0 | 0 | 3 | 7 | Mozilla |
| [ indiegogo.com ](reports/indiegogo.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ cdn.jsdelivr.net ](reports/cdn.jsdelivr.net.md) | 5 | 0 | 0 | 3 | 2 | jsDelivr |
| [ siteground.com ](reports/siteground.com.md) | 38 | 0 | 0 | 35 | 3 | top-websites gist (no active program match) |
| [ lefigaro.fr ](reports/lefigaro.fr.md) | 9 | 0 | 1 | 6 | 2 | top-websites gist (no active program match) |
| [ developer.mozilla.org ](reports/developer.mozilla.org.md) | 7 | 0 | 0 | 7 | 0 | top-websites gist (no active program match) |
| [ tiny.cc ](reports/tiny.cc.md) | 8 | 0 | 0 | 4 | 4 | top-websites gist (no active program match) |
| [ propublica.org ](reports/propublica.org.md) | 25 | 0 | 3 | 20 | 2 | top-websites gist (no active program match) |
| [ digg.com ](reports/digg.com.md) | 28 | 0 | 1 | 22 | 5 | top-websites gist (no active program match) |
| [ technorati.com ](reports/technorati.com.md) | 9 | 0 | 0 | 6 | 3 | top-websites gist (no active program match) |
| [ access.redhat.com ](reports/access.redhat.com.md) | 15 | 0 | 1 | 11 | 3 | top-websites gist (no active program match) |
| [ wsj.com ](reports/wsj.com.md) | 6 | 0 | 0 | 4 | 2 | The Wall Street Journal |
| [ gstatic.com ](reports/gstatic.com.md) | 35 | 0 | 0 | 34 | 1 | Google |
| [ gplus.to ](reports/gplus.to.md) | 11 | 0 | 1 | 8 | 2 | top-websites gist (no active program match) |
| [ google.cn ](reports/google.cn.md) | 10 | 0 | 0 | 7 | 3 | top-websites gist (no active program match) |
| [ ericsson.com ](reports/ericsson.com.md) | 29 | 0 | 0 | 29 | 0 | top-websites gist (no active program match) |
| [ payhip.com ](reports/payhip.com.md) | 5 | 0 | 0 | 4 | 1 | top-websites gist (no active program match) |
| [ webmasters.googleblog.com ](reports/webmasters.googleblog.com.md) | 26 | 0 | 0 | 25 | 1 | top-websites gist (no active program match) |
| [ s3-eu-west-1.amazonaws.com ](reports/s3-eu-west-1.amazonaws.com.md) | 13 | 0 | 1 | 4 | 8 | top-websites gist (no active program match) |
| [ teespring.com ](reports/teespring.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ iheart.com ](reports/iheart.com.md) | 3 | 0 | 0 | 3 | 0 | top-websites gist (no active program match) |
| [ gimp.org ](reports/gimp.org.md) | 3 | 0 | 0 | 1 | 2 | top-websites gist (no active program match) |
| [ buff.ly ](reports/buff.ly.md) | 25 | 0 | 1 | 22 | 2 | top-websites gist (no active program match) |
| [ support.mozilla.org ](reports/support.mozilla.org.md) | 8 | 0 | 1 | 4 | 3 | top-websites gist (no active program match) |
| [ orcid.org ](reports/orcid.org.md) | 9 | 0 | 1 | 5 | 3 | top-websites gist (no active program match) |
| [ db.tt ](reports/db.tt.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ twitch.tv ](reports/twitch.tv.md) | 9 | 0 | 2 | 6 | 1 | Twitch |
| [ vox.com ](reports/vox.com.md) | 18 | 0 | 0 | 17 | 1 | top-websites gist (no active program match) |
| [ businesswire.com ](reports/businesswire.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ www8.hp.com ](reports/www8.hp.com.md) | 6 | 0 | 0 | 3 | 3 | top-websites gist (no active program match) |
| [ journals.plos.org ](reports/journals.plos.org.md) | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| [ mailchi.mp ](reports/mailchi.mp.md) | 33 | 0 | 0 | 31 | 2 | top-websites gist (no active program match) |
| [ scratch.mit.edu ](reports/scratch.mit.edu.md) | 30 | 0 | 1 | 21 | 8 | top-websites gist (no active program match) |
| [ smithsonianmag.com ](reports/smithsonianmag.com.md) | 33 | 0 | 28 | 3 | 2 | top-websites gist (no active program match) |
| [ chromium.org ](reports/chromium.org.md) | 4 | 0 | 0 | 1 | 3 | top-websites gist (no active program match) |
| [ stumbleupon.com ](reports/stumbleupon.com.md) | 19 | 0 | 4 | 13 | 2 | top-websites gist (no active program match) |
| [ mediafire.com ](reports/mediafire.com.md) | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| [ politico.com ](reports/politico.com.md) | 7 | 0 | 0 | 4 | 3 | Politico |
| [ bloglovin.com ](reports/bloglovin.com.md) | 3 | 0 | 0 | 2 | 1 | top-websites gist (no active program match) |
| [ ssl.google-analytics.com ](reports/ssl.google-analytics.com.md) | 13 | 0 | 3 | 7 | 3 | top-websites gist (no active program match) |
| [ fr.linkedin.com ](reports/fr.linkedin.com.md) | 11 | 0 | 1 | 9 | 1 | top-websites gist (no active program match) |
| [ mozilla.com ](reports/mozilla.com.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ nginx.com ](reports/nginx.com.md) | 5 | 0 | 0 | 3 | 2 | top-websites gist (no active program match) |
| [ code.visualstudio.com ](reports/code.visualstudio.com.md) | 6 | 0 | 2 | 2 | 2 | top-websites gist (no active program match) |
| [ hawaii.edu ](reports/hawaii.edu.md) | 12 | 0 | 0 | 8 | 4 | top-websites gist (no active program match) |
| [ nicovideo.jp ](reports/nicovideo.jp.md) | 27 | 1 | 0 | 23 | 3 | top-websites gist (no active program match) |
| [ deepl.com ](reports/deepl.com.md) | 32 | 0 | 0 | 31 | 1 | top-websites gist (no active program match) |
| [ s3.amazonaws.com ](reports/s3.amazonaws.com.md) | 8 | 0 | 2 | 4 | 2 | AWS |
| [ academic.oup.com ](reports/academic.oup.com.md) | 7 | 0 | 0 | 5 | 2 | top-websites gist (no active program match) |
| [ kotaku.com ](reports/kotaku.com.md) | 2 | 0 | 0 | 2 | 0 | top-websites gist (no active program match) |
| [ metro.co.uk ](reports/metro.co.uk.md) | 10 | 0 | 3 | 3 | 4 | top-websites gist (no active program match) |
| [ blog.feedspot.com ](reports/blog.feedspot.com.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ thoughtcatalog.com ](reports/thoughtcatalog.com.md) | 17 | 0 | 0 | 14 | 3 | top-websites gist (no active program match) |
| [ tumblr.com ](reports/tumblr.com.md) | 7 | 0 | 1 | 4 | 2 | top-websites gist (no active program match) |
| [ thesun.co.uk ](reports/thesun.co.uk.md) | 22 | 0 | 4 | 15 | 3 | top-websites gist (no active program match) |
| [ sciencemag.org ](reports/sciencemag.org.md) | 33 | 0 | 0 | 30 | 3 | top-websites gist (no active program match) |
| [ columbia.edu ](reports/columbia.edu.md) | 6 | 0 | 0 | 4 | 2 | top-websites gist (no active program match) |
| [ blog.naver.com ](reports/blog.naver.com.md) | 13 | 0 | 3 | 6 | 4 | top-websites gist (no active program match) |
| [ 1.bp.blogspot.com ](reports/1.bp.blogspot.com.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ 1.usa.gov ](reports/1.usa.gov.md) | 13 | 0 | 0 | 3 | 10 | [TTS Bug Bounty](https://hackerone.com/tts) |
| [ 1drv.ms ](reports/1drv.ms.md) | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| [ 2.bp.blogspot.com ](reports/2.bp.blogspot.com.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ 3.bp.blogspot.com ](reports/3.bp.blogspot.com.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ 4.bp.blogspot.com ](reports/4.bp.blogspot.com.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ 7-zip.org ](reports/7-zip.org.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ a.co ](reports/a.co.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ abc.com ](reports/abc.com.md) | 31 | 0 | 0 | 3 | 28 | [The Walt Disney Company](https://hackerone.com/disney) |
| [ abc.net.au ](reports/abc.net.au.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ abcnews.go.com ](reports/abcnews.go.com.md) | 34 | 0 | 0 | 10 | 24 | top-websites gist (no active program match) |
| [ abebooks.com ](reports/abebooks.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ about.fb.com ](reports/about.fb.com.md) | 21 | 0 | 0 | 5 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| [ about.me ](reports/about.me.md) | 31 | 0 | 0 | 7 | 24 | top-websites gist (no active program match) |
| [ aboutads.info ](reports/aboutads.info.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ accenture.com ](reports/accenture.com.md) | 17 | 0 | 0 | 1 | 16 | top-websites gist (no active program match) |
| [ accessdata.fda.gov ](reports/accessdata.fda.gov.md) | 5 | 0 | 1 | 0 | 4 | top-websites gist (no active program match) |
| [ accessify.com ](reports/accessify.com.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ accounts.google.com ](reports/accounts.google.com.md) | 25 | 0 | 0 | 2 | 23 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ acm.org ](reports/acm.org.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ activecampaign.com ](reports/activecampaign.com.md) | 28 | 0 | 0 | 6 | 22 | top-websites gist (no active program match) |
| [ ad.doubleclick.net ](reports/ad.doubleclick.net.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ adage.com ](reports/adage.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ addons.mozilla.org ](reports/addons.mozilla.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ addthis.com ](reports/addthis.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ adf.ly ](reports/adf.ly.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ adobe.com ](reports/adobe.com.md) | 21 | 0 | 0 | 4 | 17 | [Adobe](https://hackerone.com/adobe) |
| [ adobe.ly ](reports/adobe.ly.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ ads.google.com ](reports/ads.google.com.md) | 25 | 0 | 0 | 4 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ adssettings.google.com ](reports/adssettings.google.com.md) | 18 | 0 | 0 | 4 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ adwords.google.com ](reports/adwords.google.com.md) | 25 | 0 | 0 | 5 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ affiliate-program.amazon.com ](reports/affiliate-program.amazon.com.md) | 31 | 0 | 0 | 7 | 24 | [Amazon](https://hackerone.com/amazonvrp) |
| [ airbnb.com ](reports/airbnb.com.md) | 22 | 0 | 0 | 4 | 18 | [Airbnb](https://hackerone.com/airbnb) |
| [ airtable.com ](reports/airtable.com.md) | 26 | 0 | 0 | 4 | 22 | [Airtable](https://hackerone.com/airtable) |
| [ ajax.googleapis.com ](reports/ajax.googleapis.com.md) | 20 | 0 | 0 | 5 | 15 | Google |
| [ aliexpress.com ](reports/aliexpress.com.md) | 28 | 0 | 0 | 8 | 20 | [Alibaba](https://hackerone.com/alibaba) |
| [ aljazeera.com ](reports/aljazeera.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ allmusic.com ](reports/allmusic.com.md) | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| [ amazon.ca ](reports/amazon.ca.md) | 25 | 0 | 0 | 5 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.co.jp ](reports/amazon.co.jp.md) | 24 | 0 | 0 | 5 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.co.uk ](reports/amazon.co.uk.md) | 24 | 0 | 0 | 5 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.com ](reports/amazon.com.md) | 29 | 0 | 0 | 9 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.com.au ](reports/amazon.com.au.md) | 23 | 0 | 0 | 4 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.com.br ](reports/amazon.com.br.md) | 25 | 0 | 0 | 5 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.de ](reports/amazon.de.md) | 24 | 0 | 0 | 5 | 19 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.es ](reports/amazon.es.md) | 24 | 0 | 0 | 4 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.fr ](reports/amazon.fr.md) | 24 | 0 | 0 | 4 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.in ](reports/amazon.in.md) | 24 | 0 | 0 | 4 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ amazon.it ](reports/amazon.it.md) | 25 | 0 | 0 | 5 | 20 | [Amazon](https://hackerone.com/amazonvrp) |
| [ ameblo.jp ](reports/ameblo.jp.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ amzn.asia ](reports/amzn.asia.md) | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| [ amzn.com ](reports/amzn.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ amzn.to ](reports/amzn.to.md) | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| [ analytics.google.com ](reports/analytics.google.com.md) | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ ancestry.com ](reports/ancestry.com.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ animoto.com ](reports/animoto.com.md) | 23 | 0 | 0 | 1 | 22 | top-websites gist (no active program match) |
| [ api.whatsapp.com ](reports/api.whatsapp.com.md) | 15 | 0 | 0 | 2 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| [ apis.google.com ](reports/apis.google.com.md) | 20 | 0 | 0 | 6 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ app.box.com ](reports/app.box.com.md) | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| [ apple.com ](reports/apple.com.md) | 25 | 0 | 0 | 7 | 18 | [Apple](https://security.apple.com) |
| [ apps.apple.com ](reports/apps.apple.com.md) | 24 | 0 | 0 | 2 | 22 | [Apple](https://security.apple.com) |
| [ apps.facebook.com ](reports/apps.facebook.com.md) | 20 | 0 | 0 | 7 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| [ archives.gov ](reports/archives.gov.md) | 15 | 0 | 0 | 1 | 14 | top-websites gist (no active program match) |
| [ arstechnica.com ](reports/arstechnica.com.md) | 27 | 0 | 0 | 5 | 22 | top-websites gist (no active program match) |
| [ artsandculture.google.com ](reports/artsandculture.google.com.md) | 23 | 0 | 0 | 2 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ asus.com ](reports/asus.com.md) | 8 | 0 | 1 | 1 | 6 | top-websites gist (no active program match) |
| [ aub.edu.lb ](reports/aub.edu.lb.md) | 33 | 0 | 0 | 5 | 28 | top-websites gist (no active program match) |
| [ automattic.com ](reports/automattic.com.md) | 29 | 0 | 0 | 6 | 23 | top-websites gist (no active program match) |
| [ aws.amazon.com ](reports/aws.amazon.com.md) | 23 | 0 | 0 | 2 | 21 | [Amazon](https://hackerone.com/amazonvrp) |
| [ axios.com ](reports/axios.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ azure.microsoft.com ](reports/azure.microsoft.com.md) | 9 | 0 | 0 | 2 | 7 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ baidu.com ](reports/baidu.com.md) | 19 | 0 | 0 | 4 | 15 | [Baidu](https://bsrc.baidu.com/v2/#/en) |
| [ bandcamp.com ](reports/bandcamp.com.md) | 27 | 0 | 0 | 5 | 22 | [Epic Games](https://hackerone.com/epicgames) |
| [ bandsintown.com ](reports/bandsintown.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ bbb.org ](reports/bbb.org.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ bbc.com ](reports/bbc.com.md) | 23 | 0 | 0 | 4 | 19 | [BBC](https://www.bbc.com/backstage/security-disclosure-policy/) |
| [ beian.gov.cn ](reports/beian.gov.cn.md) | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| [ bhphotovideo.com ](reports/bhphotovideo.com.md) | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| [ bigthink.com ](reports/bigthink.com.md) | 29 | 0 | 0 | 4 | 25 | top-websites gist (no active program match) |
| [ bild.de ](reports/bild.de.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ bing.com ](reports/bing.com.md) | 25 | 0 | 0 | 8 | 17 | top-websites gist (no active program match) |
| [ bizjournals.com ](reports/bizjournals.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ blockchain.info ](reports/blockchain.info.md) | 22 | 0 | 0 | 4 | 18 | [Blockchain](https://hackerone.com/blockchain) |
| [ blog.google ](reports/blog.google.md) | 26 | 0 | 0 | 5 | 21 | Google |
| [ blog.hubspot.com ](reports/blog.hubspot.com.md) | 26 | 0 | 0 | 1 | 25 | [HubSpot](https://bugcrowd.com/hubspot) |
| [ blog.livedoor.jp ](reports/blog.livedoor.jp.md) | 10 | 0 | 1 | 1 | 8 | top-websites gist (no active program match) |
| [ blog.us.playstation.com ](reports/blog.us.playstation.com.md) | 24 | 0 | 0 | 5 | 19 | [Playstation](https://hackerone.com/playstation) |
| [ blogger.com ](reports/blogger.com.md) | 24 | 0 | 0 | 6 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ blogs.adobe.com ](reports/blogs.adobe.com.md) | 6 | 0 | 1 | 1 | 4 | [Adobe](https://hackerone.com/adobe) |
| [ blogs.msdn.com ](reports/blogs.msdn.com.md) | 15 | 0 | 0 | 4 | 11 | top-websites gist (no active program match) |
| [ blogs.scientificamerican.com ](reports/blogs.scientificamerican.com.md) | 18 | 0 | 0 | 1 | 17 | top-websites gist (no active program match) |
| [ blogs.windows.com ](reports/blogs.windows.com.md) | 26 | 0 | 0 | 0 | 26 | top-websites gist (no active program match) |
| [ blogtalkradio.com ](reports/blogtalkradio.com.md) | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| [ bloomberg.com ](reports/bloomberg.com.md) | 18 | 0 | 0 | 2 | 16 | Bloomberg |
| [ bluehost.com ](reports/bluehost.com.md) | 23 | 0 | 0 | 5 | 18 | [Bluehost](https://bugcrowd.com/newfold-bluehostindia-vdp) |
| [ books.google.com ](reports/books.google.com.md) | 22 | 0 | 0 | 3 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ bookstackapp.com ](reports/bookstackapp.com.md) | 20 | 0 | 0 | 4 | 16 | None (open-source project; GitHub issue tracker) |
| [ boredpanda.com ](reports/boredpanda.com.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ breitbart.com ](reports/breitbart.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ britannica.com ](reports/britannica.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ buffer.com ](reports/buffer.com.md) | 32 | 0 | 0 | 5 | 27 | [Buffer](https://buffer.com/legal#security) |
| [ bugs.chromium.org ](reports/bugs.chromium.org.md) | 14 | 0 | 0 | 4 | 10 | top-websites gist (no active program match) |
| [ business.facebook.com ](reports/business.facebook.com.md) | 19 | 0 | 0 | 3 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| [ business.google.com ](reports/business.google.com.md) | 25 | 0 | 0 | 5 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ business.linkedin.com ](reports/business.linkedin.com.md) | 28 | 0 | 0 | 2 | 26 | top-websites gist (no active program match) |
| [ businessinsider.com ](reports/businessinsider.com.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ buymeacoffee.com ](reports/buymeacoffee.com.md) | 26 | 0 | 0 | 3 | 23 | top-websites gist (no active program match) |
| [ buzzfeednews.com ](reports/buzzfeednews.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ buzzsprout.com ](reports/buzzsprout.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ ca.linkedin.com ](reports/ca.linkedin.com.md) | 27 | 0 | 0 | 3 | 24 | top-websites gist (no active program match) |
| [ calendar.google.com ](reports/calendar.google.com.md) | 23 | 0 | 0 | 4 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ calendly.com ](reports/calendly.com.md) | 34 | 0 | 0 | 5 | 29 | top-websites gist (no active program match) |
| [ cambridge.org ](reports/cambridge.org.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ canada.ca ](reports/canada.ca.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ cancerresearchuk.org ](reports/cancerresearchuk.org.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ canva.com ](reports/canva.com.md) | 23 | 0 | 0 | 5 | 18 | [Canva](https://bugcrowd.com/canva) |
| [ cargocollective.com ](reports/cargocollective.com.md) | 27 | 0 | 0 | 7 | 20 | top-websites gist (no active program match) |
| [ cbs.com ](reports/cbs.com.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ cdc.gov ](reports/cdc.gov.md) | 21 | 0 | 0 | 4 | 17 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| [ cdn.shopify.com ](reports/cdn.shopify.com.md) | 26 | 0 | 0 | 3 | 23 | [Shopify](https://hackerone.com/shopify) |
| [ cdnjs.cloudflare.com ](reports/cdnjs.cloudflare.com.md) | 19 | 0 | 0 | 3 | 16 | [Cloudflare](https://hackerone.com/cloudflare) |
| [ cell.com ](reports/cell.com.md) | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| [ census.gov ](reports/census.gov.md) | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| [ chase.com ](reports/chase.com.md) | 18 | 0 | 0 | 5 | 13 | [Chase](https://responsibledisclosure.jpmorganchase.com) |
| [ checkpoint.com ](reports/checkpoint.com.md) | 14 | 0 | 0 | 1 | 13 | [Check Point](https://www.checkpoint.com/white-hat/) |
| [ chicagotribune.com ](reports/chicagotribune.com.md) | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| [ chris.pirillo.com ](reports/chris.pirillo.com.md) | 25 | 0 | 0 | 1 | 24 | top-websites gist (no active program match) |
| [ chrisjdavis.org ](reports/chrisjdavis.org.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ chrome.google.com ](reports/chrome.google.com.md) | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ chronicle.com ](reports/chronicle.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ cisco.com ](reports/cisco.com.md) | 19 | 0 | 0 | 5 | 14 | [Cisco Meraki](https://bugcrowd.com/ciscomeraki) |
| [ click.linksynergy.com ](reports/click.linksynergy.com.md) | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| [ cloud.google.com ](reports/cloud.google.com.md) | 23 | 0 | 0 | 2 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ cloudflare.com ](reports/cloudflare.com.md) | 22 | 0 | 0 | 5 | 17 | [Cloudflare](https://hackerone.com/cloudflare) |
| [ cnbc.com ](reports/cnbc.com.md) | 22 | 0 | 0 | 5 | 17 | Nasdaq |
| [ code.google.com ](reports/code.google.com.md) | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ codecanyon.net ](reports/codecanyon.net.md) | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| [ codepen.io ](reports/codepen.io.md) | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| [ codeproject.com ](reports/codeproject.com.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ codex.wordpress.org ](reports/codex.wordpress.org.md) | 18 | 0 | 0 | 5 | 13 | [WordPress](https://hackerone.com/wordpress) |
| [ coinbase.com ](reports/coinbase.com.md) | 19 | 0 | 0 | 3 | 16 | [Coinbase](https://hackerone.com/coinbase) |
| [ coinmarketcap.com ](reports/coinmarketcap.com.md) | 28 | 0 | 0 | 1 | 27 | top-websites gist (no active program match) |
| [ collegehumor.com ](reports/collegehumor.com.md) | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| [ connect.facebook.net ](reports/connect.facebook.net.md) | 15 | 0 | 0 | 5 | 10 | top-websites gist (no active program match) |
| [ constantcontact.com ](reports/constantcontact.com.md) | 25 | 0 | 0 | 5 | 20 | [Constant Contact](https://bugcrowd.com/constantcontact) |
| [ copyright.gov ](reports/copyright.gov.md) | 23 | 0 | 0 | 1 | 22 | top-websites gist (no active program match) |
| [ coursera.org ](reports/coursera.org.md) | 21 | 0 | 0 | 3 | 18 | [Coursera](https://hackerone.com/coursera) |
| [ createspace.com ](reports/createspace.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ creativecommons.org ](reports/creativecommons.org.md) | 28 | 0 | 0 | 4 | 24 | top-websites gist (no active program match) |
| [ creativemarket.com ](reports/creativemarket.com.md) | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| [ cse.google.com ](reports/cse.google.com.md) | 17 | 0 | 0 | 3 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ css-tricks.com ](reports/css-tricks.com.md) | 31 | 0 | 0 | 4 | 27 | top-websites gist (no active program match) |
| [ ctt.ec ](reports/ctt.ec.md) | 20 | 0 | 0 | 6 | 14 | top-websites gist (no active program match) |
| [ cyber.law.harvard.edu ](reports/cyber.law.harvard.edu.md) | 22 | 0 | 0 | 5 | 17 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| [ dailycaller.com ](reports/dailycaller.com.md) | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| [ dailymotion.com ](reports/dailymotion.com.md) | 22 | 0 | 0 | 4 | 18 | [Dailymotion](https://yeswehack.com/programs/dailymotion-public-bug-bounty) |
| [ dashlane.com ](reports/dashlane.com.md) | 21 | 0 | 0 | 2 | 19 | [Dashlane](https://hackerone.com/dashlane) |
| [ data.worldbank.org ](reports/data.worldbank.org.md) | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| [ de-de.facebook.com ](reports/de-de.facebook.com.md) | 21 | 0 | 0 | 6 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| [ de.linkedin.com ](reports/de.linkedin.com.md) | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| [ deezer.com ](reports/deezer.com.md) | 20 | 0 | 0 | 4 | 16 | [Deezer](https://yeswehack.com/programs/deezer-bug-bounty-program-2019) |
| [ denverpost.com ](reports/denverpost.com.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ design.google ](reports/design.google.md) | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| [ desktop.github.com ](reports/desktop.github.com.md) | 17 | 0 | 0 | 4 | 13 | [GitHub](https://hackerone.com/github) |
| [ developer.android.com ](reports/developer.android.com.md) | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| [ developer.apple.com ](reports/developer.apple.com.md) | 22 | 0 | 0 | 1 | 21 | [Apple](https://security.apple.com) |
| [ developer.chrome.com ](reports/developer.chrome.com.md) | 21 | 0 | 0 | 1 | 20 | top-websites gist (no active program match) |
| [ developers.facebook.com ](reports/developers.facebook.com.md) | 15 | 0 | 0 | 3 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| [ developers.google.com ](reports/developers.google.com.md) | 23 | 0 | 0 | 2 | 21 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ digitalocean.com ](reports/digitalocean.com.md) | 22 | 0 | 0 | 4 | 18 | [DigitalOcean](https://hackerone.com/digitalocean) |
| [ digitaltrends.com ](reports/digitaltrends.com.md) | 29 | 0 | 0 | 4 | 25 | top-websites gist (no active program match) |
| [ diigo.com ](reports/diigo.com.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ discordapp.com ](reports/discordapp.com.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ disqus.com ](reports/disqus.com.md) | 28 | 0 | 0 | 5 | 23 | top-websites gist (no active program match) |
| [ dl.dropbox.com ](reports/dl.dropbox.com.md) | 15 | 0 | 0 | 3 | 12 | [DropBox](https://bugcrowd.com/dropbox) |
| [ dl.dropboxusercontent.com ](reports/dl.dropboxusercontent.com.md) | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| [ docker.com ](reports/docker.com.md) | 19 | 0 | 0 | 4 | 15 | Docker |
| [ docs.google.com ](reports/docs.google.com.md) | 22 | 0 | 0 | 4 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ docs.microsoft.com ](reports/docs.microsoft.com.md) | 19 | 0 | 0 | 3 | 16 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ download.macromedia.com ](reports/download.macromedia.com.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ download.microsoft.com ](reports/download.microsoft.com.md) | 19 | 0 | 0 | 5 | 14 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ dribbble.com ](reports/dribbble.com.md) | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| [ drift.com ](reports/drift.com.md) | 21 | 0 | 0 | 6 | 15 | top-websites gist (no active program match) |
| [ drive.google.com ](reports/drive.google.com.md) | 23 | 0 | 0 | 5 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ dropbox.com ](reports/dropbox.com.md) | 22 | 0 | 0 | 5 | 17 | [DropBox](https://bugcrowd.com/dropbox) |
| [ drupal.org ](reports/drupal.org.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ dw.com ](reports/dw.com.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ dx.doi.org ](reports/dx.doi.org.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ ea.com ](reports/ea.com.md) | 28 | 0 | 0 | 6 | 22 | top-websites gist (no active program match) |
| [ earth.google.com ](reports/earth.google.com.md) | 20 | 0 | 0 | 3 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ ec.europa.eu ](reports/ec.europa.eu.md) | 22 | 0 | 0 | 5 | 17 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| [ economictimes.indiatimes.com ](reports/economictimes.indiatimes.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ economist.com ](reports/economist.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ edx.org ](reports/edx.org.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ eepurl.com ](reports/eepurl.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ eff.org ](reports/eff.org.md) | 19 | 0 | 0 | 3 | 16 | [EFF](https://www.eff.org/security/) |
| [ elmundo.es ](reports/elmundo.es.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ en-gb.facebook.com ](reports/en-gb.facebook.com.md) | 21 | 0 | 0 | 6 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| [ en.advertisercommunity.com ](reports/en.advertisercommunity.com.md) | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| [ en.wikipedia.org ](reports/en.wikipedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ engadget.com ](reports/engadget.com.md) | 23 | 0 | 0 | 4 | 19 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| [ envato.com ](reports/envato.com.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ eonline.com ](reports/eonline.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ epa.gov ](reports/epa.gov.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ es.wikipedia.org ](reports/es.wikipedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ espn.com ](reports/espn.com.md) | 26 | 0 | 0 | 5 | 21 | [The Walt Disney Company](https://hackerone.com/disney) |
| [ etsy.com ](reports/etsy.com.md) | 25 | 0 | 0 | 8 | 17 | [Etsy](https://bugcrowd.com/etsy) |
| [ eur-lex.europa.eu ](reports/eur-lex.europa.eu.md) | 6 | 0 | 0 | 0 | 6 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| [ europa.eu ](reports/europa.eu.md) | 20 | 0 | 0 | 5 | 15 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| [ europarl.europa.eu ](reports/europarl.europa.eu.md) | 21 | 0 | 0 | 4 | 17 | [European Central Bank](https://www.ecb.europa.eu/services/responsible-disclosure/html/index.nl.html) |
| [ event.on24.com ](reports/event.on24.com.md) | 13 | 0 | 0 | 1 | 12 | top-websites gist (no active program match) |
| [ eventbrite.com ](reports/eventbrite.com.md) | 23 | 0 | 0 | 5 | 18 | [Eventbrite](https://www.eventbrite.com/security/) |
| [ eventim.de ](reports/eventim.de.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ events.google.com ](reports/events.google.com.md) | 15 | 0 | 0 | 3 | 12 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ evernote.com ](reports/evernote.com.md) | 27 | 0 | 0 | 4 | 23 | [Evernote](https://hackerone.com/evernote) |
| [ expedia.com ](reports/expedia.com.md) | 19 | 0 | 0 | 4 | 15 | [Expedia Group](https://hackerone.com/expediagroup) |
| [ faa.gov ](reports/faa.gov.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ facebook.com ](reports/facebook.com.md) | 21 | 0 | 0 | 7 | 14 | [Facebook](https://www.facebook.com/whitehat) |
| [ families.google.com ](reports/families.google.com.md) | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ fastcompany.com ](reports/fastcompany.com.md) | 21 | 0 | 0 | 2 | 19 | top-websites gist (no active program match) |
| [ fb.com ](reports/fb.com.md) | 22 | 0 | 0 | 4 | 18 | [Facebook](https://www.facebook.com/whitehat) |
| [ fb.me ](reports/fb.me.md) | 18 | 0 | 0 | 3 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| [ fbi.gov ](reports/fbi.gov.md) | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| [ feeds.feedburner.com ](reports/feeds.feedburner.com.md) | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| [ filezilla-project.org ](reports/filezilla-project.org.md) | 18 | 0 | 1 | 4 | 13 | [FileZilla](https://hackerone.com/filezilla) |
| [ finance.yahoo.com ](reports/finance.yahoo.com.md) | 23 | 0 | 0 | 3 | 20 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| [ firstdata.com ](reports/firstdata.com.md) | 16 | 0 | 0 | 1 | 15 | top-websites gist (no active program match) |
| [ fiverr.com ](reports/fiverr.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ flavors.me ](reports/flavors.me.md) | 2 | 0 | 0 | 0 | 2 | top-websites gist (no active program match) |
| [ flic.kr ](reports/flic.kr.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ flickr.com ](reports/flickr.com.md) | 24 | 0 | 0 | 3 | 21 | [Flickr](https://hackerone.com/flickr) |
| [ flipboard.com ](reports/flipboard.com.md) | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| [ flow.microsoft.com ](reports/flow.microsoft.com.md) | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ fonts.google.com ](reports/fonts.google.com.md) | 19 | 0 | 0 | 2 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ fonts.googleapis.com ](reports/fonts.googleapis.com.md) | 15 | 0 | 0 | 3 | 12 | top-websites gist (no active program match) |
| [ forbes.com ](reports/forbes.com.md) | 20 | 0 | 0 | 3 | 17 | Forbes |
| [ forms.gle ](reports/forms.gle.md) | 17 | 0 | 0 | 4 | 13 | Google |
| [ forms.office.com ](reports/forms.office.com.md) | 17 | 0 | 0 | 5 | 12 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ foxnews.com ](reports/foxnews.com.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ fr.wikipedia.org ](reports/fr.wikipedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ france24.com ](reports/france24.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ franchising.com ](reports/franchising.com.md) | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| [ freelancer.com ](reports/freelancer.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ freewebs.com ](reports/freewebs.com.md) | 26 | 0 | 0 | 7 | 19 | top-websites gist (no active program match) |
| [ ftc.gov ](reports/ftc.gov.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ funnyordie.com ](reports/funnyordie.com.md) | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| [ g.co ](reports/g.co.md) | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| [ g.page ](reports/g.page.md) | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| [ g1.globo.com ](reports/g1.globo.com.md) | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| [ gartner.com ](reports/gartner.com.md) | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| [ geni.us ](reports/geni.us.md) | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| [ get.adobe.com ](reports/get.adobe.com.md) | 15 | 0 | 0 | 5 | 10 | [Adobe](https://hackerone.com/adobe) |
| [ get.google.com ](reports/get.google.com.md) | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ getpocket.com ](reports/getpocket.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ getresponse.com ](reports/getresponse.com.md) | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| [ giphy.com ](reports/giphy.com.md) | 26 | 0 | 0 | 4 | 22 | top-websites gist (no active program match) |
| [ gist.github.com ](reports/gist.github.com.md) | 18 | 0 | 0 | 3 | 15 | [GitHub](https://hackerone.com/github) |
| [ github.com ](reports/github.com.md) | 21 | 0 | 0 | 2 | 19 | [GitHub](https://hackerone.com/github) |
| [ gitlab.com ](reports/gitlab.com.md) | 40 | 0 | 9 | 2 | 29 | [GitLab](https://hackerone.com/gitlab) |
| [ gitter.im ](reports/gitter.im.md) | 19 | 0 | 0 | 5 | 14 | [GitLab](https://hackerone.com/gitlab) |
| [ gleam.io ](reports/gleam.io.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ globalnews.ca ](reports/globalnews.ca.md) | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| [ gmpg.org ](reports/gmpg.org.md) | 6 | 0 | 0 | 1 | 5 | top-websites gist (no active program match) |
| [ gofundme.com ](reports/gofundme.com.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ golang.org ](reports/golang.org.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ goo.gle ](reports/goo.gle.md) | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| [ google-analytics.com ](reports/google-analytics.com.md) | 19 | 0 | 0 | 4 | 15 | Google |
| [ google.be ](reports/google.be.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ google.ca ](reports/google.ca.md) | 22 | 0 | 0 | 4 | 18 | Google |
| [ google.co.uk ](reports/google.co.uk.md) | 22 | 0 | 0 | 4 | 18 | Google |
| [ google.co.za ](reports/google.co.za.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ google.com ](reports/google.com.md) | 23 | 0 | 0 | 5 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ google.com.br ](reports/google.com.br.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ google.de ](reports/google.de.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ google.it ](reports/google.it.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ google.nl ](reports/google.nl.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ google.se ](reports/google.se.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ googleadservices.com ](reports/googleadservices.com.md) | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| [ googletagmanager.com ](reports/googletagmanager.com.md) | 17 | 0 | 0 | 4 | 13 | Google |
| [ googlewebmastercentral.blogspot.com ](reports/googlewebmastercentral.blogspot.com.md) | 18 | 0 | 0 | 2 | 16 | top-websites gist (no active program match) |
| [ gov.uk ](reports/gov.uk.md) | 18 | 0 | 0 | 4 | 14 | [NCSC UK](https://hackerone.com/ncsc_uk) |
| [ greenpeace.org ](reports/greenpeace.org.md) | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| [ groups.google.com ](reports/groups.google.com.md) | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ gsuite.google.com ](reports/gsuite.google.com.md) | 21 | 0 | 0 | 4 | 17 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ gumroad.com ](reports/gumroad.com.md) | 36 | 0 | 0 | 7 | 29 | top-websites gist (no active program match) |
| [ hangouts.google.com ](reports/hangouts.google.com.md) | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ hbo.com ](reports/hbo.com.md) | 26 | 0 | 0 | 7 | 19 | top-websites gist (no active program match) |
| [ hbr.org ](reports/hbr.org.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ health.com ](reports/health.com.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ health.harvard.edu ](reports/health.harvard.edu.md) | 21 | 0 | 0 | 4 | 17 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| [ healthline.com ](reports/healthline.com.md) | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| [ heise.de ](reports/heise.de.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ help.apple.com ](reports/help.apple.com.md) | 19 | 0 | 0 | 1 | 18 | [Apple](https://security.apple.com) |
| [ helpx.adobe.com ](reports/helpx.adobe.com.md) | 20 | 0 | 0 | 4 | 16 | [Adobe](https://hackerone.com/adobe) |
| [ hkrsa.asia ](reports/hkrsa.asia.md) | 41 | 0 | 2 | 5 | 34 | top-websites gist (no active program match) |
| [ homedepot.com ](reports/homedepot.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ hostgator.com ](reports/hostgator.com.md) | 26 | 0 | 0 | 6 | 20 | [Host Gator](https://bugcrowd.com/hostgator) |
| [ hostinger.com ](reports/hostinger.com.md) | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| [ hp.com ](reports/hp.com.md) | 18 | 0 | 0 | 3 | 15 | top-websites gist (no active program match) |
| [ humblebundle.com ](reports/humblebundle.com.md) | 23 | 0 | 0 | 4 | 19 | [Humble Bundle](https://bugcrowd.com/humblebundle) |
| [ i.imgur.com ](reports/i.imgur.com.md) | 23 | 0 | 0 | 5 | 18 | [Imgur](https://hackerone.com/imgur) |
| [ i.redd.it ](reports/i.redd.it.md) | 18 | 0 | 0 | 4 | 14 | [Reddit](https://hackerone.com/reddit) |
| [ i0.wp.com ](reports/i0.wp.com.md) | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| [ i2.wp.com ](reports/i2.wp.com.md) | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| [ ibm.com ](reports/ibm.com.md) | 22 | 0 | 0 | 6 | 16 | [IBM](https://hackerone.com/ibm) |
| [ iconfinder.com ](reports/iconfinder.com.md) | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| [ idealo.de ](reports/idealo.de.md) | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| [ ietf.org ](reports/ietf.org.md) | 27 | 0 | 0 | 5 | 22 | IETF |
| [ ifttt.com ](reports/ifttt.com.md) | 28 | 0 | 0 | 0 | 28 | top-websites gist (no active program match) |
| [ ikea.com ](reports/ikea.com.md) | 20 | 0 | 0 | 6 | 14 | [IKEA](https://bugs.ikea.com/) |
| [ imdb.com ](reports/imdb.com.md) | 20 | 0 | 0 | 3 | 17 | [IMDB](https://help.imdb.com/article/imdb/general-information/how-to-report-security-issues-and-vulnerabilities/G99J5YVB8SBBMJ73?ref_=helpart_nav_14#) |
| [ img.youtube.com ](reports/img.youtube.com.md) | 17 | 0 | 0 | 3 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ imgur.com ](reports/imgur.com.md) | 33 | 0 | 0 | 5 | 28 | [Imgur](https://hackerone.com/imgur) |
| [ in.linkedin.com ](reports/in.linkedin.com.md) | 28 | 0 | 0 | 3 | 25 | top-websites gist (no active program match) |
| [ inc.com ](reports/inc.com.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ indiewire.com ](reports/indiewire.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ infusionsoft.com ](reports/infusionsoft.com.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ inkscape.org ](reports/inkscape.org.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ instagram.com ](reports/instagram.com.md) | 17 | 0 | 0 | 4 | 13 | [Facebook](https://www.facebook.com/whitehat) |
| [ institutvajrayogini.fr ](reports/institutvajrayogini.fr.md) | 25 | 0 | 1 | 4 | 20 | top-websites gist (no active program match) |
| [ instructables.com ](reports/instructables.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ intel.com ](reports/intel.com.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ irs.gov ](reports/irs.gov.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ is.gd ](reports/is.gd.md) | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| [ issuu.com ](reports/issuu.com.md) | 20 | 0 | 0 | 3 | 17 | [Issuu](https://issuu.com/responsible-disclosure) |
| [ istockphoto.com ](reports/istockphoto.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ it.linkedin.com ](reports/it.linkedin.com.md) | 26 | 0 | 0 | 3 | 23 | top-websites gist (no active program match) |
| [ itunes.apple.com ](reports/itunes.apple.com.md) | 23 | 0 | 0 | 3 | 20 | [Apple](https://security.apple.com) |
| [ j.mp ](reports/j.mp.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ ja-jp.facebook.com ](reports/ja-jp.facebook.com.md) | 21 | 0 | 0 | 6 | 15 | [Facebook](https://www.facebook.com/whitehat) |
| [ ja.wikipedia.org ](reports/ja.wikipedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ japantimes.co.jp ](reports/japantimes.co.jp.md) | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| [ jetbrains.com ](reports/jetbrains.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ join.slack.com ](reports/join.slack.com.md) | 25 | 0 | 0 | 6 | 19 | [Slack](https://hackerone.com/slack) |
| [ journals.sagepub.com ](reports/journals.sagepub.com.md) | 23 | 0 | 0 | 3 | 20 | top-websites gist (no active program match) |
| [ jstor.org ](reports/jstor.org.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ justgiving.com ](reports/justgiving.com.md) | 24 | 0 | 0 | 1 | 23 | top-websites gist (no active program match) |
| [ keep.google.com ](reports/keep.google.com.md) | 20 | 0 | 0 | 4 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ khanacademy.org ](reports/khanacademy.org.md) | 20 | 0 | 0 | 5 | 15 | [Khan Academy](https://hackerone.com/khanacademy) |
| [ kiva.org ](reports/kiva.org.md) | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| [ kobo.com ](reports/kobo.com.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ kraken.com ](reports/kraken.com.md) | 19 | 0 | 0 | 3 | 16 | [Kraken](https://www.kraken.com/en-us/features/security/bug-bounty) |
| [ l.facebook.com ](reports/l.facebook.com.md) | 17 | 0 | 0 | 6 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| [ laughingsquid.com ](reports/laughingsquid.com.md) | 27 | 0 | 0 | 4 | 23 | top-websites gist (no active program match) |
| [ launchpad.net ](reports/launchpad.net.md) | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| [ lemonde.fr ](reports/lemonde.fr.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ lenovo.com ](reports/lenovo.com.md) | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| [ lh3.googleusercontent.com ](reports/lh3.googleusercontent.com.md) | 19 | 0 | 0 | 4 | 15 | Google |
| [ lh4.googleusercontent.com ](reports/lh4.googleusercontent.com.md) | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| [ lh5.ggpht.com ](reports/lh5.ggpht.com.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ lifehack.org ](reports/lifehack.org.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ line.me ](reports/line.me.md) | 22 | 0 | 0 | 4 | 18 | [LINE](https://hackerone.com/line) |
| [ link.springer.com ](reports/link.springer.com.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ linkedin.com ](reports/linkedin.com.md) | 32 | 0 | 0 | 6 | 26 | top-websites gist (no active program match) |
| [ linktr.ee ](reports/linktr.ee.md) | 20 | 0 | 0 | 1 | 19 | top-websites gist (no active program match) |
| [ livestream.com ](reports/livestream.com.md) | 23 | 0 | 0 | 5 | 18 | [Livestream](https://hackerone.com/livestream) |
| [ lmgtfy.com ](reports/lmgtfy.com.md) | 32 | 0 | 0 | 5 | 27 | top-websites gist (no active program match) |
| [ login.microsoftonline.com ](reports/login.microsoftonline.com.md) | 14 | 0 | 0 | 3 | 11 | top-websites gist (no active program match) |
| [ logitech.com ](reports/logitech.com.md) | 26 | 0 | 0 | 5 | 21 | [Logitech](https://hackerone.com/logitech) |
| [ lulu.com ](reports/lulu.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ lynda.com ](reports/lynda.com.md) | 25 | 0 | 0 | 7 | 18 | top-websites gist (no active program match) |
| [ m.facebook.com ](reports/m.facebook.com.md) | 18 | 0 | 0 | 6 | 12 | [Facebook](https://www.facebook.com/whitehat) |
| [ m.me ](reports/m.me.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ m.youtube.com ](reports/m.youtube.com.md) | 22 | 0 | 0 | 4 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ mail.google.com ](reports/mail.google.com.md) | 16 | 0 | 0 | 1 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ mailchimp.com ](reports/mailchimp.com.md) | 21 | 0 | 0 | 5 | 16 | [Intuit](https://hackerone.com/intuit_rdp) |
| [ makeuseof.com ](reports/makeuseof.com.md) | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| [ maps.google.co.jp ](reports/maps.google.co.jp.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ maps.google.co.nz ](reports/maps.google.co.nz.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ maps.google.com ](reports/maps.google.com.md) | 20 | 0 | 0 | 4 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ maps.googleapis.com ](reports/maps.googleapis.com.md) | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| [ maps.gstatic.com ](reports/maps.gstatic.com.md) | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| [ market.android.com ](reports/market.android.com.md) | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| [ marketingplatform.google.com ](reports/marketingplatform.google.com.md) | 18 | 0 | 0 | 3 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ marketwatch.com ](reports/marketwatch.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ marriott.com ](reports/marriott.com.md) | 23 | 0 | 0 | 6 | 17 | [Marriott](https://hackerone.com/marriott) |
| [ mashable.com ](reports/mashable.com.md) | 30 | 0 | 0 | 4 | 26 | top-websites gist (no active program match) |
| [ medium.com ](reports/medium.com.md) | 28 | 0 | 0 | 4 | 24 | top-websites gist (no active program match) |
| [ meet.google.com ](reports/meet.google.com.md) | 16 | 0 | 0 | 2 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ meetup.com ](reports/meetup.com.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ mega.nz ](reports/mega.nz.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ mentalfloss.com ](reports/mentalfloss.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ messenger.com ](reports/messenger.com.md) | 19 | 0 | 0 | 8 | 11 | [Facebook](https://www.facebook.com/whitehat) |
| [ meta.wikimedia.org ](reports/meta.wikimedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ metmuseum.org ](reports/metmuseum.org.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ microsoft.com ](reports/microsoft.com.md) | 21 | 0 | 0 | 7 | 14 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ mixcloud.com ](reports/mixcloud.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ mlb.com ](reports/mlb.com.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ mobile.twitter.com ](reports/mobile.twitter.com.md) | 22 | 0 | 0 | 3 | 19 | [Twitter](https://hackerone.com/twitter) |
| [ moma.org ](reports/moma.org.md) | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| [ money.yandex.ru ](reports/money.yandex.ru.md) | 4 | 0 | 0 | 2 | 2 | [Yandex](https://yandex.com/bugbounty/index) |
| [ monster.com ](reports/monster.com.md) | 12 | 0 | 0 | 1 | 11 | top-websites gist (no active program match) |
| [ moz.com ](reports/moz.com.md) | 28 | 0 | 0 | 3 | 25 | top-websites gist (no active program match) |
| [ mp.weixin.qq.com ](reports/mp.weixin.qq.com.md) | 24 | 0 | 0 | 5 | 19 | [Tencent](https://en.security.tencent.com) |
| [ msdn.microsoft.com ](reports/msdn.microsoft.com.md) | 15 | 0 | 0 | 4 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ msn.com ](reports/msn.com.md) | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| [ music.apple.com ](reports/music.apple.com.md) | 27 | 0 | 0 | 2 | 25 | [Apple](https://security.apple.com) |
| [ myaccount.google.com ](reports/myaccount.google.com.md) | 17 | 0 | 0 | 2 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ myfitnesspal.com ](reports/myfitnesspal.com.md) | 26 | 0 | 0 | 6 | 20 | [UNDER ARMOUR](https://bugcrowd.com/underarmour) |
| [ myspace.com ](reports/myspace.com.md) | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| [ nasa.gov ](reports/nasa.gov.md) | 17 | 0 | 0 | 3 | 14 | [Nasa VDP](https://bugcrowd.com/engagements/nasa-vdp) |
| [ nature.com ](reports/nature.com.md) | 28 | 0 | 0 | 8 | 20 | top-websites gist (no active program match) |
| [ ncbi.nlm.nih.gov ](reports/ncbi.nlm.nih.gov.md) | 25 | 0 | 0 | 2 | 23 | [U.S. Dept of Health & Human Services (HHS)](https://www.hhs.gov/vulnerability-disclosure-policy/index.html) |
| [ neilpatel.com ](reports/neilpatel.com.md) | 28 | 0 | 0 | 2 | 26 | top-websites gist (no active program match) |
| [ nejm.org ](reports/nejm.org.md) | 26 | 0 | 0 | 7 | 19 | top-websites gist (no active program match) |
| [ netbeans.org ](reports/netbeans.org.md) | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| [ netflix.com ](reports/netflix.com.md) | 21 | 0 | 0 | 4 | 17 | [Netflix](https://bugcrowd.com/netflix) |
| [ networkadvertising.org ](reports/networkadvertising.org.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ newegg.com ](reports/newegg.com.md) | 21 | 0 | 0 | 4 | 17 | [Newegg](https://hackerone.com/newegg) |
| [ news.google.com ](reports/news.google.com.md) | 18 | 0 | 0 | 2 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ news.harvard.edu ](reports/news.harvard.edu.md) | 13 | 0 | 0 | 2 | 11 | [Harvard](https://huit.harvard.edu/responsible-vulnerability-reporting-standards#inscope) |
| [ news.mit.edu ](reports/news.mit.edu.md) | 22 | 0 | 0 | 3 | 19 | top-websites gist (no active program match) |
| [ news.yahoo.com ](reports/news.yahoo.com.md) | 18 | 0 | 0 | 5 | 13 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| [ note.mu ](reports/note.mu.md) | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| [ notion.so ](reports/notion.so.md) | 40 | 0 | 9 | 2 | 29 | top-websites gist (no active program match) |
| [ nvidia.com ](reports/nvidia.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ nydailynews.com ](reports/nydailynews.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ nypost.com ](reports/nypost.com.md) | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| [ nytimes.com ](reports/nytimes.com.md) | 23 | 0 | 0 | 3 | 20 | The New York Times |
| [ oecd.org ](reports/oecd.org.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ ok.ru ](reports/ok.ru.md) | 33 | 0 | 0 | 5 | 28 | top-websites gist (no active program match) |
| [ online.wsj.com ](reports/online.wsj.com.md) | 19 | 0 | 0 | 4 | 15 | top-websites gist (no active program match) |
| [ open.spotify.com ](reports/open.spotify.com.md) | 21 | 0 | 0 | 3 | 18 | [Spotify](https://hackerone.com/spotify) |
| [ opera.com ](reports/opera.com.md) | 20 | 0 | 0 | 4 | 16 | [Opera Public Bug Bounty](https://bugcrowd.com/opera) |
| [ opinionator.blogs.nytimes.com ](reports/opinionator.blogs.nytimes.com.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ oracle.com ](reports/oracle.com.md) | 18 | 0 | 0 | 5 | 13 | top-websites gist (no active program match) |
| [ otto.de ](reports/otto.de.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ ouest-france.fr ](reports/ouest-france.fr.md) | 7 | 0 | 0 | 3 | 4 | top-websites gist (no active program match) |
| [ overcast.fm ](reports/overcast.fm.md) | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| [ ow.ly ](reports/ow.ly.md) | 14 | 0 | 0 | 2 | 12 | [Hootsuite](https://www.hootsuite.com/security) |
| [ pandora.com ](reports/pandora.com.md) | 28 | 0 | 0 | 5 | 23 | top-websites gist (no active program match) |
| [ patents.google.com ](reports/patents.google.com.md) | 13 | 0 | 0 | 2 | 11 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ paypal.com ](reports/paypal.com.md) | 22 | 0 | 0 | 8 | 14 | [PayPal](https://hackerone.com/paypal) |
| [ paypal.me ](reports/paypal.me.md) | 22 | 0 | 0 | 4 | 18 | [PayPal](https://hackerone.com/paypal) |
| [ pbs.twimg.com ](reports/pbs.twimg.com.md) | 14 | 0 | 0 | 2 | 12 | [Twitter](https://hackerone.com/twitter) |
| [ pcworld.com ](reports/pcworld.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ penguinrandomhouse.com ](reports/penguinrandomhouse.com.md) | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| [ periscope.tv ](reports/periscope.tv.md) | 20 | 0 | 0 | 4 | 16 | [Twitter](https://hackerone.com/twitter) |
| [ pewresearch.org ](reports/pewresearch.org.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ pexels.com ](reports/pexels.com.md) | 22 | 0 | 0 | 4 | 18 | [Pexels](https://bugcrowd.com/pexels) |
| [ photos.app.goo.gl ](reports/photos.app.goo.gl.md) | 17 | 0 | 0 | 3 | 14 | top-websites gist (no active program match) |
| [ photos.google.com ](reports/photos.google.com.md) | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ php.net ](reports/php.net.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ picasaweb.google.com ](reports/picasaweb.google.com.md) | 20 | 0 | 0 | 5 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ pinterest.co.uk ](reports/pinterest.co.uk.md) | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| [ pinterest.com ](reports/pinterest.com.md) | 16 | 0 | 0 | 4 | 12 | [Pinterest](https://bugcrowd.com/pinterest) |
| [ pipes.yahoo.com ](reports/pipes.yahoo.com.md) | 1 | 0 | 0 | 0 | 1 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| [ pitchfork.com ](reports/pitchfork.com.md) | 26 | 0 | 0 | 2 | 24 | top-websites gist (no active program match) |
| [ pixabay.com ](reports/pixabay.com.md) | 24 | 0 | 0 | 2 | 22 | [Pixabay](https://bugcrowd.com/pixabay) |
| [ pixiv.net ](reports/pixiv.net.md) | 21 | 0 | 0 | 4 | 17 | [Pixiv](https://hackerone.com/pixiv) |
| [ pixlr.com ](reports/pixlr.com.md) | 32 | 0 | 0 | 4 | 28 | top-websites gist (no active program match) |
| [ pl.wikipedia.org ](reports/pl.wikipedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ platform.twitter.com ](reports/platform.twitter.com.md) | 15 | 0 | 0 | 4 | 11 | [Twitter](https://hackerone.com/twitter) |
| [ play.google.com ](reports/play.google.com.md) | 23 | 0 | 0 | 4 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ player.vimeo.com ](reports/player.vimeo.com.md) | 20 | 0 | 0 | 1 | 19 | [Vimeo](https://hackerone.com/vimeo) |
| [ plaza.rakuten.co.jp ](reports/plaza.rakuten.co.jp.md) | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| [ plus.google.com ](reports/plus.google.com.md) | 22 | 0 | 0 | 6 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ podcasts.apple.com ](reports/podcasts.apple.com.md) | 22 | 0 | 0 | 2 | 20 | [Apple](https://security.apple.com) |
| [ podcasts.google.com ](reports/podcasts.google.com.md) | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ poetryfoundation.org ](reports/poetryfoundation.org.md) | 25 | 0 | 0 | 4 | 21 | top-websites gist (no active program match) |
| [ policies.google.com ](reports/policies.google.com.md) | 24 | 0 | 0 | 5 | 19 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ pond5.com ](reports/pond5.com.md) | 30 | 0 | 0 | 7 | 23 | top-websites gist (no active program match) |
| [ popularmechanics.com ](reports/popularmechanics.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ postmates.com ](reports/postmates.com.md) | 34 | 0 | 0 | 4 | 30 | [Postmates](https://hackerone.com/postmates) |
| [ privacy.microsoft.com ](reports/privacy.microsoft.com.md) | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ prnewswire.com ](reports/prnewswire.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ prnt.sc ](reports/prnt.sc.md) | 28 | 0 | 0 | 6 | 22 | top-websites gist (no active program match) |
| [ productforums.google.com ](reports/productforums.google.com.md) | 18 | 0 | 0 | 5 | 13 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ producthunt.com ](reports/producthunt.com.md) | 25 | 0 | 0 | 2 | 23 | top-websites gist (no active program match) |
| [ profiles.google.com ](reports/profiles.google.com.md) | 24 | 0 | 0 | 8 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ psychologytoday.com ](reports/psychologytoday.com.md) | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| [ pt.slideshare.net ](reports/pt.slideshare.net.md) | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| [ purl.org ](reports/purl.org.md) | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| [ puu.sh ](reports/puu.sh.md) | 16 | 0 | 0 | 4 | 12 | top-websites gist (no active program match) |
| [ python.org ](reports/python.org.md) | 24 | 0 | 0 | 4 | 20 | PSF |
| [ quora.com ](reports/quora.com.md) | 22 | 0 | 0 | 5 | 17 | [Quora](https://hackerone.com/quora) |
| [ ranker.com ](reports/ranker.com.md) | 22 | 0 | 0 | 6 | 16 | top-websites gist (no active program match) |
| [ ravelry.com ](reports/ravelry.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ raw.githubusercontent.com ](reports/raw.githubusercontent.com.md) | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| [ reacts.ru ](reports/reacts.ru.md) | 16 | 0 | 3 | 2 | 11 | top-websites gist (no active program match) |
| [ realvnc.com ](reports/realvnc.com.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ redbubble.com ](reports/redbubble.com.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ redbull.com ](reports/redbull.com.md) | 19 | 0 | 0 | 4 | 15 | [Redbull](https://app.intigriti.com/programs/redbull/redbull/detail) |
| [ reddit.com ](reports/reddit.com.md) | 19 | 0 | 0 | 2 | 17 | [Reddit](https://hackerone.com/reddit) |
| [ redhat.com ](reports/redhat.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ researchgate.net ](reports/researchgate.net.md) | 22 | 0 | 0 | 4 | 18 | [Research Gate](https://explore.researchgate.net/display/support/Security+and+vulnerability) |
| [ residentadvisor.net ](reports/residentadvisor.net.md) | 23 | 0 | 0 | 2 | 21 | top-websites gist (no active program match) |
| [ reuters.com ](reports/reuters.com.md) | 25 | 0 | 0 | 6 | 19 | Reuters |
| [ reverbnation.com ](reports/reverbnation.com.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ rollingstone.com ](reports/rollingstone.com.md) | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| [ rottentomatoes.com ](reports/rottentomatoes.com.md) | 17 | 0 | 0 | 2 | 15 | top-websites gist (no active program match) |
| [ ru.wikipedia.org ](reports/ru.wikipedia.org.md) | 19 | 0 | 0 | 2 | 17 | top-websites gist (no active program match) |
| [ s-media-cache-ak0.pinimg.com ](reports/s-media-cache-ak0.pinimg.com.md) | 15 | 0 | 0 | 6 | 9 | top-websites gist (no active program match) |
| [ s0.wp.com ](reports/s0.wp.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ salesforce.com ](reports/salesforce.com.md) | 18 | 0 | 0 | 3 | 15 | [Salesforce](https://www.salesforce.com/company/disclosure/) |
| [ samsung.com ](reports/samsung.com.md) | 19 | 0 | 0 | 5 | 14 | [Samsung TV](https://samsungtvbounty.com) |
| [ sciencedaily.com ](reports/sciencedaily.com.md) | 25 | 0 | 0 | 5 | 20 | top-websites gist (no active program match) |
| [ scribd.com ](reports/scribd.com.md) | 19 | 0 | 0 | 3 | 16 | top-websites gist (no active program match) |
| [ search.google.com ](reports/search.google.com.md) | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ secure.gravatar.com ](reports/secure.gravatar.com.md) | 22 | 0 | 0 | 1 | 21 | top-websites gist (no active program match) |
| [ sellfy.com ](reports/sellfy.com.md) | 30 | 0 | 0 | 5 | 25 | top-websites gist (no active program match) |
| [ sendspace.com ](reports/sendspace.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ seroundtable.com ](reports/seroundtable.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ services.google.com ](reports/services.google.com.md) | 19 | 0 | 0 | 4 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ shareasale.com ](reports/shareasale.com.md) | 24 | 0 | 0 | 6 | 18 | top-websites gist (no active program match) |
| [ shopify.com ](reports/shopify.com.md) | 26 | 0 | 0 | 5 | 21 | [Shopify](https://hackerone.com/shopify) |
| [ shutterstock.com ](reports/shutterstock.com.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ sites.google.com ](reports/sites.google.com.md) | 19 | 0 | 0 | 3 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ sketchfab.com ](reports/sketchfab.com.md) | 20 | 0 | 0 | 4 | 16 | [Epic Games](https://hackerone.com/epicgames) |
| [ skfb.ly ](reports/skfb.ly.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ skillshare.com ](reports/skillshare.com.md) | 25 | 0 | 0 | 3 | 22 | top-websites gist (no active program match) |
| [ skype.com ](reports/skype.com.md) | 19 | 0 | 0 | 4 | 15 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ slack.com ](reports/slack.com.md) | 27 | 0 | 0 | 4 | 23 | [Slack](https://hackerone.com/slack) |
| [ slashgear.com ](reports/slashgear.com.md) | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| [ slate.com ](reports/slate.com.md) | 22 | 0 | 0 | 2 | 20 | top-websites gist (no active program match) |
| [ slideshare.net ](reports/slideshare.net.md) | 26 | 0 | 0 | 6 | 20 | top-websites gist (no active program match) |
| [ smashingmagazine.com ](reports/smashingmagazine.com.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ smile.amazon.com ](reports/smile.amazon.com.md) | 21 | 0 | 0 | 5 | 16 | [Amazon](https://hackerone.com/amazonvrp) |
| [ smugmug.com ](reports/smugmug.com.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ snapchat.com ](reports/snapchat.com.md) | 23 | 0 | 0 | 5 | 18 | [Snapchat](https://hackerone.com/snapchat) |
| [ snip.ly ](reports/snip.ly.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ socialmediatoday.com ](reports/socialmediatoday.com.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ sophos.com ](reports/sophos.com.md) | 17 | 0 | 0 | 5 | 12 | [Sophos](https://bugcrowd.com/sophos) |
| [ soundcloud.com ](reports/soundcloud.com.md) | 31 | 0 | 0 | 5 | 26 | [SoundCloud](https://bugcrowd.com/soundcloud) |
| [ sourceforge.net ](reports/sourceforge.net.md) | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| [ space.com ](reports/space.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ speakerdeck.com ](reports/speakerdeck.com.md) | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| [ spiegel.de ](reports/spiegel.de.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ spotify.com ](reports/spotify.com.md) | 25 | 0 | 0 | 3 | 22 | [Spotify](https://hackerone.com/spotify) |
| [ sproutsocial.com ](reports/sproutsocial.com.md) | 23 | 0 | 0 | 1 | 22 | [Sprout Social](https://bugcrowd.com/sproutsocial) |
| [ squareup.com ](reports/squareup.com.md) | 25 | 0 | 0 | 3 | 22 | [Square](https://bugcrowd.com/square) |
| [ stackoverflow.com ](reports/stackoverflow.com.md) | 24 | 0 | 0 | 3 | 21 | top-websites gist (no active program match) |
| [ startnext.com ](reports/startnext.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ starwars.com ](reports/starwars.com.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ stats.g.doubleclick.net ](reports/stats.g.doubleclick.net.md) | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| [ stats.wp.com ](reports/stats.wp.com.md) | 19 | 0 | 0 | 6 | 13 | top-websites gist (no active program match) |
| [ steamcommunity.com ](reports/steamcommunity.com.md) | 19 | 0 | 0 | 4 | 15 | [Valve Software](https://hackerone.com/valve) |
| [ stock.adobe.com ](reports/stock.adobe.com.md) | 20 | 0 | 0 | 4 | 16 | [Adobe](https://hackerone.com/adobe) |
| [ storage.googleapis.com ](reports/storage.googleapis.com.md) | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| [ store.google.com ](reports/store.google.com.md) | 20 | 0 | 0 | 2 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ store.steampowered.com ](reports/store.steampowered.com.md) | 16 | 0 | 0 | 4 | 12 | [Valve Software](https://hackerone.com/valve) |
| [ strava.com ](reports/strava.com.md) | 24 | 1 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ stripe.com ](reports/stripe.com.md) | 20 | 0 | 0 | 1 | 19 | [Stripe](https://hackerone.com/stripe) |
| [ sublimetext.com ](reports/sublimetext.com.md) | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| [ support.apple.com ](reports/support.apple.com.md) | 19 | 0 | 0 | 2 | 17 | [Apple](https://security.apple.com) |
| [ support.cloudflare.com ](reports/support.cloudflare.com.md) | 20 | 0 | 0 | 5 | 15 | [Cloudflare](https://hackerone.com/cloudflare) |
| [ support.google.com ](reports/support.google.com.md) | 22 | 0 | 0 | 2 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ support.microsoft.com ](reports/support.microsoft.com.md) | 12 | 0 | 0 | 2 | 10 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ support.office.com ](reports/support.office.com.md) | 14 | 0 | 0 | 5 | 9 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ surveymonkey.com ](reports/surveymonkey.com.md) | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| [ sutterhealth.org ](reports/sutterhealth.org.md) | 16 | 0 | 0 | 5 | 11 | top-websites gist (no active program match) |
| [ sxsw.com ](reports/sxsw.com.md) | 30 | 0 | 0 | 5 | 25 | top-websites gist (no active program match) |
| [ t.co ](reports/t.co.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ t.ly ](reports/t.ly.md) | 27 | 0 | 0 | 2 | 25 | top-websites gist (no active program match) |
| [ t.me ](reports/t.me.md) | 29 | 0 | 0 | 11 | 18 | top-websites gist (no active program match) |
| [ t.qq.com ](reports/t.qq.com.md) | 2 | 0 | 0 | 0 | 2 | [Tencent](https://en.security.tencent.com) |
| [ techcrunch.com ](reports/techcrunch.com.md) | 25 | 0 | 0 | 3 | 22 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| [ technet.microsoft.com ](reports/technet.microsoft.com.md) | 15 | 0 | 0 | 4 | 11 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ telegram.me ](reports/telegram.me.md) | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| [ telegram.org ](reports/telegram.org.md) | 23 | 0 | 0 | 4 | 19 | Telegram |
| [ tesla.com ](reports/tesla.com.md) | 21 | 0 | 0 | 5 | 16 | [Tesla](https://bugcrowd.com/tesla) |
| [ tf1.fr ](reports/tf1.fr.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ theguardian.com ](reports/theguardian.com.md) | 23 | 0 | 0 | 7 | 16 | top-websites gist (no active program match) |
| [ themarthablog.com ](reports/themarthablog.com.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ themify.me ](reports/themify.me.md) | 30 | 0 | 0 | 4 | 26 | top-websites gist (no active program match) |
| [ thinkgeek.com ](reports/thinkgeek.com.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ thinkwithgoogle.com ](reports/thinkwithgoogle.com.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ ticketportal.cz ](reports/ticketportal.cz.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ time.com ](reports/time.com.md) | 24 | 0 | 0 | 4 | 20 | TIME |
| [ timesofindia.indiatimes.com ](reports/timesofindia.indiatimes.com.md) | 16 | 0 | 0 | 3 | 13 | top-websites gist (no active program match) |
| [ tools.google.com ](reports/tools.google.com.md) | 18 | 0 | 0 | 4 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ tools.ietf.org ](reports/tools.ietf.org.md) | 24 | 0 | 0 | 5 | 19 | top-websites gist (no active program match) |
| [ translate.google.com ](reports/translate.google.com.md) | 22 | 0 | 0 | 2 | 20 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ treasury.gov ](reports/treasury.gov.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ trello.com ](reports/trello.com.md) | 30 | 0 | 0 | 5 | 25 | [Trello](https://bugcrowd.com/trello) |
| [ trends.google.com ](reports/trends.google.com.md) | 18 | 0 | 0 | 3 | 15 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ tripadvisor.com ](reports/tripadvisor.com.md) | 21 | 0 | 0 | 4 | 17 | top-websites gist (no active program match) |
| [ trustpilot.com ](reports/trustpilot.com.md) | 20 | 0 | 0 | 4 | 16 | [Trustpilot](https://hackerone.com/trustpilot) |
| [ twitter.com ](reports/twitter.com.md) | 22 | 0 | 0 | 2 | 20 | [Twitter](https://hackerone.com/twitter) |
| [ uber.com ](reports/uber.com.md) | 17 | 0 | 0 | 1 | 16 | [Uber](https://hackerone.com/uber) |
| [ udemy.com ](reports/udemy.com.md) | 21 | 0 | 0 | 4 | 17 | [Udemy](https://hackerone.com/udemy) |
| [ un.org ](reports/un.org.md) | 20 | 0 | 0 | 3 | 17 | top-websites gist (no active program match) |
| [ united.com ](reports/united.com.md) | 18 | 0 | 0 | 4 | 14 | [United Airlines](https://bugcrowd.com/united-vdp) |
| [ untappd.com ](reports/untappd.com.md) | 21 | 0 | 0 | 2 | 19 | top-websites gist (no active program match) |
| [ upwork.com ](reports/upwork.com.md) | 21 | 0 | 0 | 1 | 20 | [Upwork](https://bugcrowd.com/upwork) |
| [ us.battle.net ](reports/us.battle.net.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ use.typekit.net ](reports/use.typekit.net.md) | 19 | 0 | 0 | 5 | 14 | top-websites gist (no active program match) |
| [ uspto.gov ](reports/uspto.gov.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ validator.w3.org ](reports/validator.w3.org.md) | 20 | 0 | 0 | 2 | 18 | top-websites gist (no active program match) |
| [ verizon.com ](reports/verizon.com.md) | 17 | 0 | 0 | 4 | 13 | top-websites gist (no active program match) |
| [ vice.com ](reports/vice.com.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ video.google.com ](reports/video.google.com.md) | 19 | 0 | 0 | 5 | 14 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ vimeo.com ](reports/vimeo.com.md) | 28 | 0 | 0 | 1 | 27 | [Vimeo](https://hackerone.com/vimeo) |
| [ vine.co ](reports/vine.co.md) | 24 | 0 | 0 | 3 | 21 | [Twitter](https://hackerone.com/twitter) |
| [ vizio.com ](reports/vizio.com.md) | 25 | 0 | 0 | 5 | 20 | top-websites gist (no active program match) |
| [ vk.com ](reports/vk.com.md) | 29 | 0 | 0 | 8 | 21 | top-websites gist (no active program match) |
| [ vogue.com ](reports/vogue.com.md) | 24 | 0 | 0 | 4 | 20 | top-websites gist (no active program match) |
| [ vr.google.com ](reports/vr.google.com.md) | 20 | 0 | 0 | 4 | 16 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ w3schools.com ](reports/w3schools.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ walmart.com ](reports/walmart.com.md) | 20 | 0 | 0 | 5 | 15 | [Walmart Corporation](https://corporate.walmart.com/article/responsible-disclosure-policy) |
| [ washingtonpost.com ](reports/washingtonpost.com.md) | 27 | 0 | 0 | 6 | 21 | top-websites gist (no active program match) |
| [ waze.com ](reports/waze.com.md) | 23 | 0 | 0 | 5 | 18 | top-websites gist (no active program match) |
| [ web.facebook.com ](reports/web.facebook.com.md) | 22 | 0 | 0 | 6 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| [ webmd.com ](reports/webmd.com.md) | 21 | 0 | 0 | 5 | 16 | top-websites gist (no active program match) |
| [ webroot.com ](reports/webroot.com.md) | 49 | 0 | 6 | 12 | 31 | top-websites gist (no active program match) |
| [ weebly.com ](reports/weebly.com.md) | 30 | 0 | 0 | 6 | 24 | top-websites gist (no active program match) |
| [ weforum.org ](reports/weforum.org.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ wetransfer.com ](reports/wetransfer.com.md) | 25 | 0 | 0 | 2 | 23 | top-websites gist (no active program match) |
| [ whatsapp.com ](reports/whatsapp.com.md) | 20 | 0 | 0 | 4 | 16 | [Facebook](https://www.facebook.com/whitehat) |
| [ who.int ](reports/who.int.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ wikipedia.org ](reports/wikipedia.org.md) | 21 | 0 | 0 | 3 | 18 | top-websites gist (no active program match) |
| [ windows.microsoft.com ](reports/windows.microsoft.com.md) | 18 | 0 | 0 | 5 | 13 | [Microsoft Online Services](https://www.microsoft.com/en-us/msrc/bounty-online-services) |
| [ wired.com ](reports/wired.com.md) | 23 | 0 | 0 | 4 | 19 | top-websites gist (no active program match) |
| [ wix.com ](reports/wix.com.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ wordpress.com ](reports/wordpress.com.md) | 28 | 0 | 0 | 10 | 18 | WordPress |
| [ wordpress.org ](reports/wordpress.org.md) | 30 | 0 | 0 | 7 | 23 | [WordPress](https://hackerone.com/wordpress) |
| [ wp.me ](reports/wp.me.md) | 18 | 0 | 0 | 6 | 12 | top-websites gist (no active program match) |
| [ www-01.ibm.com ](reports/www-01.ibm.com.md) | 17 | 0 | 0 | 5 | 12 | [IBM](https://hackerone.com/ibm) |
| [ www.ietf.org ](reports/www.ietf.org.md) | 23 | 0 | 0 | 2 | 21 | IETF |
| [ xbox.com ](reports/xbox.com.md) | 22 | 0 | 0 | 5 | 17 | top-websites gist (no active program match) |
| [ xing.com ](reports/xing.com.md) | 26 | 0 | 0 | 5 | 21 | top-websites gist (no active program match) |
| [ yadi.sk ](reports/yadi.sk.md) | 18 | 0 | 0 | 4 | 14 | top-websites gist (no active program match) |
| [ yahoo.com ](reports/yahoo.com.md) | 18 | 0 | 0 | 5 | 13 | [Yahoo!](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) |
| [ yandex.com ](reports/yandex.com.md) | 23 | 0 | 0 | 5 | 18 | [Yandex](https://yandex.com/bugbounty/index) |
| [ yandex.ru ](reports/yandex.ru.md) | 23 | 0 | 0 | 6 | 17 | [Yandex](https://yandex.com/bugbounty/index) |
| [ yelp.com ](reports/yelp.com.md) | 22 | 0 | 0 | 5 | 17 | [Yelp](https://hackerone.com/yelp) |
| [ yoursite.com ](reports/yoursite.com.md) | 23 | 0 | 0 | 6 | 17 | top-websites gist (no active program match) |
| [ youtube-nocookie.com ](reports/youtube-nocookie.com.md) | 7 | 0 | 1 | 1 | 5 | Google |
| [ youtube.com ](reports/youtube.com.md) | 19 | 0 | 0 | 1 | 18 | [Google](https://www.google.com/about/appsecurity/reward-program/) |
| [ zalo.me ](reports/zalo.me.md) | 25 | 0 | 0 | 6 | 19 | top-websites gist (no active program match) |
| [ zdnet.com ](reports/zdnet.com.md) | 20 | 0 | 0 | 5 | 15 | top-websites gist (no active program match) |
| [ zeit.de ](reports/zeit.de.md) | 20 | 0 | 0 | 4 | 16 | top-websites gist (no active program match) |
| [ zen.yandex.ru ](reports/zen.yandex.ru.md) | 25 | 0 | 0 | 7 | 18 | [Yandex](https://yandex.com/bugbounty/index) |
| [ zillow.com ](reports/zillow.com.md) | 22 | 0 | 0 | 4 | 18 | top-websites gist (no active program match) |
| [ zoom.us ](reports/zoom.us.md) | 49 | 0 | 9 | 5 | 35 | [Zoom](https://explore.zoom.us/docs/ent/h1.html) |
