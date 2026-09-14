# Source and first-party audit

Checked 2026-09-14. This records hostname classification evidence, not successful account access, transaction execution or geographic eligibility. Public webpage checks did not authenticate to any financial service.

## Compatibility

The installed Shadowrocket 2.2.92 build 3445 executable recognizes `udp-policy-not-supported-behaviour`. Its bundled default template declares `DIRECT` and `REJECT` and uses `REJECT`. The generated file sets that one General option. This is direct evidence from the installed application; no settings were changed. The full stored archive was traversed independently of the UI's collapsed display, and each of the four required node labels occurred once as a node title.

## Crypto and PayPal

| Service | Primary reference | Covered identification |
|---|---|---|
| Binance | [Official Spot API docs](https://developers.binance.com/en/docs/binance-spot-api-docs/rest-api/general-api-information), [official market-data repository](https://github.com/binance/binance-spot-api-docs/blob/master/faqs/market_data_only.md) | binance.com REST/stream/ws-api/futures subdomains; binance.vision data API and data stream; reviewed first-party static domain bnbstatic.com |
| OKX | [Official API guide](https://www.okx.com/docs-v5/en/) | openapi, ws, wspap, static and account under okx.com; dedicated oklink and okex domains |
| Gate | [Official REST](https://www.gate.com/docs/developers/apiv4/en/), [official WebSocket](https://www.gate.com/docs/developers/apiv4/ws/en/) | gate.com, gate.io, api.gateio.ws, fx-api.gateio.ws, api-testnet.gateapi.io; service-specific image/CDN domains |
| Bybit | [Official integration guide](https://bybit-exchange.github.io/docs/v5/guide), [WebSocket connections](https://bybit-exchange.github.io/docs/v5/ws/connect) | bybit.com and bytick.com REST and streams; documented regional API variants; exact documented Japanese and Hong Kong partner API hostnames |
| MEXC | [Official Spot API](https://mexcdevelop.github.io/apidocs/spot_v3_en/), [official contracts](https://mexcdevelop.github.io/apidocs/contract_v1_en/) | api.mexc.com, wbs-api.mexc.com, contract.mexc.com and the whole first-party mexc.com suffix |
| Kraken | [Official API center](https://docs.kraken.com/), [WebSocket FAQ](https://support.kraken.com/articles/360022326871-kraken-websocket-api-frequently-asked-questions) | api.kraken.com, pro.kraken.com, ws.kraken.com, ws-auth.kraken.com, futures.kraken.com and first-party assets under kraken.com; all UK |
| Krak | [Kraken's product page](https://www.kraken.com/krak), [Krak support](https://support.krak.app/br/articles/what-is-krak) | krak.app and subdomains, plus Kraken account infrastructure; all UK |
| PayPal | [Official resource/CSP requirements](https://developer.paypal.com/payment-links-buttons/troubleshooting/), [PayPal.Me help](https://www.paypal.com/us/cshelp/article/what-is-paypalme-help432) | paypal.com API/auth/checkout and paypalobjects.com static resources stay UK; paypal.me is also UK; URL paths cannot alter the domain policy |

Core exchange, wallet, explorer and DeFi namespaces are protected in `crypto-extra.list`. Parent suffix rules cover API, account, auth, stream and static subdomains without guessing individual subdomain labels. A shared AWS/Cloudflare/Akamai parent is not considered evidence of exchange ownership. Secondary/alias domains from selected community data are retained only subject to normalizer exclusions and regression gates; they are not all independently certified as first-party.

The [public crypto webpage checks](crypto-domain-checks.json) additionally identified static.okx.ac, static.okx.cab, static.okx.reise, www.kucoinauth.cloud, file.coinexstatic.com and a MEXC-specific AWS bucket hostname. These are covered without assigning all AWS traffic to crypto. Kraken's official page links to krak.app and iapi.kraken.com. The guessed krakenpro.com alias could not be verified and was excluded; actual Kraken Pro is covered by pro.kraken.com. PayPal's official pages link to paypal-status.com, paypal.ai and paypal-corp.com; those were added to its UK exception.

## Finance

[Monzo's developer documentation](https://docs.monzo.com/) identifies api.monzo.com; [Starling's payment API documentation](https://developer.starlingbank.com/payments/docs) identifies payment-api.starlingbank.com. Their parent first-party suffixes keep the same UK policy for the app, website and documented API.

Official banking/regulator pages were checked for the requested UK, Japan and Hong Kong institutions. The public result table is in [finance-domain-checks.json](finance-domain-checks.json). Trading 212 and Mizuho returned HTTP 403 to an automated request; that is an access restriction, not proof that the domain is invalid. Some Lloyds-group pages returned HTTP 200 with an error/unavailable title, so these are not counted as successful banking-session checks. Domains are also supported by their official service references:

- [Trading 212 official help](https://helpcentre.trading212.com/), [official API](https://docs.trading212.com/).
- [Mizuho Bank official company page](https://www.mizuhobank.co.jp/company/).
- [MUFG](https://www.bk.mufg.jp/), [SMBC](https://www.smbc.co.jp/), [Japan Post Bank](https://www.jp-bank.japanpost.jp/), [SBI Securities](https://www.sbisec.co.jp/), [Rakuten Securities](https://www.rakuten-sec.co.jp/).
- [HKEX](https://www.hkex.com.hk/), [SFC](https://www.sfc.hk/), [HSBC HK](https://www.hsbc.com.hk/), [Hang Seng](https://www.hangseng.com/), [BOCHK](https://www.bochk.com/), [ZA](https://bank.za.group/), [Mox](https://mox.com/), [WeLab](https://www.welab.bank/), [Futu HK](https://www.futuhk.com/).

The user's explicit exceptions override global branding: Wise and Trading 212 use UK; Revolut uses US. Regional brokerage country domains use the corresponding region. Shared international brokerage domains use US.

## Apple

[Apple's current enterprise-network page](https://support.apple.com/en-us/101555) explicitly lists apzones.com and icloud.com.cn as mainland-China iCloud services. It separately lists cdn-apple.com, icloud.com, icloud-content.com, apple-cloudkit.com and Apple account hosts as shared services; these stay US. This configuration neither changes Apple account region nor modifies DNS.

## Upstream exclusions

The audit found generic Cognito, mobile analytics, Brightcove, LaunchDarkly and JWPlayer endpoints mixed into regional lists. It also found international Rakuten/Viber, Sky New Zealand and TVB overseas variants. They were excluded from those regional inputs. Exact service-specific CDN hosts remain eligible, but ownership of the shared parent is never inferred.

The project is active, while individual Crypto and OKX rule files are older. Official exchange documentation supplied missing first-party REST and stream roots. The complete fetched source hashes, declared content dates and filtered domains are in [upstream-lock.json](../upstream-lock.json). All published rule-set URLs are self-hosted, tested snapshots rather than mutable upstream branches.
