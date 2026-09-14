# Shadowrocket Ultimate Regional Routing

A standalone, credential-free Shadowrocket configuration using exactly four existing local node labels: **英国家宽**, **日本家宽**, **美国家宽**, **香港家宽**. The public import URL stays stable:

[shadowrocket-ultimate.conf](https://raw.githubusercontent.com/Joe15935/shadowrocket-regional-routing/main/shadowrocket-ultimate.conf)

<!-- STATUS -->
Current Version: `rules-bf2e86a4deec8e13`  
Last Updated: 2026-09-14T04:32:19+00:00  
Last Successful Test: 2026-09-14T04:32:19+00:00 — 401 / 401 fixed cases  
Last Change Report: [2026-09-14](reports/2026-09-14.md)
<!-- /STATUS -->

## Routing contract

First match wins. Private/local traffic is direct. PayPal and Kraken/Pro/Krak have UK overrides; the specific paypal.us suffix uses US. UK, Japanese and Hong Kong native services precede general crypto (Japan), global AI, streaming and social (US), international finance (US), and mainland services (DIRECT). Country domain suffixes follow; only CN has a country-IP fallback. The final policy is explicitly **美国家宽**.

Wise and Trading 212 are UK. Revolut and international US brokerages use US. Explicit regional versions use their target market. LINE is Japan. Douyin, Weixin/WeChat and Bilibili China are direct; TikTok, Bilibili International and AliExpress use US. International Apple domains use US; apple.com.cn, icloud.com.cn and apzones.com are direct. The latter is listed by [Apple's enterprise network documentation](https://support.apple.com/en-us/101555) as iCloud infrastructure for mainland China.

Only the minimal `[General]` UDP rejection option and `[Rule]` sections are present. There are no node definitions, DNS changes, certificates, interception sections, request rewriting or runtime scripts. Unsupported node UDP is configured to reject. Support for this spelling and value was checked in the installed application's own template for Shadowrocket 2.2.92 (3445); actual UDP forwarding was not exercised.

Service-specific hostnames may be included under shared CDN parents. Generic Cloudflare, Akamai, AWS, Firebase, Brightcove, Sentry and other shared infrastructure are not assigned wholesale to a regional customer. Domains are classified by product market, rather than corporate nationality or server location. A domain suffix matches the root and all descendants, so one `uk`, `jp` or `hk` fallback covers its national subdomains as well. Explicit services precede those fallbacks.

## Sources and reuse choice

| Candidate | Maintenance observed | Reuse | Deployment/resources | Decision |
|---|---|---|---|---|
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | Active repository, updated 2026-09-13; individual files have separate dates | Native Shadowrocket service lists and ChinaMaxNoIP | Public text snapshots; standard Python on a daily hosted runner | Reuse and normalize selected lists, with local canonical overrides |
| [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) | Active, updated 2026-09-14 | Broad direct/proxy building blocks | Similar lightweight text hosting | Too broad for the required regional product policies |
| [h2y/Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules) | Archived; last push 2021 | Historical complete profiles | Simple hosting but obsolete policy assumptions | Not used |

The minimum implementation reuses maintained domain data and adds a small standard-library normalization/test layer. No proxy server, account service or production dependency is required. Each upstream revision, content hash, declared update date, HTTP status and normalization exclusion is recorded in [upstream-lock.json](upstream-lock.json). A maintained repository does not imply every service list is recent: Crypto has a 2025 content date and OKX has a 2024 content date, so official API documentation and reviewed extras fill the gaps.

The native ChinaMaxNoIP rule file is supplemented by its `_Domain.list` companion; both are converted to standard `DOMAIN`/`DOMAIN-SUFFIX` lines. Keywords, request-path rules, user-agent rules and upstream IP ranges are deliberately excluded. This avoids broad client/keyword/CDN classification and supports transparent hostname simulation. Only private LAN address ranges are included as literal IP rules.

## Updates and audit history

[Daily update workflow](.github/workflows/update-rules.yml) → fetch a single upstream commit → normalize → resolve conflicts → build candidate → syntax and confidentiality checks → first-match routing cases → simulator/conflict tests → effective-policy diff → report → atomic publication.

The configuration references an immutable `rules-<content digest>` tag for **all** of its rule files. The updater pushes that tag and the new main commit atomically. This prevents a profile from combining independent untested upstream revisions. Existing cached profiles retain their previous complete snapshot until Shadowrocket downloads the new configuration.

Local canonical files are never rewritten by the upstream updater. New and old domain rules generate both apex and descendant witnesses for policy comparisons. Any effective country/DIRECT transition blocks automatic publication, even if a new upstream rule caused it. An intentional policy change requires a reviewed canonical edit. This is conservative: some legitimate newly added regional or mainland domains can await review rather than publish automatically.

Successful changes update [CHANGELOG.md](CHANGELOG.md), dated reports and complete machine-readable changes. No-change runs leave history intact. Failed updates leave the previous remote main unchanged and upload an **UPDATE_BLOCKED** report as an Actions artifact and job summary. View failures at [Actions](https://github.com/Joe15935/shadowrocket-regional-routing/actions). GitHub scheduling is best effort and daily cron schedules can be delayed or disabled by platform inactivity rules.

[conflicts.json](conflicts.json) records both removed cross-policy duplicates and retained higher-priority exceptions inside broader suffixes. No conflict is accepted without deterministic resolution. Reports include policy changes, high-impact changes, counts by category and upstream revisions.

## Verification

Python 3.10+ and curl are sufficient; no package installation is needed.

```sh
python3 scripts/pipeline.py update
python3 scripts/validate.py
python3 scripts/regression_test.py --verbose
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/remote_verify.py
```

`tests/routing_cases.yaml` uses the JSON subset of YAML 1.2. Routing output includes `HOST`, `MATCHED_RULE`, `POLICY`, `EXPECTED`, and `RESULT`. The simulator parses the published configuration order and expands its actual rule-set files; it does not just look for domain strings. It supports exact domains, suffixes, keywords for isolated engine tests, private IPv4/IPv6 ranges, synthetic CN country metadata, and FINAL.

The current app/node archive was read without importing, activating, editing, or switching a profile. All four exact labels were found once. This repository contains no node material. Native import and live traffic were not tested, because changing the user's active connection is outside the task. The checks establish supported configuration syntax, static policy behavior and public raw downloadability, not account availability or undiscovered app endpoints. Existing enabled modules may take precedence over profile rules; they were not modified.

## Attribution

Domain snapshots derive from [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script), licensed GPL-2.0, and its credited upstream contributors. This repository is distributed under GPL-2.0 with original-source revision metadata and modification reports. Reviewed first-party references are listed in [source audit](reports/source-audit.md).
