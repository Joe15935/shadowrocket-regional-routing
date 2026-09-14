# Initial public acceptance and update safeguards

Update Date: 2026-09-14  
Previous Version: rules-bf2e86a4deec8e13  
New Version: rules-bf2e86a4deec8e13 (routing unchanged)

## Acceptance

- The repository is public and its default branch is main.
- The stable configuration and all 25 referenced rule files returned HTTP 200 to anonymous curl HEAD and GET requests. All 26 payloads were plain text and matched the verified local bytes.
- The immutable candidate configuration URL was also checked independently with the same 25 rule files: all 26 passed.
- Configuration validation expanded 113,157 rules in the authoritative order. All 401 fixed cases, 2,066 canonical apex/descendant checks, and 13 engine/failure-report tests passed locally.
- The first [GitHub validation run](https://github.com/Joe15935/shadowrocket-regional-routing/actions/runs/34806545384) succeeded, including anonymous public URL checks.
- The first [GitHub update trial](https://github.com/Joe15935/shadowrocket-regional-routing/actions/runs/34806573412) succeeded. It fetched 64 pinned source files, passed routing tests and reported `NO_RULE_CHANGES`; the published snapshot was retained.
- Hashes of all nine preflight-tracked original configuration/node-archive files were unchanged. No profile was imported or activated, and no system network setting was written.

## Update safeguards

The updater now checks the public candidate tag before moving the stable main branch. A retry reuses an existing immutable tag and verifies its contents rather than overwriting it. An unsuccessful run always emits a current `UPDATE_BLOCKED` report, replacing stale success text in local scratch output. A unit test injects a fetch failure and verifies that behavior.

These changes affect build/update scripts and reports only. The configuration and all routing lists are unchanged.

## POLICY CHANGES

None.

## HIGH IMPACT CHANGES

None.

| Category | Added rules | Removed rules | Modified rules |
|---|---:|---:|---:|
| UK | 0 | 0 | 0 |
| Japan | 0 | 0 | 0 |
| Hong Kong | 0 | 0 | 0 |
| US/Global | 0 | 0 | 0 |
| Crypto | 0 | 0 | 0 |
| AI | 0 | 0 | 0 |
| Streaming | 0 | 0 | 0 |
| Social | 0 | 0 | 0 |
| China DIRECT | 0 | 0 | 0 |
| Finance | 0 | 0 | 0 |
| Apple | 0 | 0 | 0 |

Upstream sources changed: none.

## Scope of proof

This is static routing, configuration-compatibility, publication and workflow evidence. The active Shadowrocket configuration was not switched. Live forwarding, UDP transport behavior, native import, account sessions and availability of undiscovered app endpoints were not exercised.
