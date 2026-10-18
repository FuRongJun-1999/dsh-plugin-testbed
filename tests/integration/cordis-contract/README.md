# Real Cordis runtime anchor + contract suite (`cordis-contract-suite/v1`)

These tests prove the locked Cordis runtime behaves as the testbed requires.
They are not fixture tests: the runtime is imported from the exact
`testbed-runtime-anchor/v2` entry built from `cordis-runtime/node_modules`, and
the suite fails closed with `[blocked:<reason>]` when that runtime is missing or
does not match the anchor.

## Locked matrix

`cordis-runtime/` is a standalone, exactly pinned install root. It is not the
testbed plugin package, is never installed into a live DSH/desktop profile, and
every resolved artifact is pinned by `cordis-runtime/pnpm-lock.yaml` integrity.

| Package | Version | Role |
|---|---|---|
| `@deepseek-ai/cordis` | `4.0.5` | runtime under contract |
| `@deepseek-ai/dsh` | `0.2.1-rc.2` | locked DSH host package |
| `@deepseek-ai/dsh-cordis-host-runner` | `0.2.1-rc.2` | real `define/run/stop/undefine` service |
| `@deepseek-ai/cordis-plugin-loader` | `1.0.6` | Cordis peer (loader) |
| `@deepseek-ai/cordis-plugin-include` | `1.0.10` | Cordis peer (include) |
| `@deepseek-ai/cordis-plugin-timer` | `1.1.7` | timer service contract |
| Node | `24.21.0` | locked runtime matrix (`engines.node`) |

The current evidence was produced on `win32` / `x64`, OS `10.0.26200`
(Windows 11 Pro), Node ABI `137`. The anchor binds those values; a different
Node/OS is a different matrix row, not a compatible range.

## Commands

```powershell
# from dsh-plugin-testbed/
pnpm --dir cordis-runtime install --frozen-lockfile
pnpm --dir cordis-runtime exec node --version
node --test "tests/integration/cordis-contract/**/*.test.js"
```

`pnpm-workspace.yaml` in `cordis-runtime/` sets `ignoreScripts: true` and
explicitly denies every detected build script (`allowBuilds: false`), so a fresh
frozen install is deterministic and executes no registry lifecycle code. The
frozen install is the integrity gate; `install.test.js` cross-checks the Cordis
and DSH SRI values against the published registry values.

## Files

| Path | Purpose |
|---|---|
| `cordis-runtime/runtime-anchor.json` | generated `testbed-runtime-anchor/v2` (package/version/integrity, real entry + digest, lockfile digest, DSH/Node/OS, catalog ref) |
| `contract/cordis-contract-suite.v1.json` | static suite definition |
| `evidence/cordis-api-catalog.v1.json` | observed export/API surface of the locked Cordis package |
| `evidence/cordis-contract-suite.v1.json` | materialized suite bound to the anchor digest |
| `evidence/cordis-contract-results.v1.json` | per-case `pass/fail/error`, bound to suite/anchor/lockfile/catalog/Node/OS |
| `evidence/runtime-anchor-verification.v1.json` | positive verifier output |
| `evidence/runtime-install-evidence.v1.json` | exact pins, lockfile SRI, no-Electron/app.asar, isolation checks |
| `_runtime.js` | reads the isolated install, builds/verifies the anchor, imports the real packages, writes evidence |
| `anchor.test.js` | positive v2 anchor verification + negative `app.asar`/fixture/floating-tag/digest/version/environment cases |
| `install.test.js` | exact pins, lockfile SRI, frozen-install isolation, no Electron/app.asar, no lifecycle scripts |
| `contract.test.js` | executes the 12 behavioral cases and writes the results evidence |
| `fixtures/loader-plugin.mjs` | a real ESM plugin loaded through the real loader (not a runtime substitute) |

The generated anchor contains the absolute path of the isolated install for
provenance. Moving the workspace or upgrading any pinned package requires
rerunning the contract suite and committing the new evidence. The anchor is
never a live-profile or `app.asar` path.

## Behavioral cases

| Case | What it proves |
|---|---|
| `runtime.module-identity` | the entry is the real Cordis class surface; the workspace `fake-cordis-stub` cannot impersonate it |
| `context.events-dispatch` | `emit`/`bail`/`serial`/`parallel`/`waterfall` semantics and listener cleanup |
| `context.service-registry` | plugin registry, `provide`/`get`, registry iteration/delete, duplicate rejection |
| `service.isolation` | `ctx.isolate()` scopes, `inject`-driven activation, provider disposal/reactivation |
| `fiber.lifecycle` | `PENDING -> LOADING -> ACTIVE -> UNLOADING -> DISPOSED`, `DISPOSED` cannot restart/effect |
| `fiber.failure-recovery` | `LOADING -> FAILED`, restart re-execution, and the locked 4.0.5 restart-promise quirk recorded verbatim |
| `fiber.effects-resource-release` | effect labels, reverse-order async disposers, plugin-return disposer, abort signal |
| `loader.dynamic-entries` | real loader `create`/`update`/`remove` of a file-URL plugin |
| `loader.group-entries` | real `Group` carrier with a nested entry and recursive release |
| `timer.disposal` | real timer service clears interval/timeout on fiber disposal |
| `dynamic-runner.define-run-stop-undefine` | real DSH host-runner `define`/`run`/`stop`/`undefine` over real Cordis fibers |
| `dynamic-runner.error-and-cancel` | host-half failure, pre-aborted cancellation, cleanup afterwards |

The dynamic-runner cases mount the runner with a minimal `tools` peer service
(the runner declares `tools` as an inject). Cordis, the host-half VM and the
runner itself are the real locked packages; the minimal peer is not used as
runtime evidence.

## Fail-closed rules

- `testbed-runtime-anchor/v2` verification rejects `app.asar` entries
  (`runtime-anchor-app-asar-rejected`), `runtime_kind=test-fixture`
  (`runtime-anchor-fixture-rejected`), floating tags/ranges
  (`runtime-package-unlockable`), entry/lockfile digest mismatch, observed
  version mismatch, and Node/OS mismatch.
- Missing `node_modules`, a bad lockfile, or an unverifiable anchor throws a
  `[blocked:<reason>]` error; the suite fails rather than skipping or using a
  fixture.
- The workspace `tests/fixtures/fake-cordis-stub.mjs` is imported only as a
  counterexample in `runtime.module-identity`; it lacks the real Cordis surface
  and cannot satisfy the suite.
- `resolveRuntimeAnchorV2` / `verifyRuntimeAnchorV2` in
  `src/worker/runtime.js` expose the same fail-closed checks to integration;
  the v1 resolver remains local-L1-only and must not satisfy a market gate.

## Binding chain

`evidence/cordis-contract-results.v1.json` binds:

- `runtime_anchor_digest` — canonical `testbed-runtime-anchor/v2` digest
- `suite_digest` — materialized suite including the anchor digest
- `lockfile_digest` — `cordis-runtime/pnpm-lock.yaml`
- `entry_digest` — SHA-256 of the real Cordis entry file
- `catalog_digest` — observed API catalog
- `environment_digest` plus `environment` — Node version/ABI, platform, arch, OS release/version

Run from `dsh-plugin-testbed/`:

```powershell
node --test "tests/integration/cordis-contract/**/*.test.js"
```
