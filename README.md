# dsh-plugin-testbed

**DSH 本地自检元插件**：为开发者自有、受信的 PUT（被测插件）提供显式触发的本地自检，把 `run-spec/v1` 走完「冻结 Plan → 执行 → 对账 → 门禁」，输出可审计的 `receipt/v1` 与只读投影；另提供独立的市场门禁入口，以及默认关闭的受治理调度入口。

> **开发程度（2026-10-19）**：本地 L1/local-only 闭环已可用，全量 **853/853** 测试通过，`tsc --noEmit` 通过；真实 Cordis 运行时已精确锁定并通过 **12/12** 行为契约。市场阶段（L2 provider、证据/签名/归档抽象、市场门禁、调度器）代码已落地，但当前环境**只能输出 `non-eligible`（exit 2、`publish=false`）**，从未产生 eligible 或发布；L3、生产级 KMS/HSM、WORM/TSA 与预执行审批尚未实现。**本仓库是可执行原型，不是市场发布器。**

## 开发程度

| 范围 | 程度 | 当前事实 |
|---|---|---|
| 本地自检 L0/L1 | ✅ 可用 | `plugin_selfcheck` / CLI / API 共用 `runSelfCheck`；冻结 Plan、执行、对账、GateDecision、`receipt/v1`、只读投影闭环 |
| 控制内核 | ✅ 已验证 | 必测基线、冻结后不可变、稳定拓扑序、attempt 历史、missing/retry/cancel、控制面独立 admission |
| 受控工具 | ✅ 已验证 | `test-tool-manifest/v1` + `test-tool/v1`；固定入口、参数数组、`shell:false`；OS `spawn` 是唯一 `started` 来源 |
| Receipt 与投影 | ✅ 已验证 | RFC 8785 + SHA-256 可复算摘要；JUnit / TAP / HTML / CI summary 只读投影 |
| 真实 Cordis 锚定 | ✅ 已验证 | `@deepseek-ai/cordis@4.0.5` / `@deepseek-ai/dsh@0.2.1-rc.2`；`testbed-runtime-anchor/v2`；12/12 契约 |
| L2 隔离 | 🟡 受限 | Windows AppContainer Low-IL + Job Object provider 已实现；A2 的 18 个 case 中 8 个通过、10 个 blocked，`evaluation=blocked`；无外部 availability，harness 仍是 High-IL 管理员会话 |
| L3 / 远程 runner | ❌ 未实现 | 无 rootless container、micro-VM 或远程 runner；不得用 L2 冒充 L3 |
| 市场门禁 | 🟡 fail-closed | 条件引擎、审批/豁免、证据包、固定顺序已实现；当前 C03/C04 pass，C01/C02/C05–C10 fail → `non-eligible` / exit 2 / `publish=false` |
| 签名 / 归档 | 🟡 dev-only | 只有 E1 development signer / local archive；无 KMS/HSM/OS-keystore、WORM/object-lock/tlog、TSA |
| 调度 | 🟡 默认关闭 | durable lease/fencing/TTL/cancel/reap + `node:sqlite`；`cron_enabled=false`、`background_loops=false`、`single_host=true`、`ha=false` |
| TypeScript 迁移 | 🚧 进行中 | P1 protocol、P3 evidence/market schemas 已迁移；P2 控制核心部分迁移；P4 adapters/worker/reports/CLI/plugin 仍为 JS compatibility；63 个 `.ts` 模块 |

**适合**：在开发者控制、无秘密的本地环境中自检自有 PUT；在 CI 中复跑同一本地流程；审计 `receipt/v1` 与投影。
**不适合**：执行不可信/恶意 PUT；把 L1 当安全沙箱；作为市场发布证据；多租户或远程执行。

## 快速开始

### 环境

- Node.js >= 20（本次验证：`v24.21.0`）
- pnpm `11.28.5`（`packageManager` 固定）
- 本次唯一实测平台：Windows 11 `10.0.26200` / `win32 x64`；尚不是跨平台兼容矩阵

```bash
git clone https://github.com/supengpeng/dsh-plugin-testbed.git
cd dsh-plugin-testbed
pnpm install --frozen-lockfile

pnpm exec tsc --noEmit          # 类型门禁
pnpm run build:ts               # 由 src/**/*.ts 生成 sibling .js（禁止手改）
pnpm test                       # 全量测试
```

真实 Cordis 契约测试需要一个独立的锁定安装：

```bash
pnpm --dir cordis-runtime install --frozen-lockfile
node --test "tests/integration/cordis-contract/**/*.test.js"
```

缺少或篡改 `cordis-runtime/node_modules` 时该套件会 fail-closed（`[blocked:<reason>]`），不会用 fixture 冒充真实运行时。

仓库内的 `cordis-runtime/runtime-anchor.json` 与 `tests/integration/cordis-contract/evidence/` 绑定当前验证主机、安装路径与 lockfile；在其他机器或路径上契约测试会 fail-closed，需要按 [`tests/integration/cordis-contract/README.md`](tests/integration/cordis-contract/README.md) 重新生成 anchor/evidence 并提交。

## 入口

### DSH 工具

`cordis.patch.yml` 将本包注册为 DSH bundle，安装后提供工具 `plugin_selfcheck`：

- `spec`：`run-spec/v1`（必填）
- `profile`：`local-selfcheck/v1`（默认）或 `market-required/v1`
- `receipt_out`：receipt 输出目录，默认 `.dsh-testbed-receipts`
- `execution_mode`：`in-process`（L0，默认）或 `subprocess`（L1）
- `runtime_anchor`：可选的 v1 运行时描述符

该工具只做本地自检，不产生市场结论。

### CLI

```bash
# 本地自检（L0/L1，receipt/v1，local-only）
node bin/selfcheck.js selfcheck --spec <spec.json> [--execution-mode in-process|subprocess] \
  [--runtime-anchor <v1-descriptor-json|anchor-file>] [--timeout-ms <n>] [--probe-time <iso>] \
  [--profile local-selfcheck/v1|market-required/v1] [--receipt-out <dir>] [--overwrite]

# receipt 只读投影
node bin/selfcheck.js project --receipt <receipt.json> --format junit,tap,html,ci-summary

# 独立市场门禁（fail-closed；当前环境恒 non-eligible）
node bin/selfcheck.js market --receipt <receipt.json> --policy <policy.json> \
  [--runtime-anchor <v2-anchor.json>] [--contract-evidence-dir <dir>] \
  [--isolation-attestation <json>|--isolation-execution-evidence <json>] [--a2-evidence <json>] \
  [--host-facts <json>] [--approvals <json>] [--waivers <json>] [--scheduler-evidence <json>] \
  [--evidence-out <dir>] [--verifier-id <id>] [--control-plane-id <id>] \
  [--control-plane-version <version>] [--now <iso>]

# 受治理调度入口（默认 disabled；显式 enable 需 policy + authorization + durable store）
node bin/selfcheck.js scheduler
node bin/selfcheck.js scheduler --enable-policy <policy.json> \
  --authorization <authorization.json> --store <scheduler.sqlite> [--owner-id <id>]
```

### 编程 API

```js
import {
  runSelfCheck, project, projectAll,
  runMarketGate, computeEligibility, assessReceipt, validateMarketPolicy,
  verifyRuntimeEvidence, assessIsolation, assessProviders,
  buildEvidencePackage, verifyEvidencePackage,
  describeSchedulerEntry,
} from '@deepseek-ai/dsh-plugin-testbed/api'
```

包根 `.` 是 DSH 插件入口，不暴露编程 API。`market` / `scheduler` 入口都不改写 `receipt/v1`。

## run-spec/v1 最小示例

```jsonc
{
  "schema_version": "run-spec/v1",
  "target": { "kind": "plugin", "put_digest": "sha256:<64hex>" },
  "scenario": { "cases": [
    { "test_id": "contract.echo", "node_id": "n1", "classification": "required",
      "criteria": { "assert": "equals", "path": "status", "expected": "ok" },
      "probe": { "op": "echo", "value": { "status": "ok" } } }
  ]}
}
```

注意：上面的 `echo` 是 legacy probe，没有 OS-spawn 启动见证，因此 `invocation_status=unknown`，即使 observation 通过也会得到本地 `blocked`（exit 2）。要得到本地 `pass`/exit 0，需要使用带 `test-tool/v1` 受控工具的 case；完整正向与负向示例见 [`tests/integration/m5-tool.test.js`](tests/integration/m5-tool.test.js)。

## 运行模式与信任边界

| 模式 | 隔离 | 说明 |
|---|---|---|
| `in-process`（默认） | L0 行为隔离 | 进程内 observation 生产者，**非隔离**；无可核验 OS 启动事件，`invocation_status=unknown` |
| `subprocess` | L1 fault 隔离 | 子进程 + 版本化 NDJSON；`test-tool/v1` attempt 由 adapter 以固定入口、参数数组、`shell:false` 启动一次性进程；OS `spawn` 事件是唯一 `invocation_status=started` 来源；资源维度均 `unenforced`（**非安全边界**） |

- `echo` / `load-put` 等 legacy 控制面 op 没有 OS-spawn 见证，不能放行 Gate。
- 受控工具（`test-tool/v1`）有独立启动见证，required 全部 pass 时可得到本地 `gate_decision=pass` 与 exit `0`。
- 工具/场景在 Plan 冻结前被拒绝 → pre-plan `blocked`，不伪造逐项终态；冻结后由控制面独立准入拒绝 → `admission_status=rejected`、`execution_status=skipped`、`verdict=skip`、`invocation_status=not-started`、`reason_code=policy_rejected`。
- 普通同权限子进程只是 **fault 隔离，不是安全边界**；L1 不能强制文件、网络、子进程、设备、CPU 或内存限制。

## 运行时锚定

本地自检使用 **v1** 运行时描述符，市场门禁使用 **v2** `testbed-runtime-anchor/v2`。两者不互相冒充：

- **v1（local）**：入口显式 `runtime_anchor` / `--runtime-anchor`（JSON descriptor 或文件）→ `DSH_TESTBED_RUNTIME_ANCHOR` → `DSH_TESTBED_CORDIS_ENTRY` → 已安装 `@deepseek-ai/cordis` 解析；不可用或版本不符时显式 `unavailable`（Gate `blocked`）。
- **v2（market）**：`cordis-runtime/runtime-anchor.json`，绑定 `runtime_kind=locked-runtime`、精确版本/integrity/lockfile/entry digest，逐项动态复核；`app.asar`、`test-fixture`、浮动 tag、过期副本全部拒绝。
- 把 v2 anchor 传给本地 v1 入口会 fail-closed（`runtime-unavailable`），不会被当作本地通过。

## 市场门禁（已实现，当前 non-eligible）

- **独立策略**：`market-gate-policy/v1` 必须冻结；`required_conditions` 必须完整枚举 MKT-C01..C10（partial/omitted 均 policy-invalid），不做 caller 子集裁剪。
- **固定顺序**：严格 `receipt/v1` 校验 → archive subject entry N → `market-eligibility/v1`（条件 AND）→ `market-attestation/v1` 构建/签名 → entry N+1 → 独立验证/发布。任一条件 fail/unknown 即 `non-eligible`/`blocked`，非 eligible 绝不签名、绝不产生 entry N+1。
- **独立 sidecar**：eligibility/attestation/verification/evidence package 独立落盘；`receipt/v1` 保持 unsigned/local-only/`market_eligible=false`。
- **条件**：C01/C02 隔离、C03 真实 Cordis anchor/contract、C04 receipt、C05 签名 provider、C06 归档/可信时间、C07 证据包、C08/C09 审批/豁免、C10 审计/调度证据。
- **当前环境**：C03/C04 pass；C01/C02（A2 blocked、无外部 availability、High-IL harness）、C05（无 KMS/HSM）、C06（无 WORM/TSA）、C08/C09（无预执行审批）、C07/C10 fail → `non-eligible`、exit `2`、`publish=false`。
- **转为 eligible 的外部前置**：真实低权限 L2（或策略要求 L3）provider + 完整 A2/A3；KMS/HSM/OS-keystore 签名；独立 WORM/object-lock/tlog + TSA；与冻结 policy 绑定的预执行审批/合法 waiver；以及独立 QA 复核。缺一不可。

## 受治理调度（默认关闭）

- `scheduler` 入口默认返回 `scheduler-disabled`（exit 2）；**无 cron、无后台定时器、无自动发布**，`cron_enabled=false`、`background_loops=false`、`single_host=true`、`ha=false`。
- 显式 enable 需要：`scheduler-policy/v1` + 未过期 operator authorization（职责分离）+ 可用的 `node:sqlite` durable store；任一缺失保持 `blocked`/disabled 并返回稳定 reason code。入口只报告状态并关闭 store，不常驻。
- 市场门禁只接受可选 `--scheduler-evidence`（`scheduler-lease/v1` + `scheduler-event/v1` chain）；调度 observation 的 `gate_effect=none`，不产生 GateDecision、不绕过市场审批。

## 退出码

| 场景 | local-selfcheck/v1 | market-required/v1 | market 入口 |
|---|---:|---:|---:|
| 本地 `pass` | 0 | 2（不具市场适格性） | — |
| 本地 `reject` | 1 | 2 | — |
| 本地 `blocked` | 2 | 2 | — |
| market `non-eligible`/`blocked` | — | — | 2 |
| receipt 无效/写失败 | 3 | 3 | 3 |
| market `eligible` + 签名/归档/审批/验证全部通过 | — | — | 0（当前环境不可能） |

`scheduler`：默认 disabled → 2；显式 enable 且全部治理条件通过 → 0；参数缺失/不可读 → 3。

## 仓库结构

```text
bin/selfcheck.js          CLI 入口（selfcheck / project / market / scheduler）
index.js                  DSH bundle 入口，注册 plugin_selfcheck
src/protocol/             版本化 schema、JSON Schema、摘要、transport、tool manifest
src/control/              PlanCandidate、冻结、拓扑执行、admission、对账、GatePolicy
src/worker/               worker host/runner/probe、环境边界、runtime anchor
src/adapters/             in-process、subprocess、OS spawn 启动见证
src/isolation/            L1/L2 隔离抽象与 Windows AppContainer/Job Object provider
src/evidence/             规范化、签名/归档 provider 抽象、attestation、evidence sequence
src/market/               市场 policy/eligibility/审批/证据包/固定顺序门禁
src/scheduler/            durable lease、fencing、TTL、cancel/reap、入口状态
src/reports/              receipt/v1、只读投影（JUnit/TAP/HTML/CI summary）
tests/                    单元、集成、安全与真实 Cordis 契约测试
cordis-runtime/           精确锁定的 Cordis/DSH 独立安装与 v2 anchor
```

## 验证快照

本次（2026-10-19，Node `v24.21.0`，Windows 11 `10.0.26200` x64）复跑结果：

| 命令 | 结果 |
|---|---|
| `pnpm exec tsc --noEmit` | exit 0 |
| `node --test "tests/**/*.test.js"` | **853 tests / 853 pass / 0 fail**（串行复跑同样 853/853） |
| `node --test "tests/integration/cordis-contract/**/*.test.js"` | 通过；真实 Cordis 契约 **12/12** |
| `node --test "tests/integration/market/**/*.test.js"` | 26/26 pass |
| `node bin/selfcheck.js market ...` | `non-eligible` / exit 2 / `publish=false` |

这些数字是当前工作区快照，不是持续集成徽章；任何代码变更后都应重新执行上述命令。

## 边界与文档

- **L1 不是安全边界**。只在开发者控制、专用、无秘密环境中运行自有且信任的 PUT/工具；不要用它执行不可信代码。
- 所有本地 receipt 固定 `trust_scope=local-only`、`market_eligible=false`、`integrity.signed=false`；本地 `pass` 不等于市场发布通过。
- 市场门禁在当前环境从未产生 `eligible`，也没有发布路径；fixture/mock/app.asar/dev provider 不得作为市场证据。
- 调度器默认关闭，单机、无 HA、无 cron；当前不提供多 worker、远程 runner 或在线建议器。
- 本次只在 Windows 11 x64 上实测，其他平台属于未验证矩阵。
- 架构、开发、开发计划、实现设计、验收与后续阶段需求文档只在本地维护，不随本仓库分发。
