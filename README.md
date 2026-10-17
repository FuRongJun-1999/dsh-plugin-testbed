# @deepseek-ai/dsh-plugin-testbed

装进 DSH 的单一元插件：为开发者自有、受信的 PUT（被测插件）提供**显式触发的本地自检**，把 `run-spec/v1` 走完「冻结 Plan → 执行 → 对账 → 门禁」，输出可审计的 `receipt/v1` 与只读投影。

> 定位 **L1、本地、开发者自控环境**：receipt 固定 `trust_scope=local-only`、`market_eligible=false`；普通同权限子进程只是 **fault 隔离，不是安全边界**，本地 `pass` 不等于市场发布通过。

## 入口

**DSH 工具** `plugin_selfcheck`：传 `{ spec, profile?, receipt_out? }`，`spec` 为 `run-spec/v1`。

**CLI**

```bash
node bin/selfcheck.js selfcheck --spec <spec.json> [--execution-mode in-process|subprocess] [--profile local-selfcheck/v1|market-required/v1] [--receipt-out <dir>] [--overwrite]
node bin/selfcheck.js project --receipt <receipt.json> --format junit,tap,html,ci-summary
```

**编程 API**：`import { runSelfCheck, project, projectAll } from '@deepseek-ai/dsh-plugin-testbed'`。

## run-spec/v1（最小示例）

```jsonc
{
  "schema_version": "run-spec/v1",
  "target": { "kind": "plugin", "put_digest": "sha256:<64hex>" },
  "scenario": { "cases": [
    { "test_id": "contract.echo", "node_id": "n1", "classification": "required",
      "criteria": { "assert": "equals", "path": "status", "expected": "ok" },
      "probe": { "op": "echo", "value": { "status": "ok" } } }
  ] }
}
```

## 运行模式

| 模式 | 隔离 | 说明 |
|---|---|---|
| `in-process`（默认） | L0 行为隔离 | 进程内 observation 生产者，**非隔离** |
| `subprocess` | L1 fault 隔离 | 子进程 + `control-protocol/v1` NDJSON + deadline/取消 + 进程树回收；资源维度均 `unenforced`（**非安全边界**） |

## 退出码

| gate_decision | local-selfcheck/v1 | market-required/v1 |
|---|---:|---:|
| `pass` | 0 | 2（不具市场适格性） |
| `reject` | 1 | 2 |
| `blocked` | 2 | 2 |
| 写不出有效 receipt / receipt 无效 | 3 | 3 |

## cordis 入口解析（load-put 场景）

`load-put` 探针需要真实 cordis。解析顺序：

1. 显式传参 `opts.cordisEntry`
2. 环境变量 `DSH_TESTBED_CORDIS_ENTRY`（本地路径或 file:// URL）
3. 从本包位置向上解析 `cordis`——装进 DSH 宿主时命中的就是宿主自带的那份
4. 都没有 → `load-put` 场景 fail-closed，报错里带可操作指引（其余场景不受影响）

此前开发者机器的绝对路径（file:///D:/deepseek-harness/...）导致 fresh clone 的
M3 集成测试与 host 单测必然失败，已改为上述解析链。

## 开发

```bash
npm install cordis@4.0.0-rc.11 --no-save   # 独立跑 load-put 测试用（宿主内无需）
node --test "tests/**/*.test.js"
```

架构、开发、契约与验收文档只在本地维护，不随本仓库分发。
