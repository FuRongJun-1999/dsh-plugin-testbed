/**
 * 伪造时间戳 worker fixture（control-protocol/v1 预期协议）。
 *
 * 行为：收到 request 帧后**只回一条 response**（**不发 started 帧**），并在 response 里
 * 夹带假的 `started_at`。用于验证逆向不变量（architecture §9.5 / §16.1 行 8）：
 * 「worker 自报时间戳不构成可核验调用开始事件」——控制面只能凭 `started` 帧写
 * `invocation_status=started`，否则按证据写 `unknown`，不得被假 `started_at` 提升。
 *
 * 顶部声明：这是 L1 子进程内建 smoke 能力替身，不是用户工具、不执行 PUT、不使用 `node:vm`。
 */
import { createInterface } from 'node:readline'
import { CONTROL_PROTOCOL_VERSION } from '../../src/protocol/transport.js'

function correlationOf(f) {
  return {
    request_id: f.request_id,
    run_id: f.run_id,
    plan_id: f.plan_id,
    test_id: f.test_id,
    attempt: f.attempt,
  }
}

const rl = createInterface({ input: process.stdin })

rl.on('line', (line) => {
  let frame
  try {
    frame = JSON.parse(line)
  } catch {
    return // 非法 JSON 行：忽略
  }

  // 只回 response（无 started 帧），并夹带假 started_at —— 适配器应忽略假时间戳、记 unknown。
  process.stdout.write(JSON.stringify({
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'response',
    ...correlationOf(frame),
    execution_status: 'completed',
    started_at: '2026-10-17T00:00:00.000Z', // 伪造时间戳（不可信，应被控制面忽略）
    observations: [{ observation_id: 'obs-1', value: { status_code: 200 }, source: 'worker', limitations: [] }],
    reason_codes: [],
  }) + '\n')
})