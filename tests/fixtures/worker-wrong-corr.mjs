/**
 * 错配 correlation worker fixture（control-protocol/v1 预期协议）。
 *
 * 行为：收到 request 后先回一条 **correlation 正确** 的 `started` 帧（可核验开始事件），
 * 再回一条 **request_id 故意错配** 的 `response` 帧。用于验证适配器「response 必须原样
 * 回显 correlation tuple」：`frame.request_id !== req.request_id` → `correlation-mismatch`
 * （且 invocation_status 依 started 帧判定为 'started'）。
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

  // 1) 先回正确 correlation 的 started 帧（让 invocation 可核验为 started）。
  process.stdout.write(JSON.stringify({
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'started',
    ...correlationOf(frame),
  }) + '\n')

  // 2) 再回 request_id 故意错配的 response 帧。
  process.stdout.write(JSON.stringify({
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'response',
    ...correlationOf(frame),
    request_id: 'req-WRONG-' + frame.request_id, // 故意错配 request_id
    execution_status: 'completed',
    observations: [{ observation_id: 'obs-1', value: { status: 'ok' }, source: 'worker', limitations: [] }],
    reason_codes: [],
  }) + '\n')
})