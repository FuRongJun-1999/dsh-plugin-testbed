/**
 * 最小临时 worker fixture（control-protocol/v1，CONTRACT-m2 §2 预期协议）。
 *
 * 仅用于 `src/adapters/subprocess.js` 的传输/回收单测，在 worker-owner 的 `src/worker/host.js`
 * 落盘前作为其替身；协议行为与 host.js 预期一致（echo/error/sleep + started 先行）。
 *
 * 顶部声明：这是 L1 子进程内建 smoke 能力，不是用户工具、不执行 PUT、不使用 `node:vm`；
 * `started` 帧是「可核验调用开始事件」的 worker 侧来源。
 */
import { createInterface } from 'node:readline'
import { assertFrameShape, CONTROL_PROTOCOL_VERSION } from '../../src/protocol/transport.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function emit(frame) {
  process.stdout.write(JSON.stringify(frame) + '\n')
}

function correlationOf(f) {
  return {
    request_id: f.request_id,
    run_id: f.run_id,
    plan_id: f.plan_id,
    test_id: f.test_id,
    attempt: f.attempt,
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })

rl.on('line', async (line) => {
  let frame
  try {
    frame = JSON.parse(line)
  } catch {
    return // 非法 JSON 行：忽略
  }
  const shape = assertFrameShape(frame)
  if (!shape.ok || frame.kind !== 'request') {
    // 非法/未知帧 → 尽力回一条 response error（reason_code = shape.reason_code 或 worker-error）
    emit({
      protocol_version: CONTROL_PROTOCOL_VERSION,
      kind: 'response',
      ...(frame && typeof frame.request_id === 'string'
        ? correlationOf(frame)
        : { request_id: '', run_id: '', plan_id: '', test_id: '', attempt: 0 }),
      execution_status: 'error',
      observations: [],
      reason_codes: [shape.reason_code ?? 'worker-error'],
    })
    return
  }

  const corr = correlationOf(frame)
  // 先 emit started（可核验调用开始事件），再执行内建 op。
  emit({ protocol_version: CONTROL_PROTOCOL_VERSION, kind: 'started', ...corr })

  const op = frame.input?.op ?? 'echo'
  const delay_ms = Number(frame.input?.delay_ms ?? 0)
  if (delay_ms > 0) await sleep(delay_ms)

  if (op === 'error') {
    emit({
      protocol_version: CONTROL_PROTOCOL_VERSION,
      kind: 'response',
      ...corr,
      execution_status: 'error',
      observations: [],
      reason_codes: ['worker-error'],
    })
    return
  }

  // echo（含 sleep 后的 echo）
  emit({
    protocol_version: CONTROL_PROTOCOL_VERSION,
    kind: 'response',
    ...corr,
    execution_status: 'completed',
    observations: [{
      observation_id: 'obs-1',
      value: frame.input?.value,
      source: 'worker',
      limitations: ['l1-subprocess'],
    }],
    reason_codes: [],
  })
})