/**
 * DSH bundle 入口：单安装入口，只注册显式本地自检工具，不在 apply 中执行任何自检，不读写凭据。
 * 契约对齐 packages/extensions/tool-cordis 的 name/inject/apply 形态。
 */
import { defineTool } from '@deepseek-ai/dsh-tools'
import { runSelfCheck } from './src/index.js'

export const name = 'plugin-testbed'
export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'plugin_selfcheck',
    description:
      'Run an explicit local self-check for a developer-owned DSH plugin (PUT). It freezes a test '
      + 'plan, runs a trusted gate kernel over in-process observations, and emits a local-only '
      + 'receipt/v1 with a recomputable SHA-256 digest. This is NOT market gate; trust_scope is '
      + 'always local-only and market_eligible is always false. Pass a run-spec/v1 `spec` object.',
    parameters: {
      spec: {
        type: 'json',
        required: true,
        description: 'run-spec/v1: schema_version, target, scenario.cases (test_id/node_id/classification/criteria/probe), profile_ref, policy_ref.',
      },
      profile: {
        type: 'string',
        description: 'Exit-code profile. local-selfcheck/v1 (default) or market-required/v1.',
        enum: ['local-selfcheck/v1', 'market-required/v1'],
      },
      receipt_out: {
        type: 'string',
        description: 'Directory to write the receipt. Default: .dsh-testbed-receipts.',
      },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args, exec) {
      return runSelfCheck(args.spec, {
        profile: args.profile,
        receiptOutDir: args.receipt_out,
        signal: exec?.signal,
      })
    },
  }))
}