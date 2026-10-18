#!/usr/bin/env node
/**
 * 本地自检 CLI：`selfcheck`（跑自检）+ `project`（receipt 只读投影）+
 * `market`（独立市场门禁，fail-closed；当前环境只能输出 blocked/non-eligible）。
 * 参数数组解析，无 shell 拼接。运行时锚点只能由部署方显式注入（无硬编码路径）。
 */
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { runSelfCheck, projectAll, runMarketGate, describeSchedulerEntry } from '../src/index.js'

function parseArgs(argv) {
  const args = {
    spec: null,
    profile: 'local-selfcheck/v1',
    receiptOut: '.dsh-testbed-receipts',
    overwrite: false,
    receipt: null,
    format: 'junit,tap,html,ci-summary',
    executionMode: 'in-process',
    runtimeAnchor: undefined,
    timeoutMs: undefined,
    probeTime: undefined,
  }
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]
    if (a === '--spec') args.spec = argv[++i]
    else if (a === '--profile') args.profile = argv[++i]
    else if (a === '--execution-mode') args.executionMode = argv[++i]
    else if (a === '--receipt-out') args.receiptOut = argv[++i]
    else if (a === '--overwrite') args.overwrite = true
    else if (a === '--receipt') args.receipt = argv[++i]
    else if (a === '--format') args.format = argv[++i]
    else if (a === '--runtime-anchor') args.runtimeAnchor = argv[++i]
    else if (a === '--timeout-ms') args.timeoutMs = Number(argv[++i])
    else if (a === '--probe-time') args.probeTime = argv[++i]
  }
  return args
}

function parseRuntimeAnchor(value) {
  if (value === undefined) return undefined
  const trimmed = value.trim()
  if (trimmed.startsWith('{')) return trimmed // inline worker-descriptor JSON
  // A path to an anchor descriptor is passed through; runSelfCheck/worker resolve it.
  return trimmed
}

const MARKET_ARG_KEYS = Object.freeze({
  '--receipt': 'receipt',
  '--policy': 'policy',
  '--runtime-anchor': 'runtimeAnchor',
  '--runtime-base-dir': 'runtimeBaseDir',
  '--contract-evidence-dir': 'contractEvidenceDir',
  '--isolation-attestation': 'isolationAttestation',
  '--isolation-execution-evidence': 'isolationAttestation',
  '--a2-evidence': 'a2Evidence',
  '--host-facts': 'hostFacts',
  '--approvals': 'approvals',
  '--waivers': 'waivers',
  '--scheduler-evidence': 'schedulerEvidence',
  '--evidence-out': 'evidenceOut',
  '--verifier-id': 'verifierId',
  '--control-plane-id': 'controlPlaneId',
  '--control-plane-version': 'controlPlaneVersion',
  '--now': 'now',
})

function parseMarketArgs(argv) {
  const args = {
    receipt: null,
    policy: null,
    runtimeAnchor: null,
    runtimeBaseDir: null,
    contractEvidenceDir: null,
    isolationAttestation: null,
    a2Evidence: null,
    hostFacts: null,
    approvals: null,
    waivers: null,
    schedulerEvidence: null,
    evidenceOut: null,
    verifierId: null,
    controlPlaneId: null,
    controlPlaneVersion: null,
    now: null,
    unknown: [],
  }
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]
    const key = MARKET_ARG_KEYS[flag]
    if (key === undefined) {
      args.unknown.push(flag)
      continue
    }
    const value = argv[i + 1]
    if (value === undefined || value.startsWith('--')) {
      args.unknown.push(flag)
      continue
    }
    args[key] = value
    i += 1
  }
  return args
}

const SCHEDULER_ARG_KEYS = Object.freeze({
  '--enable-policy': 'enablePolicy',
  '--authorization': 'authorization',
  '--store': 'store',
  '--owner-id': 'ownerId',
})

function parseSchedulerArgs(argv) {
  const args = { enablePolicy: null, authorization: null, store: null, ownerId: null, unknown: [] }
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]
    const key = SCHEDULER_ARG_KEYS[flag]
    if (key === undefined) {
      args.unknown.push(flag)
      continue
    }
    const value = argv[i + 1]
    if (value === undefined || value.startsWith('--')) {
      args.unknown.push(flag)
      continue
    }
    args[key] = value
    i += 1
  }
  return args
}

async function readJsonFile(path) {
  return JSON.parse(await readFile(resolve(path), 'utf8'))
}

async function schedulerCommand(argvSlice) {
  const args = parseSchedulerArgs(argvSlice)
  if (args.unknown.length > 0) {
    console.error(`unknown or incomplete scheduler arguments: ${args.unknown.join(', ')}`)
    console.error(
      'usage: node bin/selfcheck.js scheduler [--enable-policy <policy.json> '
      + '--authorization <authorization.json> --store <scheduler.sqlite> [--owner-id <id>]]',
    )
    process.exit(3)
  }
  if (args.enablePolicy === null && args.authorization === null && args.store === null) {
    const status = describeSchedulerEntry()
    console.log(JSON.stringify(status, null, 2))
    process.exit(2)
  }
  if (args.enablePolicy === null || args.authorization === null || args.store === null) {
    console.error(
      'scheduler enable requires all of --enable-policy, --authorization and --store; '
      + 'scheduling stays disabled/blocked',
    )
    process.exit(3)
  }
  let policy
  let authorization
  try {
    policy = await readJsonFile(args.enablePolicy)
    authorization = await readJsonFile(args.authorization)
  } catch (error) {
    console.error(`scheduler input unreadable: ${error?.message ?? String(error)}`)
    process.exit(3)
  }
  const status = describeSchedulerEntry({
    enabled: true,
    policy,
    authorization,
    storePath: args.store,
    ownerId: args.ownerId ?? 'scheduler-entry',
  })
  console.log(JSON.stringify(status, null, 2))
  process.exit(status.status === 'enabled' ? 0 : 2)
}

const argv = process.argv.slice(2)

if (argv[0] === 'scheduler') {
  await schedulerCommand(argv.slice(1))
}

if (argv[0] === 'market') {
  const args = parseMarketArgs(argv.slice(1))
  if (args.unknown.length > 0) {
    console.error(`unknown or incomplete market arguments: ${args.unknown.join(', ')}`)
    console.error(
      'usage: node bin/selfcheck.js market --receipt <receipt.json> --policy <policy.json> '
      + '[--runtime-anchor <anchor.json>] [--runtime-base-dir <dir>] [--contract-evidence-dir <dir>] '
      + '[--isolation-attestation <json>|--isolation-execution-evidence <json>] [--a2-evidence <json>] '
      + '[--host-facts <json>] [--approvals <json>] [--waivers <json>] [--scheduler-evidence <json>] '
      + '[--evidence-out <dir>] [--verifier-id <id>] [--control-plane-id <id>] '
      + '[--control-plane-version <version>] [--now <iso>]',
    )
    process.exit(3)
  }
  if (!args.receipt) {
    console.error('usage: node bin/selfcheck.js market --receipt <receipt.json> --policy <policy.json> [...]')
    process.exit(3)
  }
  const options = {
    receipt: args.receipt,
    policy: args.policy,
    runtimeAnchor: args.runtimeAnchor ?? undefined,
    runtimeBaseDir: args.runtimeBaseDir ?? undefined,
    contractEvidenceDir: args.contractEvidenceDir ?? undefined,
    isolationAttestation: args.isolationAttestation ?? undefined,
    a2Evidence: args.a2Evidence ?? undefined,
    hostFacts: args.hostFacts ?? undefined,
    approvals: args.approvals ?? undefined,
    waivers: args.waivers ?? undefined,
    schedulerEvidence: args.schedulerEvidence ?? undefined,
    evidenceOutDir: args.evidenceOut ?? undefined,
    verifierId: args.verifierId ?? undefined,
    controlPlane: args.controlPlaneId
      ? { id: args.controlPlaneId, version: args.controlPlaneVersion ?? '1.0.0' }
      : undefined,
    now: args.now ?? undefined,
  }
  try {
    const result = await runMarketGate(options)
    console.log(JSON.stringify(result, null, 2))
    process.exit(result.exit_code)
  } catch (error) {
    console.error(`market-gate-internal-error: ${error?.message ?? String(error)}`)
    process.exit(3)
  }
}

const verb = argv[0] === 'project' ? 'project' : 'selfcheck'
const args = parseArgs(argv.slice(1))

if (verb === 'project') {
  if (!args.receipt) {
    console.error('usage: node bin/selfcheck.js project --receipt <receipt.json> [--format junit,tap,html,ci-summary]')
    process.exit(3)
  }
  const receipt = JSON.parse(await readFile(resolve(args.receipt), 'utf8'))
  const out = projectAll(receipt, 'cli')
  for (const f of args.format.split(',').map((s) => s.trim()).filter((f) => out[f])) {
    console.log(`=== ${f} ===\n${out[f].body}\n`)
  }
  process.exit(0)
}

if (!args.spec) {
  console.error(
    'usage: node bin/selfcheck.js selfcheck --spec <path.json> [--profile <p>] [--execution-mode in-process|subprocess] '
    + '[--runtime-anchor <descriptor-json|path>] [--timeout-ms <n>] [--probe-time <iso>] [--receipt-out <dir>] [--overwrite]',
  )
  process.exit(3)
}
const spec = JSON.parse(await readFile(resolve(args.spec), 'utf8'))
const result = await runSelfCheck(spec, {
  profile: args.profile,
  receiptOutDir: args.receiptOut,
  overwrite: args.overwrite,
  executionMode: args.executionMode,
  runtimeAnchor: parseRuntimeAnchor(args.runtimeAnchor),
  timeoutMs: Number.isSafeInteger(args.timeoutMs) && args.timeoutMs > 0 ? args.timeoutMs : undefined,
  probeTime: args.probeTime,
})
console.log(JSON.stringify(result, null, 2))
process.exit(result.exitCode)
