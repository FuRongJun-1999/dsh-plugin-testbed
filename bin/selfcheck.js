#!/usr/bin/env node
/**
 * 本地自检 CLI：`selfcheck`（跑自检）+ `project`（receipt 只读投影）。
 * 参数数组解析，无 shell 拼接。
 */
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { runSelfCheck, projectAll } from '../src/index.js'

function parseArgs(argv) {
  const args = { spec: null, profile: 'local-selfcheck/v1', receiptOut: '.dsh-testbed-receipts', overwrite: false, receipt: null, format: 'junit,tap,html,ci-summary', executionMode: 'in-process' }
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]
    if (a === '--spec') args.spec = argv[++i]
    else if (a === '--profile') args.profile = argv[++i]
    else if (a === '--execution-mode') args.executionMode = argv[++i]
    else if (a === '--receipt-out') args.receiptOut = argv[++i]
    else if (a === '--overwrite') args.overwrite = true
    else if (a === '--receipt') args.receipt = argv[++i]
    else if (a === '--format') args.format = argv[++i]
  }
  return args
}

const argv = process.argv.slice(2)
const verb = argv[0] === 'project' ? 'project' : 'selfcheck'
const args = parseArgs(argv.slice(1))

if (verb === 'project') {
  if (!args.receipt) {
    console.error('usage: node bin/selfcheck.js project --receipt <receipt.json> [--format junit,tap,html,ci-summary]')
    process.exit(3)
  }
  const receipt = JSON.parse(await readFile(resolve(args.receipt), 'utf8'))
  const out = projectAll(receipt, 'cli')
  for (const f of args.format.split(',').map(s => s.trim()).filter(f => out[f])) {
    console.log(`=== ${f} ===\n${out[f].body}\n`)
  }
  process.exit(0)
}

if (!args.spec) {
  console.error('usage: node bin/selfcheck.js selfcheck --spec <path.json> [--profile <p>] [--receipt-out <dir>] [--overwrite]')
  process.exit(3)
}
const spec = JSON.parse(await readFile(resolve(args.spec), 'utf8'))
const result = await runSelfCheck(spec, {
  profile: args.profile,
  receiptOutDir: args.receiptOut,
  overwrite: args.overwrite,
  executionMode: args.executionMode,
})
console.log(JSON.stringify(result, null, 2))
process.exit(result.exitCode)