/**
 * Receipt persistence: temp file + atomic rename (architecture §11.2.1;
 * plugin-reports §6.3 idempotency). Synchronous `node:fs` so the kernel's
 * synchronous `finish()` can consume `{path, recordDigest}` directly.
 * @module @deepseek-ai/dsh-plugin-testbed/reports/receipt
 */
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'
import path from 'node:path'

/**
 * Persist a receipt/v1 atomically.
 *
 * @param {object} receipt built by `reports/shape.js` (has `run_id` + `integrity.record_digest`)
 * @param {string} dir destination directory
 * @param {{overwrite?: boolean}} [opts]
 * @returns {{path:string, recordDigest:string|null}}
 */
export function persistReceipt(receipt, dir, opts = {}) {
  const overwrite = opts.overwrite ?? false
  if (!receipt || typeof receipt !== 'object') throw new Error('persistReceipt: receipt required')

  const recordDigest = receipt?.integrity?.record_digest ?? null
  const outDir = dir ?? '.'
  mkdirSync(outDir, { recursive: true })

  const runId = typeof receipt.run_id === 'string' ? receipt.run_id : 'run'
  const target = path.join(outDir, `${runId}.json`)

  let fileExists = false
  let existingDigest = null
  try {
    existingDigest = JSON.parse(readFileSync(target, 'utf8'))?.integrity?.record_digest ?? null
    fileExists = true
  } catch (err) {
    if (err.code !== 'ENOENT') {
      // unreadable / non-JSON existing file: treat as a differing receipt.
      fileExists = true
      existingDigest = null
    }
  }

  // Same name exists, digest differs, and no overwrite → refuse (atomicity guarded).
  if (fileExists && !overwrite && existingDigest !== recordDigest) {
    throw new Error(`persistReceipt: existing receipt differs (overwrite=false): ${target}`)
  }

  const tmp = path.join(outDir, `.${runId}.${process.pid}.${Date.now().toString(36)}.tmp`)
  writeFileSync(tmp, JSON.stringify(receipt, null, 2) + '\n', 'utf8')
  renameSync(tmp, target)

  return { path: target, recordDigest }
}