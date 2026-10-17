import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

// 自动化秘密泄漏扫描：仅扫运行时代码（src/、index.js、bin/），不含 tests/ 与 doc。
// 明文私钥/长凭据若出现即 fail；`sha256:<64hex>` 摘要与项目内固定向量不是秘密，不误报。
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const s = statSync(p)
    if (s.isDirectory()) walk(p, acc)
    else if (name.endsWith('.js') || name.endsWith('.yml') || name.endsWith('.json')) acc.push(p)
  }
  return acc
}

const files = [
  ...walk(join(ROOT, 'src')),
  join(ROOT, 'index.js'),
  ...walk(join(ROOT, 'bin')),
]

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b(api[_-]?key|secret|password|access[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"][^'"]{12,}['"]/i,
  /\bsk-[A-Za-z0-9]{20,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
]

test('运行时代码不含硬编码私钥/长凭据', () => {
  const hits = []
  for (const file of files) {
    const text = readFileSync(file, 'utf8')
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i += 1) {
      for (const re of SECRET_PATTERNS) {
        if (re.test(lines[i])) {
          hits.push(`${file}:${i + 1}: ${re.source}`)
        }
      }
    }
  }
  assert.deepEqual(hits, [], `发现疑似硬编码秘密：\n${hits.join('\n')}`)
})

test('运行时文件集合非空（扫描未落空）', () => {
  assert.ok(files.length >= 10, `expected >=10 runtime files, got ${files.length}`)
})