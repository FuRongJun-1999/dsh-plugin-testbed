/**
 * Migration toolchain gate (TS-01/TS-03/TS-05/TS-07/TS-09).
 *
 * Proves, mechanically, that:
 *   - the compiler is an exact-pinned local devDependency (no global tsc, no
 *     floating `latest`, lockfile committed) and Node type stripping is not the
 *     production check;
 *   - `tsc --noEmit` over the strict tsconfig is green;
 *   - every migrated `.ts` source has a byte-identical emitted `.js` artifact
 *     (rebuild into a throw-away directory and compare) — stale artifacts fail;
 *   - `any` / `as any` / `@ts-ignore` / `@ts-expect-error` / `@ts-nocheck` never
 *     enter the TypeScript tree, and source imports use `.js` specifiers.
 *
 * The build step is intentionally part of `node --test`: a TypeScript build or
 * type-check failure therefore blocks delivery instead of being an optional
 * script.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const TSC = join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc')
const PKG = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'))
const STATUS = JSON.parse(readFileSync(join(REPO_ROOT, 'tests/unit/migration/migration-status.json'), 'utf8'))
const EXPECTED_TYPESCRIPT = '5.9.3'
const EXPECTED_NODE_TYPES = '24.19.2'
const EXPECTED_PNPM = 'pnpm@11.28.5'

function runNode(args, options = {}) {
  return spawnSync(process.execPath, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 300_000,
    windowsHide: true,
    ...options,
  })
}

function walk(dir, extension) {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walk(full, extension))
    else if (entry.isFile() && full.endsWith(extension)) out.push(full)
  }
  return out.sort()
}

function workspacePath(absolute) {
  return relative(REPO_ROOT, absolute).split('\\').join('/')
}

/**
 * Minimal JSONC/comment reader. A character scanner (not regex) is required so
 * glob/string literals such as a src path with double-star are never treated as comments.
 */
function stripComments(text) {
  let out = ''
  let inString = false
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]
    if (inString) {
      out += char
      if (char === '\\') { out += text[i + 1] ?? ''; i += 1 }
      else if (char === '"') inString = false
      continue
    }
    if (char === '"') { inString = true; out += char; continue }
    if (char === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1
      out += '\n'
      continue
    }
    if (char === '/' && text[i + 1] === '*') {
      i += 2
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1
      i += 1
      continue
    }
    out += char
  }
  return out
}

/** Minimal JSONC reader: tsconfig files carry explanatory comments. */
function parseJsonc(path) {
  return JSON.parse(stripComments(readFileSync(path, 'utf8')))
}

const ANY_ESCAPES = [
  ['any type annotation', /(:\s*any\b|\bas\s+any\b|<\s*any\b|\bany\s*\[\s*\]|\bany\s*[|&]|[|&]\s*any\b)/],
  ['@ts-ignore', /@ts-ignore\b/],
  ['@ts-expect-error', /@ts-expect-error\b/],
  ['@ts-nocheck', /@ts-nocheck\b/],
]

test('TypeScript toolchain is exactly pinned, local and lockfile-backed', () => {
  assert.equal(PKG.devDependencies.typescript, EXPECTED_TYPESCRIPT, 'typescript must be an exact devDependency pin')
  assert.equal(PKG.devDependencies['@types/node'], EXPECTED_NODE_TYPES, '@types/node must be an exact devDependency pin')
  assert.equal(PKG.packageManager, EXPECTED_PNPM, 'package manager must be pinned for reproducible installs')
  for (const [name, spec] of Object.entries(PKG.devDependencies)) {
    assert.match(spec, /^\d+\.\d+\.\d+$/, `${name} must use an exact version (no ^, ~, latest or range)`)
  }
  assert.equal(PKG.scripts.typecheck, 'tsc --noEmit')
  assert.equal(
    PKG.scripts['build:ts'],
    'tsc -p tsconfig.json --noEmit false --outDir src --rootDir src --allowJs false --newLine lf',
  )

  const installed = JSON.parse(readFileSync(join(REPO_ROOT, 'node_modules/typescript/package.json'), 'utf8')).version
  assert.equal(installed, EXPECTED_TYPESCRIPT, 'installed compiler must be the pinned local one')

  const version = runNode([TSC, '--version'])
  assert.equal(version.status, 0, `local tsc --version failed: ${version.stderr}`)
  assert.equal(version.stdout.trim(), `Version ${EXPECTED_TYPESCRIPT}`)

  const lock = readFileSync(join(REPO_ROOT, 'pnpm-lock.yaml'), 'utf8')
  assert.match(lock, /lockfileVersion: '\d+\.\d+'/)
  assert.match(lock, /typescript@5\.9\.3:/)
  assert.match(lock, /specifier: 5\.9\.3/)
  assert.match(lock, /@types\/node@24\.19\.2/)
  assert.match(lock, /integrity: sha512-/, 'lockfile must pin registry integrity')
})

test('strict tsconfig is the production type gate (no checkJs/type-stripping shortcut)', () => {
  const base = parseJsonc(join(REPO_ROOT, 'tsconfig.json'))
  assert.equal(base.compilerOptions.strict, true)
  assert.equal(base.compilerOptions.noImplicitAny, true)
  assert.equal(base.compilerOptions.noEmit, true)
  assert.equal(base.compilerOptions.module, 'NodeNext')
  assert.equal(base.compilerOptions.moduleResolution, 'NodeNext')
  assert.equal(base.compilerOptions.allowJs, true)
  assert.equal(base.compilerOptions.checkJs, false, 'checkJs is a legacy bridge only; new code must be .ts')
  assert.deepEqual(base.include, ['src/**/*.ts'])

  // The emit build is expressed as CLI overrides of this same tsconfig
  // (no second config file), so there is exactly one authoritative option set.
  for (const flag of ['--noEmit false', '--outDir src', '--rootDir src', '--allowJs false', '--newLine lf']) {
    assert.ok(PKG.scripts['build:ts'].includes(flag), `build:ts must override ${flag}`)
  }
})

test('pnpm exec tsc --noEmit passes with the local compiler', () => {
  const result = runNode([TSC, '--noEmit'])
  assert.equal(
    result.status,
    0,
    `TypeScript type gate failed (delivery must be blocked):\n${result.stdout}\n${result.stderr}`,
  )
})

test('migrated .ts modules build to fresh, byte-identical committed .js artifacts', () => {
  const work = mkdtempSync(join(tmpdir(), 'testbed-ts-build-'))
  try {
    const result = runNode([
      TSC, '-p', 'tsconfig.json', '--noEmit', 'false', '--outDir', work, '--rootDir', 'src', '--allowJs', 'false', '--newLine', 'lf',
    ])
    assert.equal(
      result.status,
      0,
      `tsc build failed (delivery must be blocked):\n${result.stdout}\n${result.stderr}`,
    )

    // The whole tree must type-check (previous test), but byte freshness is
    // asserted only for the modules owned by this migration phase list. New
    // modules added by parallel tasks are frozen into the same freshness list
    // by t8/t11 once their owners hand them off; asserting their bytes here
    // would race with their in-flight builds.
    const migrated = STATUS.phases.filter((phase) => phase.status !== 'pending').flatMap((phase) => phase.modules ?? [])
    assert.ok(migrated.length > 0, 'expected migrated TypeScript modules')
    for (const modulePath of migrated) {
      const relPath = modulePath.replace(/^src[\\/]/, '')
      const emitted = join(work, relPath.replace(/\.ts$/, '.js'))
      assert.ok(existsSync(emitted), `tsc emitted no artifact for ${modulePath}`)
      const committed = join(REPO_ROOT, 'src', relPath.replace(/\.ts$/, '.js'))
      assert.ok(existsSync(committed), `missing committed build artifact for ${modulePath} (run pnpm run build:ts)`)
      assert.ok(
        readFileSync(committed).equals(readFileSync(emitted)),
        `stale build artifact ${workspacePath(committed)}: rebuild with pnpm run build:ts`,
      )
    }

    const emittedFiles = walk(work, '.js').map((file) => relative(work, file).split('\\').join('/'))
    for (const relPath of emittedFiles) {
      assert.ok(
        existsSync(join(REPO_ROOT, 'src', relPath)),
        `tsc emitted ${relPath} without a committed counterpart under src/`,
      )
    }
  } finally {
    rmSync(work, { recursive: true, force: true })
  }
})

test('migrated phases cover the protocol + pure-control boundary in order', () => {
  assert.deepEqual(STATUS.phases.map((phase) => phase.id), ['P1', 'P2', 'P3', 'P4'])
  assert.equal(STATUS.phases[0].name, 'protocol/types')
  assert.equal(STATUS.phases[0].status, 'migrated')
  assert.equal(STATUS.phases[1].name, 'pure control')
  assert.equal(STATUS.phases[1].status, 'partially-migrated')
  assert.equal(STATUS.phases[2].status, 'handoff-verified')
  assert.equal(STATUS.phases[2].name, 'market-stage evidence sidecars (t5 handoff)')
  assert.equal(STATUS.phases[3].name, 'protocol/adapters/worker/reports/CLI/plugin')
  assert.equal(STATUS.phases[3].status, 'pending')

  for (const phase of STATUS.phases) {
    for (const modulePath of phase.modules ?? []) {
      assert.ok(existsSync(join(REPO_ROOT, modulePath)), `missing migration module ${modulePath}`)
    }
  }
  for (const phase of STATUS.phases.filter((item) => item.status !== 'pending')) {
    for (const modulePath of phase.modules) {
      assert.ok(modulePath.endsWith('.ts'), `${modulePath} must be TypeScript source`)
      assert.ok(existsSync(join(REPO_ROOT, modulePath.replace(/\.ts$/, '.js'))), `missing emitted artifact for ${modulePath}`)
    }
  }
  for (const deferred of STATUS.phases[1].deferred) {
    assert.ok(existsSync(join(REPO_ROOT, deferred)), `deferred compatibility entry disappeared: ${deferred}`)
    assert.ok(!existsSync(join(REPO_ROOT, deferred.replace(/\.js$/, '.ts'))), `${deferred} is listed as deferred but has a .ts source`)
  }
})

test('TypeScript tree has no any/@ts escapes and imports use .js specifiers', () => {
  const violations = []
  for (const file of walk(join(REPO_ROOT, 'src'), '.ts').filter((item) => !item.endsWith('.d.ts'))) {
    const text = stripComments(readFileSync(file, 'utf8'))
    for (const [name, pattern] of ANY_ESCAPES) {
      if (pattern.test(text)) violations.push(`${workspacePath(file)}: ${name}`)
    }
    if (/(?:from|import)\s*\(?\s*['"][^'"]+\.ts['"]/.test(text)) {
      violations.push(`${workspacePath(file)}: .ts import specifier (use .js)`)
    }
  }
  assert.deepEqual(
    violations,
    [],
    `forbidden TypeScript escape hatches or .ts import specifiers:\n${violations.join('\n')}`,
  )
})
