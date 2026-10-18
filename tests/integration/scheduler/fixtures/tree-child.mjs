/**
 * Fixture for durable-cancel tests: spawns a live grandchild and prints its pid,
 * then stays alive so the scheduler has a genuine multi-level process tree to
 * reclaim and confirm through the OS.
 */
import { spawn } from 'node:child_process'

const grandchild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
  stdio: 'ignore',
  windowsHide: true,
})
process.stdout.write(`${grandchild.pid}\n`)
setInterval(() => {}, 1000)
