/**
 * Complete process-tree reaper used by durable cancel (NEXT-PHASE-REQUIREMENTS
 * SCH-05: "reap 必须等完整进程树"; "未确认 => cancel-not-acknowledged").
 *
 * The reaper is injectable so negative tests can prove that a failed/unconfirmed
 * reap never turns into an acknowledged cancel.
 *
 * The OS primitives below intentionally mirror the canonical, already-accepted
 * `src/adapters/subprocess.js` implementation (Windows `taskkill /T /F` awaited
 * to completion, POSIX process-group SIGTERM→grace→SIGKILL, then an OS-measured
 * PID poll). They are replicated here because the scheduler module is a strict
 * TypeScript source and may not import the still-unmigrated legacy JavaScript
 * adapter from typed code; behavior is covered by the same real-process tests.
 * The report always contains **measured survivors**, never a bare exit code.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/reaper
 */
import { spawn } from 'node:child_process';
const PID_POLL_INTERVAL_MS = 25;
const TASKKILL_TIMEOUT_MS = 3_000;
const DEFAULT_REAP_TIMEOUT_MS = 5_000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** @returns {'taskkill-tree'|'process-group-signal'} OS mechanism in use */
export function reapMechanism() {
    return process.platform === 'win32' ? 'taskkill-tree' : 'process-group-signal';
}
/** OS PID liveness: `EPERM` still means the process exists. */
export function isPidAlive(pid) {
    if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 1)
        return false;
    try {
        process.kill(pid, 0);
        return true;
    }
    catch (err) {
        return err.code === 'EPERM';
    }
}
/** Poll until every given PID is observed gone (bounded, fail-closed). */
export async function waitForPidsGone(pids, options = {}) {
    const targets = [...new Set([...pids])].filter((pid) => Number.isSafeInteger(pid) && pid > 0);
    const deadlineAt = Date.now() + Math.max(0, options.timeoutMs ?? DEFAULT_REAP_TIMEOUT_MS);
    let remaining = targets.filter(isPidAlive);
    while (remaining.length > 0 && Date.now() < deadlineAt) {
        await sleep(PID_POLL_INTERVAL_MS);
        remaining = remaining.filter(isPidAlive);
    }
    return { ok: remaining.length === 0, remaining };
}
/**
 * Windows `taskkill` is an asynchronous child process: wait for it to exit (or be
 * killed on timeout) before trusting any cleanup decision.
 */
async function runTaskkill(pid, options = {}) {
    const tree = options.tree !== false;
    const timeoutMs = options.timeoutMs ?? TASKKILL_TIMEOUT_MS;
    if (process.platform !== 'win32' || !Number.isSafeInteger(pid) || pid < 1)
        return;
    await new Promise((resolveDone) => {
        let settled = false;
        let timer = null;
        let taskkill = null;
        const finish = () => {
            if (settled)
                return;
            settled = true;
            if (timer)
                clearTimeout(timer);
            resolveDone();
        };
        try {
            const args = ['/pid', String(pid), '/F'];
            if (tree)
                args.push('/T');
            taskkill = spawn('taskkill', args, { stdio: 'ignore', windowsHide: true });
        }
        catch {
            finish();
            return;
        }
        timer = setTimeout(() => {
            try {
                taskkill?.kill();
            }
            catch { /* already gone */ }
            finish();
        }, timeoutMs);
        timer.unref?.();
        taskkill.once('error', finish);
        taskkill.once('close', finish);
    });
}
/**
 * Terminate a complete process tree and wait for OS-measured confirmation.
 * Windows: await `taskkill /T /F`, then re-kill known descendants, poll, and do
 * a second pass for re-parented descendants. POSIX: process-group SIGTERM →
 * grace → SIGKILL plus individual known descendants.
 */
export async function terminateProcessTree(pid, options = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_REAP_TIMEOUT_MS;
    const graceMs = options.graceMs ?? 0;
    if (!Number.isSafeInteger(pid) || pid < 1)
        return { ok: true, remaining: [] };
    const known = [...new Set([...options.knownChildPids ?? []])].filter((childPid) => Number.isSafeInteger(childPid) && childPid > 0);
    const targets = [pid, ...known];
    if (process.platform === 'win32') {
        // Must run while the root is still alive so /T can enumerate descendants.
        await runTaskkill(pid, { tree: true });
        for (const target of targets) {
            if (isPidAlive(target))
                await runTaskkill(target, { tree: true });
        }
        let result = await waitForPidsGone(targets, { timeoutMs });
        // Second pass covers descendants re-parented between enumeration and kill.
        if (!result.ok) {
            await runTaskkill(pid, { tree: true });
            for (const target of result.remaining)
                await runTaskkill(target, { tree: true });
            result = await waitForPidsGone(targets, { timeoutMs });
        }
        return result;
    }
    try {
        process.kill(-pid, 'SIGTERM');
    }
    catch { /* group already gone */ }
    for (const target of targets) {
        try {
            process.kill(target, 'SIGTERM');
        }
        catch { /* already gone */ }
    }
    if (graceMs > 0) {
        const graceful = await waitForPidsGone(targets, { timeoutMs: graceMs });
        if (graceful.ok)
            return graceful;
    }
    try {
        process.kill(-pid, 'SIGKILL');
    }
    catch { /* group already gone */ }
    for (const target of targets) {
        try {
            process.kill(target, 'SIGKILL');
        }
        catch { /* already gone */ }
    }
    return waitForPidsGone(targets, { timeoutMs });
}
/** Default OS-measured complete-process-tree reaper. */
export const defaultProcessTreeReaper = async (rootPid, options = {}) => {
    const timeoutMs = Number.isSafeInteger(options.timeoutMs) && options.timeoutMs > 0
        ? options.timeoutMs
        : DEFAULT_REAP_TIMEOUT_MS;
    if (!Number.isSafeInteger(rootPid) || rootPid < 1) {
        return { ok: true, remaining: [], mechanism: 'none' };
    }
    const report = await terminateProcessTree(rootPid, {
        knownChildPids: options.knownChildPids ?? [],
        timeoutMs,
    });
    return { ok: report.ok === true, remaining: [...report.remaining], mechanism: reapMechanism() };
};
/**
 * Wait for a set of PIDs to disappear (used when a runner reported descendant
 * PIDs but the tree root already exited).
 */
export async function waitForTreeGone(pids, options = {}) {
    const report = await waitForPidsGone(pids, { timeoutMs: options.timeoutMs ?? DEFAULT_REAP_TIMEOUT_MS });
    return { ok: report.ok === true, remaining: [...report.remaining], mechanism: 'pid-poll' };
}
