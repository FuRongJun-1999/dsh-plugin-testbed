/**
 * Shared durable-scheduler type model (TypeScript migration phase).
 *
 * The trust boundary accepts `unknown`; every validator narrows explicitly with
 * predicates from `lease.ts`. No `any`, no `@ts-ignore`: the only casts are
 * documented schema assertions over SQLite rows (whose shape is created by the
 * versioned DDL in `store.ts`).
 *
 * @module @deepseek-ai/dsh-plugin-testbed/scheduler/types
 */
export {};
