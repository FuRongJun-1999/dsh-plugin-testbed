/**
 * Canonical protocol type model — migration phase `protocol/types`.
 *
 * This module is the single source of *types* for the versioned protocol
 * artifacts. It is type-only at runtime (elided from the emitted JavaScript),
 * so importing it can never change runtime behavior, and it carries no
 * credentials, verdicts or gate authority.
 *
 * The model deliberately separates:
 *   - JSON domain values (`JsonValue`) from loose `unknown` input at the trust
 *     boundary: every validator accepts `unknown` and narrows explicitly;
 *   - closed protocol vocabularies (`RunStatus`, `Verdict`, `GateDecision`, ...)
 *     re-exported from `enums.ts`, so an enum can never be widened in one place;
 *   - validation/check results (`ValidationResult`, `CheckResult`), keeping the
 *     fail-closed `{ ok: false, errors }` / `{ ok: false, reason_code }` shapes
 *     explicit instead of implicit `any`.
 *
 * Types only — no runtime exports, no `any`, no `@ts-ignore`.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/protocol/types
 */
export {};
