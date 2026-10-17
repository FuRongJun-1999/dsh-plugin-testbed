/**
 * 公共门面：对外只暴露 runSelfCheck（DSH 工具入口、CI、开发者脚本共享同一实现）。
 * @module @deepseek-ai/dsh-plugin-testbed
 */
export { runSelfCheck } from './kernel.js'
export { canonicalJson, sha256Hex, recordDigest, verifyRecordDigest, FIXED_VECTOR_INPUT, FIXED_VECTOR_DIGEST } from './protocol/digest.js'
export { project, projectAll, PROJECT_FORMATS } from './reports/project/index.js'