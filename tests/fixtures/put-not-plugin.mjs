/**
 * Fixture PUT that exports a non-plugin value. `Context.plugin(42)` must be
 * rejected by the host/probe instead of being treated as a loaded PUT.
 */
export default 42
