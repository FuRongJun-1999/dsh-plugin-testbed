/**
 * Tool artifact: report what credential-ish ambient variables the tool child can
 * observe. The worker must pass only a minimal environment, so both values must
 * be null even when the parent test process carries them.
 */
export async function run() {
  return {
    fake_secret: typeof process.env.DSH_TESTBED_FAKE_SECRET === 'string' ? process.env.DSH_TESTBED_FAKE_SECRET : null,
    openai_key: typeof process.env.OPENAI_API_KEY === 'string' ? process.env.OPENAI_API_KEY : null,
    node_no_warnings: typeof process.env.NODE_NO_WARNINGS === 'string' ? process.env.NODE_NO_WARNINGS : null,
  }
}
