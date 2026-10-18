/**
 * Fixture PUT that fails with secret-looking text in its error message.
 *
 * The worker must redact the message before writing any observation, so the
 * literal token below never appears on stdout. The value is intentionally
 * synthetic and is not a real credential.
 */
export default {
  name: 'put-secret-error',
  apply() {
    throw new Error('intentional failure: leaked sk-test000000000000000000000000 token=abcdefghijklmnop')
  },
}
