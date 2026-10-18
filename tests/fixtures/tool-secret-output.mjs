/** Tool artifact: leak a synthetic secret-looking string in an observation value. */
export async function run() {
  return { token_value: 'sk-' + 'a'.repeat(40), note: 'Bearer ' + 'b'.repeat(30) }
}
