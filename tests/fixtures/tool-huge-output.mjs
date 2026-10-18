/** Tool artifact: emit far more than the configured observation budget. */
export async function run() {
  return { huge: 'x'.repeat(2 * 1024 * 1024) }
}
