/** Tool artifact: report the working directory the worker gave the child. */
export async function run() {
  return { cwd: process.cwd() }
}
