/** Tool artifact: wait long enough for the worker deadline to cancel it. */
export async function run() {
  await new Promise((resolve) => setTimeout(resolve, 5000))
  return { finished: true }
}
