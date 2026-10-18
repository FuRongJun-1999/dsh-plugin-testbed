/** Tool artifact: echo the input value verbatim (argv/shell-metacharacter test). */
export async function run(input) {
  return { echoed: input.value }
}
