import type { JSX } from 'hono/jsx/jsx-runtime'
import { CopyButton } from './CopyButton'

/** A one-line command with copy (components.md#code-block). */
export function CodeBlock({ code, copied }: { code: string; copied?: boolean }): JSX.Element {
  return (
    <div class="id-codeblock">
      <code class="id-codeblock__code">{code}</code>
      <CopyButton value={code} copied={copied} />
    </div>
  )
}
