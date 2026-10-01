# CLI login output

Mock: `../mocks/screens/4a-cli-terminal.html`.

This applies to `id.org.ai login` (this repo, `src/sdk/cli/`) and is the text spec for the auto.dev and headless.ly CLIs, which live in their own repos.

```
$ npx auto.dev login

  auto.dev  ·  sign in with id.org.ai

  Code     WDJB-MJHT
  Confirm  https://id.org.ai/device?code=WDJB-MJHT
           Opened in your browser.  c copy link   o open again

  ⠋ Waiting for you to confirm in the browser  ·  expires in 29:52

  ✓ Signed in as Bryant Skarda <bryant@driv.ly>
    Workspace  Drivly
    Stored in  macOS Keychain · auto.dev
    Switch     auto.dev login --account
```

## Rules

**Indentation and alignment**
- Indent every line by 2 spaces.
- Labels are left-aligned in a 9-character column (`Code     `, `Confirm  `).
- Success detail lines are indented 4 spaces, with labels in an 11-character column.

**Colour (when stdout is a TTY)**

| Text | Style |
|---|---|
| Prompt `$` | dim |
| App name | bold |
| `·  sign in with id.org.ai` | dim |
| Labels | dim |
| Code | bold |
| URL | normal |
| Hint keys (`c`, `o`) | normal |
| Hint words | dim |
| Spinner line | normal |
| Expiry | dim |
| `✓` line | normal |
| Email in `<>` | dim |

- Respect `NO_COLOR`.
- When not a TTY, print plain text without the spinner or key hints.

**Behaviour**
- **Code**: the user code in `XXXX-XXXX` form.
- **Confirm URL**: `verification_uri_complete` with the code. Open it in the default browser right away.
- **Keys**: `c` copies the link to the clipboard and `o` opens it again. Both are active only while waiting.
- **Spinner**: the braille spinner (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`, 80ms). The expiry counts down in mm:ss (29:52).
- **Polling**: follow `interval`, and back off on `slow_down`.

**Outcomes**
- **Success**: the `✓` block. "Stored in" names the credential store actually used. "Switch" shows how to sign in with another account.
- **Denied**: `✗ Sign-in cancelled in the browser.`
- **Expired**: `✗ The code expired. Run {cli} login again.`
- Exit codes: 0 on success, 1 when denied or expired, 2 on usage errors.
