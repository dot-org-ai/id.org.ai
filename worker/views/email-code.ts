/**
 * Email verification-code page — the fallback a viewer lands on when their
 * Entra tenant refuses to consent to an app it has not approved.
 *
 * Tone matters here. The viewer did nothing wrong and cannot fix their IT
 * policy, so the copy names what happened in one line and immediately offers
 * the thing that works. It never says "error".
 *
 * Server-rendered, no build step, matching worker/views/provider-picker.ts.
 */
import { escapeHtml } from '../utils/html'

export interface EmailCodePageOptions {
  continueUrl: string
  /** FederationErrorKind, or `not-configured`. Shapes the explanatory line. */
  reason?: string
  /** Pre-fill, carried over from the Microsoft login hint. */
  email?: string
  /** Whether to offer "try Microsoft instead". */
  microsoftAvailable: boolean
}

function explain(reason: string | undefined): string | null {
  switch (reason) {
    case 'consent-required':
      return "Your organisation's sign-in policy blocks apps it hasn't pre-approved. No problem — we'll email you a code instead."
    case 'access-denied':
      return "That sign-in didn't complete. You can verify with an emailed code instead."
    case 'invalid-token':
    case 'upstream-error':
      return "Microsoft sign-in didn't complete. You can verify with an emailed code instead."
    case 'not-configured':
      return null
    default:
      return null
  }
}

export function renderEmailCodePage(options: EmailCodePageOptions): Response {
  const { continueUrl, reason, email, microsoftAvailable } = options
  const note = explain(reason)
  const prefill = email && email.includes('@') ? email : ''

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verify your email — id.org.ai</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
      background: #000; color: #fff; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    .container { width: 100%; max-width: 420px; padding: 24px; }
    .brand { font-size: 14px; color: #666; margin-bottom: 24px; }
    h1 { font-size: 28px; font-weight: 600; letter-spacing: -0.02em; margin-bottom: 8px; }
    .subtitle { font-size: 15px; color: #888; }
    .note {
      margin-top: 20px; padding: 14px 16px; border-radius: 10px;
      background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
      font-size: 14px; line-height: 1.5; color: #ccc;
    }
    form { margin-top: 24px; display: flex; flex-direction: column; gap: 12px; }
    label { font-size: 13px; color: #888; }
    input {
      width: 100%; padding: 14px 16px; font-size: 16px;
      background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.14);
      border-radius: 10px; color: #fff;
    }
    input:focus { outline: none; border-color: rgba(255,255,255,0.4); }
    button {
      width: 100%; padding: 14px 16px; font-size: 15px; font-weight: 600;
      background: #fff; color: #000; border: 0; border-radius: 10px; cursor: pointer;
    }
    button:disabled { opacity: 0.5; cursor: default; }
    .hidden { display: none; }
    .msg { font-size: 14px; margin-top: 4px; min-height: 20px; }
    .msg.error { color: #ff7a7a; }
    .msg.ok { color: #7ad48c; }
    .alt { margin-top: 24px; font-size: 14px; color: #666; }
    .alt a { color: #aaa; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">id.org.ai</div>
    <h1>Verify your email</h1>
    <p class="subtitle">We'll send a 6-digit code to your work address.</p>
    ${note ? `<div class="note">${escapeHtml(note)}</div>` : ''}

    <form id="send-form">
      <label for="email">Work email</label>
      <input id="email" name="email" type="email" autocomplete="email" required
             placeholder="you@company.com" value="${escapeHtml(prefill)}">
      <button type="submit" id="send-btn">Send code</button>
    </form>

    <form id="verify-form" class="hidden">
      <label for="code">6-digit code</label>
      <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
             pattern="[0-9]{6}" maxlength="6" placeholder="123456" required>
      <button type="submit" id="verify-btn">Verify</button>
    </form>

    <div class="msg" id="msg"></div>

    ${
      microsoftAvailable
        ? `<div class="alt"><a href="/federation/microsoft/start?continue=${encodeURIComponent(continueUrl)}">Try signing in with Microsoft instead</a></div>`
        : ''
    }
  </div>

  <script>
    const CONTINUE = ${JSON.stringify(continueUrl)};
    const sendForm = document.getElementById('send-form');
    const verifyForm = document.getElementById('verify-form');
    const msg = document.getElementById('msg');
    const emailInput = document.getElementById('email');
    const codeInput = document.getElementById('code');

    function say(text, kind) {
      msg.textContent = text;
      msg.className = 'msg' + (kind ? ' ' + kind : '');
    }

    sendForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('send-btn');
      btn.disabled = true;
      say('Sending…');
      try {
        const res = await fetch('/federation/email/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: emailInput.value })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { say(data.error_description || data.error || 'Could not send the code', 'error'); btn.disabled = false; return; }
        say('Code sent — check your inbox.', 'ok');
        verifyForm.classList.remove('hidden');
        codeInput.focus();
      } catch (err) {
        say('Network error — please try again', 'error');
      }
      btn.disabled = false;
    });

    verifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('verify-btn');
      btn.disabled = true;
      say('Verifying…');
      try {
        const res = await fetch('/federation/email/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: emailInput.value, code: codeInput.value, continue: CONTINUE })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { say(data.error_description || data.error || 'That code did not work', 'error'); btn.disabled = false; return; }
        window.location.href = data.continue || CONTINUE || '/';
      } catch (err) {
        say('Network error — please try again', 'error');
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>`

  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}
