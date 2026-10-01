import { afterEach, describe, expect, it } from 'vitest'
import { initSubmit } from './submit'

function mount(): HTMLFormElement {
  document.body.innerHTML = `
    <div class="id-card"><form data-js="submit" method="post" action="/oauth/authorize">
      <div class="id-conn" data-js="connector" data-state="idle"></div>
      <div data-actions>
        <button type="submit" name="approved" value="false"><span>Cancel</span></button>
        <button type="submit" name="approved" value="true" data-busy-label="Allowing…"><span>Allow</span></button>
      </div>
    </form></div>`
  const form = document.querySelector('form')!
  initSubmit(form)
  form.addEventListener('submit', (e) => e.preventDefault())
  return form
}

afterEach(() => (document.body.innerHTML = ''))

describe('submit.ts', () => {
  it('Allow: connector connecting, primary busy with its label, the rest disabled, value kept', () => {
    const form = mount()
    const [cancel, allow] = Array.from(form.querySelectorAll('button'))
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: allow }))
    expect(document.querySelector('[data-js="connector"]')!.getAttribute('data-state')).toBe('connecting')
    expect(allow!.disabled).toBe(true)
    expect(allow!.getAttribute('aria-busy')).toBe('true')
    expect(allow!.textContent).toBe('Allowing…')
    expect(cancel!.disabled).toBe(true)
    const kept = form.querySelector<HTMLInputElement>('input[type=hidden][name=approved]')!
    expect(kept.value).toBe('true')
  })

  it('Cancel: no connector, nothing busy, the deny value kept', () => {
    const form = mount()
    const [cancel] = Array.from(form.querySelectorAll('button'))
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: cancel }))
    expect(document.querySelector('[data-js="connector"]')!.getAttribute('data-state')).toBe('idle')
    expect(form.querySelector('[aria-busy]')).toBeNull()
    expect(form.querySelector<HTMLInputElement>('input[type=hidden][name=approved]')!.value).toBe('false')
  })
})
