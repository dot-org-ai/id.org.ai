/**
 * "Sign this device out" (backend.md#b3): it asks before revoking (a link
 * never revokes by itself), posts with CSRF, and says when it's done.
 */
import { describe, expect, it } from 'vitest'
import { renderHtml } from '../render'
import { DeviceSignOut, type DeviceSignOutProps } from './DeviceSignOut'

const base: DeviceSignOutProps = {
  state: 'confirm',
  client: { name: 'auto.dev CLI', tile: { kind: 'icon', icon: 'terminal' } },
  device: 'macOS · Miami, FL',
  action: '/device/fam_1/revoke',
  csrf: 'tok',
  cancelHref: '/',
}

async function dom(p: DeviceSignOutProps): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(<DeviceSignOut {...p} />, { title: 't' }), 'text/html')
}

describe('DeviceSignOut', () => {
  it('asks first: one h1, a POST form with CSRF to its revoke action, and a way to keep it', async () => {
    const d = await dom(base)
    expect([...d.querySelectorAll('h1')].map((h) => h.textContent)).toEqual(['Sign this device out?'])
    expect(d.querySelector('.id-desc')!.textContent).toBe('auto.dev CLI on macOS · Miami, FL loses access to your account. Its sign-in can’t be used again.')
    const form = d.querySelector('form')!
    expect([form.getAttribute('method'), form.getAttribute('action'), form.getAttribute('data-js')]).toEqual(['post', '/device/fam_1/revoke', 'submit'])
    expect(form.querySelector<HTMLInputElement>('input[name="csrf"]')!.value).toBe('tok')
    expect(d.querySelector('a.id-btn')!.getAttribute('href')).toBe('/')
    expect(d.querySelector('button[type="submit"]')!.textContent).toBe('Sign it out')
    expect(d.querySelector('[role="status"][data-status]')).not.toBeNull()
  })

  it('done: says so, with no form', async () => {
    const d = await dom({ ...base, state: 'done', csrf: '' })
    expect(d.querySelector('h1')!.textContent).toBe('Device signed out')
    expect(d.querySelector('form')).toBeNull()
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
  })
})
