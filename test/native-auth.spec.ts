/**
 * Provider-native Codex/Grok credential files stay outside the plugin store.
 * These tests exercise parsing, source selection, and re-reading through the
 * public native-store seam without ever using a developer's real auth files.
 */

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createNativeStore,
  nativeAuthPath,
  selectAuthSource,
} from '../src/auth/native.js'

const TEMP_DIRS: string[] = []

function jwt(payload: Record<string, unknown>): string {
  return `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`
}

async function fixture(value: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'subscriptions-native-'))
  TEMP_DIRS.push(dir)
  const path = join(dir, 'auth.json')
  await writeFile(path, JSON.stringify(value), { mode: 0o600 })
  return path
}

after(async () => {
  await Promise.all(TEMP_DIRS.map(dir => rm(dir, { recursive: true, force: true })))
})

test('Codex native auth parses nested account claims and the earliest JWT expiry', async () => {
  const accessToken = jwt({ exp: 3_000 })
  const idToken = jwt({
    exp: 2_000,
    email: 'codex@example.com',
    'https://api.openai.com/auth': {
      chatgpt_account_id: 'acct-codex',
      chatgpt_plan_type: 'pro',
    },
  })
  const path = await fixture({
    auth_mode: 'chatgpt',
    tokens: {
      access_token: accessToken,
      refresh_token: 'codex-refresh',
      id_token: idToken,
    },
  })
  const store = createNativeStore('codex', { kind: 'native', path, readOnly: true })
  const entries = await store.list()
  assert.equal(entries.length, 1)
  const session = entries[0].session
  assert.equal(session.accessToken, accessToken)
  assert.equal(session.refreshToken, 'codex-refresh')
  assert.equal(session.accountId, 'acct-codex')
  assert.equal(session.expiresAt, 2_000_000)
  assert.equal(session.emailAddress, 'codex@example.com')
  assert.equal(session.planType, 'pro')
  assert.equal((await store.get('acct-codex'))?.accountId, 'acct-codex')
  assert.equal((await store.get('not-the-active-account')), undefined)
})

test('Grok native auth parses scope entries, token aliases, and expiry formats', async () => {
  const clientId = 'b1a00492-073a-47ea-816f-4c329264a828'
  const accessToken = jwt({ exp: 4_000, email: 'grok@example.com' })
  const path = await fixture({
    [`https://auth.x.ai::${clientId}`]: {
      key: accessToken,
      refresh_token: 'grok-refresh',
      expires_at: 3_500,
      oidc_issuer: 'https://auth.x.ai/',
      oidc_client_id: clientId,
      scope: 'openid profile',
    },
  })
  const store = createNativeStore('grok', { kind: 'native', path, readOnly: true })
  const [entry] = await store.list()
  assert.equal(entry.session.accessToken, accessToken)
  assert.equal(entry.session.refreshToken, 'grok-refresh')
  assert.equal(entry.session.expiresAt, 3_500_000)
  assert.equal(entry.session.tokenEndpoint, 'https://auth.x.ai/oauth2/token')
  assert.equal(entry.session.account, 'grok@example.com')
  assert.equal(entry.session.scopes, 'openid profile')
  assert.equal((await store.get('grok@example.com'))?.accessToken, accessToken)

  const alternatePath = await fixture({
    tenant: {
      access_token: 'alternate-access',
      refresh_token: 'alternate-refresh',
      expires_at: '2030-01-01T00:00:00Z',
      oidc_issuer: 'https://auth.x.ai',
      oidc_client_id: clientId,
      user_id: 'alternate-user',
      scopes: 'openid',
    },
  })
  const alternate = createNativeStore('grok', { kind: 'native', path: alternatePath, readOnly: true })
  const [alternateEntry] = await alternate.list()
  assert.equal(alternateEntry.session.accessToken, 'alternate-access')
  assert.equal(alternateEntry.session.account, 'alternate-user')
})

test('native source selection is explicit, path-aware, and validates auto files', async () => {
  const missing = join(TEMP_DIRS[0] ?? tmpdir(), 'missing-codex', 'auth.json')
  assert.deepEqual(selectAuthSource('codex', { mode: 'plugin', path: missing }), { kind: 'plugin', readOnly: false })
  assert.deepEqual(selectAuthSource('codex', { mode: 'auto', path: missing }), { kind: 'plugin', readOnly: false })
  assert.deepEqual(selectAuthSource('codex', { mode: 'native', path: missing }), { kind: 'native', path: missing, readOnly: true })

  const validPath = await fixture({
    auth_mode: 'chatgpt',
    tokens: {
      access_token: jwt({ exp: 4_000 }),
      refresh_token: 'refresh',
      account_id: 'acct',
    },
  })
  assert.deepEqual(selectAuthSource('codex', { mode: 'auto', path: validPath }), {
    kind: 'native', path: validPath, readOnly: true,
  })

  const malformedDir = await mkdtemp(join(tmpdir(), 'subscriptions-native-'))
  TEMP_DIRS.push(malformedDir)
  const malformed = join(malformedDir, 'auth.json')
  await writeFile(malformed, '{not-json', { mode: 0o600 })
  assert.deepEqual(selectAuthSource('codex', { mode: 'auto', path: malformed }), { kind: 'plugin', readOnly: false })
  assert.equal(nativeAuthPath('codex', 'C:\\runtime\\auth.json'), 'C:\\runtime\\auth.json')
  assert.equal(nativeAuthPath('grok', 'C:\\runtime'), 'C:\\runtime\\auth.json')
})

test('native stores re-read the external file instead of persisting a local copy', async () => {
  const first = jwt({ exp: 3_000 })
  const second = jwt({ exp: 4_000 })
  const path = await fixture({
    auth_mode: 'chatgpt',
    tokens: { access_token: first, refresh_token: 'refresh', account_id: 'acct' },
  })
  const store = createNativeStore('codex', { kind: 'native', path, readOnly: true })
  assert.equal((await store.get('acct'))?.accessToken, first)
  await writeFile(path, JSON.stringify({
    auth_mode: 'chatgpt',
    tokens: { access_token: second, refresh_token: 'refresh-rotated', account_id: 'acct' },
  }))
  const current = await store.get('acct')
  assert.equal(current?.accessToken, second)
  assert.equal(current?.refreshToken, 'refresh-rotated')
  await assert.rejects(store.save('acct', current!), /read-only/)
  await assert.rejects(store.remove('acct'), /owned by the external CLI\/tool/)
})

test('native stores reject malformed JSON and unusable official sessions', async () => {
  const malformedDir = await mkdtemp(join(tmpdir(), 'subscriptions-native-'))
  TEMP_DIRS.push(malformedDir)
  const malformed = join(malformedDir, 'auth.json')
  await writeFile(malformed, '{not-json', { mode: 0o600 })
  const store = createNativeStore('codex', { kind: 'native', path: malformed, readOnly: true })
  await assert.rejects(store.list(), /not valid JSON/)

  const noExpiry = await fixture({
    auth_mode: 'chatgpt',
    tokens: { access_token: 'opaque', refresh_token: 'refresh', account_id: 'acct' },
  })
  const noExpiryStore = createNativeStore('codex', { kind: 'native', path: noExpiry, readOnly: true })
  await assert.rejects(noExpiryStore.list(), /has no token expiry/)

  const invalidMode = await fixture({ auth_mode: 'api-key', tokens: {} })
  const invalidModeStore = createNativeStore('codex', { kind: 'native', path: invalidMode, readOnly: true })
  assert.deepEqual(await invalidModeStore.list(), [])

  // Read-back confirms the fixture was not accidentally redirected to the
  // plugin-owned store while the native source was being tested.
  assert.match(await readFile(noExpiry, 'utf8'), /opaque/)
})
