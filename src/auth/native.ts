/**
 * Provider-native credential sources shared with the CLI/tooling ecosystem.
 *
 * Native mode deliberately reads the provider's own runtime file instead of
 * copying credentials into the plugin store. The default is read-only: the
 * external client remains the refresh owner, and this plugin re-reads the file
 * when a request discovers that its in-memory token is stale.
 */

import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { decodeJwtPayload } from './jwt.js'
import { accountKeyOf } from './store.js'
import type { AccountEntry, CodexSession, GrokSession, ProviderId, SessionOf } from './store.js'
import type { AccountStoreIo } from '../providers/accounts.js'
/** xAI CLI OAuth client id used by the native Grok auth scope. */
const GROK_CLIENT_ID = 'b1a00492-073a-47ea-816f-4c329264a828'

/** Source selection for a provider's durable credentials. */
export type AuthSourceMode = 'plugin' | 'native' | 'auto'

/** Configuration for one provider-native credential file. */
export interface NativeAuthSourceConfig {
  /** `auto` prefers the native file when it exists; `plugin` preserves legacy behavior. */
  mode?: AuthSourceMode
  /** A native runtime directory or an explicit auth.json path. */
  path?: string
  /** Native refresh writes are disabled by default so the external client owns rotation. */
  readOnly?: boolean
}

/** The source that was selected when the plugin composition was applied. */
export interface SelectedAuthSource {
  kind: 'plugin' | 'native'
  path?: string
  readOnly: boolean
}

const CODEX_AUTH_FILE = 'auth.json'
const GROK_AUTH_FILE = 'auth.json'
const XAI_ISSUER = 'https://auth.x.ai'
const XAI_SCOPE_KEY = `${XAI_ISSUER}::${GROK_CLIENT_ID}`

/** Resolve a configured native path as a file, accepting either a directory or auth.json. */
export function nativeAuthPath(provider: 'codex' | 'grok', configured?: string): string {
  const envName = provider === 'codex' ? 'CODEX_HOME' : 'GROK_HOME'
  const defaultRoot = provider === 'codex' ? join(homedir(), '.codex') : join(homedir(), '.grok')
  const root = configured?.trim() || process.env[envName]?.trim() || defaultRoot
  if (basename(root).toLowerCase() === (provider === 'codex' ? CODEX_AUTH_FILE : GROK_AUTH_FILE).toLowerCase()) {
    return root
  }
  return join(root, provider === 'codex' ? CODEX_AUTH_FILE : GROK_AUTH_FILE)
}

/** Select a source without parsing secrets. `auto` falls back only when native auth is absent. */
export function selectAuthSource(
  provider: ProviderId,
  config?: NativeAuthSourceConfig,
): SelectedAuthSource {
  // Keep legacy/plugin behavior unless native mode is explicitly opted in.
  // This avoids silently hijacking a developer's real CLI login in tests or
  // profiles that were never configured to share native credentials. The
  // schema also defaults to `plugin`; `auto` is an explicit sharing choice.
  const mode = config?.mode ?? 'plugin'
  if (provider !== 'codex' && provider !== 'grok') {
    return { kind: 'plugin', readOnly: false }
  }
  const path = nativeAuthPath(provider, config?.path)
  if (mode === 'plugin' || (mode === 'auto' && (!existsSync(path) || !nativeSessionUsable(provider, path)))) {
    return { kind: 'plugin', readOnly: false }
  }
  return { kind: 'native', path, readOnly: config?.readOnly !== false }
}

export interface NativeStore<S> extends AccountStoreIo<S> {
  readonly source: SelectedAuthSource
  /** Native sources expose one currently active account; there is no local default switch. */
  readonly setDefault: (account: string) => Promise<void>
}

interface JsonObject {
  [key: string]: unknown
}

function objectOf(value: unknown): JsonObject | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as JsonObject
    : undefined
}

function stringOf(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined
}

function jwtExpiry(token: string | undefined): number | undefined {
  if (token === undefined) return undefined
  const exp = decodeJwtPayload(token)?.exp
  return typeof exp === 'number' && Number.isFinite(exp) ? Math.trunc(exp * 1000) : undefined
}

function jwtClaim(token: string | undefined, ...keys: string[]): string | undefined {
  const payload = token === undefined ? undefined : decodeJwtPayload(token)
  for (const key of keys) {
    const value = payload?.[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

function nestedJwtClaim(token: string | undefined, objectKey: string, claimKey: string): string | undefined {
  const payload = token === undefined ? undefined : decodeJwtPayload(token)
  const object = objectOf(payload?.[objectKey])
  return stringOf(object?.[claimKey])
}

function expiryOf(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Native Codex/Grok files use Unix seconds, while this plugin uses ms.
    return value < 100_000_000_000 ? Math.trunc(value * 1000) : Math.trunc(value)
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const numeric = Number(value)
    if (Number.isFinite(numeric)) return expiryOf(numeric)
    const parsed = Date.parse(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return undefined
}

function minExpiry(...values: (number | undefined)[]): number | undefined {
  const present = values.filter((value): value is number => value !== undefined)
  return present.length === 0 ? undefined : Math.min(...present)
}

function nativeSessionUsable(provider: 'codex' | 'grok', path: string): boolean {
  // This synchronous probe is used only by `auto` during plugin apply. The
  // stores still re-read and fully validate the file for every account query.
  try {
    const text = requireText(path)
    const parsed = JSON.parse(text) as unknown
    const root = objectOf(parsed)
    if (root === undefined) return false
    return provider === 'codex'
      ? codexSession(root, path) !== undefined
      : grokSession(root, path) !== undefined
  } catch {
    return false
  }
}

function requireText(path: string): string {
  // `selectAuthSource` is intentionally synchronous; use the native fs API
  // only for the auto-selection probe, never for token persistence.
  return readFileSync(path, 'utf8')
}

async function readJson(path: string): Promise<JsonObject | undefined> {
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error(`native auth file at ${path} is not valid JSON`)
  }
  const object = objectOf(parsed)
  if (object === undefined) throw new Error(`native auth file at ${path} must be a JSON object`)
  return object
}

async function writeJson(path: string, value: JsonObject): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.dsh-plugin-${process.pid}-${Math.random().toString(36).slice(2)}.tmp`
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
    await chmod(temporary, 0o600)
    await rename(temporary, path)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}

function readOnlyError(path: string): Error {
  return new Error(`native credentials are read-only (${path}); refresh or log out with the owning CLI/tool`)
}

/** Native credentials are never deleted by this plugin, even in writable refresh mode. */
function nativeOwnerError(provider: 'codex' | 'grok', path: string): Error {
  return new Error(`native ${provider} credentials are owned by the external CLI/tool (${path}); log out there instead`)
}

function missingNativeSession(provider: ProviderId, path: string): Error {
  return new Error(`${provider} native auth file at ${path} does not contain a usable official subscription login`)
}

function codexSession(root: JsonObject, path: string): CodexSession | undefined {
  if (root.auth_mode !== undefined && root.auth_mode !== 'chatgpt') return undefined
  const tokens = objectOf(root.tokens)
  if (tokens === undefined) return undefined
  const accessToken = stringOf(tokens.access_token)
  const refreshToken = stringOf(tokens.refresh_token)
  if (accessToken === undefined || refreshToken === undefined) return undefined
  const idToken = stringOf(tokens.id_token)
  const accountId = stringOf(tokens.account_id)
    ?? nestedJwtClaim(idToken, 'https://api.openai.com/auth', 'chatgpt_account_id')
    ?? jwtClaim(idToken, 'chatgpt_account_id')
  if (accountId === undefined) throw missingNativeSession('codex', path)
  const expiresAt = minExpiry(jwtExpiry(accessToken), jwtExpiry(idToken))
  if (expiresAt === undefined) throw new Error(`codex native auth at ${path} has no token expiry`)
  const emailAddress = jwtClaim(idToken, 'email')
    ?? nestedJwtClaim(idToken, 'https://api.openai.com/profile', 'email')
  const planType = (() => {
    const auth = objectOf(idToken === undefined ? undefined : decodeJwtPayload(idToken)?.['https://api.openai.com/auth'])
    return stringOf(auth?.chatgpt_plan_type)
  })()
  return {
    accessToken,
    refreshToken,
    expiresAt,
    accountId,
    ...idToken === undefined ? {} : { idToken },
    ...emailAddress === undefined ? {} : { emailAddress },
    ...planType === undefined ? {} : { planType },
  }
}

function codexEntry(root: JsonObject): JsonObject {
  const tokens = objectOf(root.tokens) ?? {}
  return tokens
}

class CodexNativeStore implements NativeStore<CodexSession> {
  readonly source: SelectedAuthSource

  constructor(private readonly path: string, readOnly: boolean) {
    this.source = { kind: 'native', path, readOnly }
  }

  private async read(): Promise<CodexSession | undefined> {
    const root = await readJson(this.path)
    return root === undefined ? undefined : codexSession(root, this.path)
  }

  async list(): Promise<AccountEntry<CodexSession>[]> {
    const session = await this.read()
    return session === undefined ? [] : [{ key: accountKeyOf('codex', session), session }]
  }

  async get(account?: string): Promise<CodexSession | undefined> {
    const session = await this.read()
    if (session === undefined) return undefined
    const key = accountKeyOf('codex', session)
    return account === undefined || account === key || account === session.accountId ? session : undefined
  }

  async save(account: string, session: CodexSession): Promise<void> {
    if (this.source.readOnly) throw readOnlyError(this.path)
    const root = (await readJson(this.path)) ?? {}
    const current = codexSession(root, this.path)
    if (current !== undefined && account !== accountKeyOf('codex', current) && account !== current.accountId) {
      throw new Error('the native Codex account changed outside the plugin; refusing to overwrite it')
    }
    root.auth_mode = 'chatgpt'
    root.tokens = {
      ...codexEntry(root),
      access_token: session.accessToken,
      refresh_token: session.refreshToken,
      account_id: session.accountId,
      ...session.idToken === undefined ? {} : { id_token: session.idToken },
    }
    root.last_refresh = new Date().toISOString()
    await writeJson(this.path, root)
  }

  async remove(_account: string): Promise<void> {
    throw nativeOwnerError('codex', this.path)
  }

  async resolve(account: string): Promise<string> {
    const session = await this.get(account)
    if (session === undefined) throw new Error(`native Codex account "${account}" is not active`)
    return accountKeyOf('codex', session)
  }

  async setDefault(account: string): Promise<void> {
    await this.resolve(account)
  }
}

function grokScopeEntry(root: JsonObject): { key: string; entry: JsonObject } | undefined {
  const exact = objectOf(root[XAI_SCOPE_KEY])
  if (exact !== undefined) return { key: XAI_SCOPE_KEY, entry: exact }
  for (const [key, value] of Object.entries(root)) {
    const entry = objectOf(value)
    if (entry === undefined) continue
    if (stringOf(entry.oidc_issuer)?.replace(/\/$/, '') === XAI_ISSUER
      && stringOf(entry.oidc_client_id) === GROK_CLIENT_ID) return { key, entry }
  }
  return undefined
}

function grokSession(root: JsonObject, path: string): GrokSession | undefined {
  const found = grokScopeEntry(root)
  if (found === undefined) return undefined
  const accessToken = stringOf(found.entry.key) ?? stringOf(found.entry.access_token)
  const refreshToken = stringOf(found.entry.refresh_token)
  if (accessToken === undefined || refreshToken === undefined) return undefined
  const issuer = stringOf(found.entry.oidc_issuer)?.replace(/\/$/, '') ?? XAI_ISSUER
  const expiresAt = minExpiry(
    expiryOf(found.entry.expires_at),
    jwtExpiry(accessToken),
  )
  if (expiresAt === undefined) throw new Error(`grok native auth at ${path} has no token expiry`)
  const account = stringOf(found.entry.email)
    ?? stringOf(found.entry.user_id)
    ?? stringOf(found.entry.principal_id)
    ?? jwtClaim(accessToken, 'email', 'preferred_username', 'name', 'sub')
  const scopes = stringOf(found.entry.scope) ?? stringOf(found.entry.scopes)
  return {
    accessToken,
    refreshToken,
    expiresAt,
    tokenEndpoint: `${issuer}/oauth2/token`,
    ...scopes === undefined ? {} : { scopes },
    ...account === undefined ? {} : { account },
  }
}

class GrokNativeStore implements NativeStore<GrokSession> {
  readonly source: SelectedAuthSource

  constructor(private readonly path: string, readOnly: boolean) {
    this.source = { kind: 'native', path, readOnly }
  }

  private async read(): Promise<GrokSession | undefined> {
    const root = await readJson(this.path)
    return root === undefined ? undefined : grokSession(root, this.path)
  }

  async list(): Promise<AccountEntry<GrokSession>[]> {
    const session = await this.read()
    return session === undefined ? [] : [{ key: accountKeyOf('grok', session), session }]
  }

  async get(account?: string): Promise<GrokSession | undefined> {
    const session = await this.read()
    if (session === undefined) return undefined
    const key = accountKeyOf('grok', session)
    return account === undefined || account === key || account === session.account ? session : undefined
  }

  async save(account: string, session: GrokSession): Promise<void> {
    if (this.source.readOnly) throw readOnlyError(this.path)
    const root = (await readJson(this.path)) ?? {}
    const found = grokScopeEntry(root)
    const current = grokSession(root, this.path)
    if (current !== undefined && account !== accountKeyOf('grok', current) && account !== current.account) {
      throw new Error('the native Grok account changed outside the plugin; refusing to overwrite it')
    }
    const key = found?.key ?? XAI_SCOPE_KEY
    const entry = { ...(found?.entry ?? {}) }
    entry.key = session.accessToken
    entry.access_token = session.accessToken
    entry.refresh_token = session.refreshToken
    entry.expires_at = new Date(session.expiresAt).toISOString()
    entry.auth_mode = 'oidc'
    entry.oidc_issuer = XAI_ISSUER
    entry.oidc_client_id = GROK_CLIENT_ID
    if (session.account !== undefined) entry.email = session.account
    root[key] = entry
    await writeJson(this.path, root)
  }

  async remove(_account: string): Promise<void> {
    throw nativeOwnerError('grok', this.path)
  }

  async resolve(account: string): Promise<string> {
    const session = await this.get(account)
    if (session === undefined) throw new Error(`native Grok account "${account}" is not active`)
    return accountKeyOf('grok', session)
  }

  async setDefault(account: string): Promise<void> {
    await this.resolve(account)
  }
}

/** Build a native store for the providers whose runtime auth files are stable enough to parse. */
export function createNativeStore(
  provider: 'codex',
  source: SelectedAuthSource,
): NativeStore<CodexSession>
export function createNativeStore(
  provider: 'grok',
  source: SelectedAuthSource,
): NativeStore<GrokSession>
export function createNativeStore(
  provider: 'codex' | 'grok',
  source: SelectedAuthSource,
): NativeStore<CodexSession> | NativeStore<GrokSession> {
  if (source.path === undefined) throw new Error(`native ${provider} source has no path`)
  return provider === 'codex'
    ? new CodexNativeStore(source.path, source.readOnly)
    : new GrokNativeStore(source.path, source.readOnly)
}

/** Type guard used by the host controller to expose source metadata without secrets. */
export function isNativeSource(source: SelectedAuthSource): boolean {
  return source.kind === 'native'
}

/** Keep the provider session type available to callers building source registries. */
export type NativeSessionOf<P extends 'codex' | 'grok'> = SessionOf<P>
