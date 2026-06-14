/**
 * Chat client deep-link helpers (聊天广场一期).
 *
 * Phase 1 of the chat plaza is "out-of-station deep links": the platform never
 * hosts a chat UI. Instead the user picks a public/local chat client, we mint a
 * temporary restricted API key, and we build a deep link that hands the client
 * our gateway base URL + that key. All chat traffic still flows through the
 * gateway (the key points at it), so there is no extra server/UI cost here.
 *
 * The token-replacement logic is ported from new-api's `chat-links.ts`, adapted
 * to TypeScript. We do NOT force an `sk-` prefix (sub2api keys carry their own
 * format) and the embedded config payloads identify us as `sub2api`.
 */

export type ChatLinkType = 'web' | 'app'

export interface ChatPreset {
  /** Stable identifier (used as v-for key and i18n sub-key). */
  id: string
  /** Display name. */
  name: string
  /** URL template containing {key}/{address}/{*Config} tokens. */
  url: string
  /** 'web' opens in a new tab; 'app' invokes a custom-protocol handler. */
  type: ChatLinkType
}

/**
 * Built-in chat clients. None require self-hosting:
 *  - web   → publicly hosted sites (Lobe Chat preview, AI as Workspace)
 *  - app   → local desktop/mobile apps invoked via custom protocol
 *
 * baseURL handling: web templates append `/v1` themselves, so {address} must be
 * the gateway root (no trailing /v1).
 */
export const CHAT_PRESETS: ChatPreset[] = [
  {
    id: 'lobechat',
    name: 'Lobe Chat',
    url: 'https://chat-preview.lobehub.com/?settings={"keyVaults":{"openai":{"apiKey":"{key}","baseURL":"{address}/v1"}}}',
    type: 'web',
  },
  {
    id: 'aiaw',
    name: 'AI as Workspace',
    url: 'https://aiaw.app/set-provider?provider={"type":"openai","settings":{"apiKey":"{key}","baseURL":"{address}/v1","compatibility":"strict"}}',
    type: 'web',
  },
  {
    id: 'cherrystudio',
    name: 'Cherry Studio',
    url: 'cherrystudio://providers/api-keys?v=1&data={cherryConfig}',
    type: 'app',
  },
  {
    id: 'aionui',
    name: 'AionUI',
    url: 'aionui://provider/add?v=1&data={aionuiConfig}',
    type: 'app',
  },
  {
    id: 'deepchat',
    name: 'DeepChat',
    url: 'deepchat://provider/install?v=1&data={deepchatConfig}',
    type: 'app',
  },
  {
    id: 'opencat',
    name: 'OpenCat',
    url: 'opencat://team/join?domain={address}&token={key}',
    type: 'app',
  },
]

const HTTP_REGEX = /^https?:\/\//i

function toBase64(value: string): string {
  if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
    // btoa only handles latin1; encode UTF-8 first to stay safe with non-ASCII.
    return window.btoa(unescape(encodeURIComponent(value)))
  }
  return ''
}

function replaceToken(source: string, token: string, value: string): string {
  return source.split(token).join(value)
}

/**
 * Normalize a gateway base URL to its root form (no trailing `/v1`, no trailing
 * slashes). Deep-link templates append the protocol suffix themselves.
 */
export function resolveServerRoot(apiBaseUrl: string | undefined): string {
  const raw = (apiBaseUrl && apiBaseUrl.trim()) || (typeof window !== 'undefined' ? window.location.origin : '')
  return raw.replace(/\/v1\/?$/i, '').replace(/\/+$/, '')
}

export interface ResolveChatUrlParams {
  template: string
  apiKey: string
  /** Gateway root (no /v1). Use resolveServerRoot() to derive it. */
  serverAddress: string
}

/**
 * Replace tokens in a client URL template with the actual key/address.
 *
 * Mirrors new-api: {address} is percent-encoded, {key} is inserted verbatim, and
 * the app-config tokens carry a base64url-ish JSON payload.
 */
export function resolveChatUrl({ template, apiKey, serverAddress }: ResolveChatUrlParams): string {
  let url = template
  const address = serverAddress || ''
  const key = (apiKey || '').trim()

  if (url.includes('{cherryConfig}')) {
    const payload = { id: 'sub2api', baseUrl: address, apiKey: key }
    const encoded = encodeURIComponent(toBase64(JSON.stringify(payload)))
    return replaceToken(url, '{cherryConfig}', encoded)
  }

  if (url.includes('{aionuiConfig}')) {
    const payload = { platform: 'sub2api', baseUrl: address, apiKey: key }
    const encoded = encodeURIComponent(toBase64(JSON.stringify(payload)))
    return replaceToken(url, '{aionuiConfig}', encoded)
  }

  if (url.includes('{deepchatConfig}')) {
    const payload = { id: 'sub2api', baseUrl: address, apiKey: key }
    const encoded = encodeURIComponent(toBase64(JSON.stringify(payload)))
    return replaceToken(url, '{deepchatConfig}', encoded)
  }

  if (address) {
    url = replaceToken(url, '{address}', encodeURIComponent(address))
  }
  if (key) {
    url = replaceToken(url, '{key}', key)
  }

  return url
}

/**
 * Open a resolved chat link. Web links open in a new tab; app (custom-protocol)
 * links are assigned to location so the OS protocol handler intercepts them
 * without navigating the SPA away.
 */
export function openChatLink(url: string, type: ChatLinkType): void {
  if (typeof window === 'undefined') return
  if (type === 'web' || HTTP_REGEX.test(url)) {
    window.open(url, '_blank', 'noopener,noreferrer')
  } else {
    window.location.href = url
  }
}
