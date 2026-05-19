/**
 * Shared URL builder for iframe-embedded pages.
 * Used by CustomPageView for embedded custom menu pages to build URLs with
 * theme, lang, ui_mode, and (optionally) user_id, token, src_host, src_url.
 *
 * Identity-bearing params (user_id / token / src_host / src_url) are only
 * appended when the caller passes injectCredentials=true. They MUST stay off
 * for external sites — leaking a JWT into a third-party CDN's logs/referrer
 * is a security issue, and many WAFs (e.g. Cloudflare Managed Rules) will
 * block requests carrying token-shaped query params.
 */

const EMBEDDED_USER_ID_QUERY_KEY = 'user_id'
const EMBEDDED_AUTH_TOKEN_QUERY_KEY = 'token'
const EMBEDDED_THEME_QUERY_KEY = 'theme'
const EMBEDDED_LANG_QUERY_KEY = 'lang'
const EMBEDDED_UI_MODE_QUERY_KEY = 'ui_mode'
const EMBEDDED_UI_MODE_VALUE = 'embedded'
const EMBEDDED_SRC_HOST_QUERY_KEY = 'src_host'
const EMBEDDED_SRC_QUERY_KEY = 'src_url'

export function buildEmbeddedUrl(
  baseUrl: string,
  userId?: number,
  authToken?: string | null,
  theme: 'light' | 'dark' = 'light',
  lang?: string,
  injectCredentials: boolean = false,
): string {
  if (!baseUrl) return baseUrl
  try {
    const url = new URL(baseUrl)
    url.searchParams.set(EMBEDDED_THEME_QUERY_KEY, theme)
    if (lang) {
      url.searchParams.set(EMBEDDED_LANG_QUERY_KEY, lang)
    }
    url.searchParams.set(EMBEDDED_UI_MODE_QUERY_KEY, EMBEDDED_UI_MODE_VALUE)
    if (injectCredentials) {
      if (userId) {
        url.searchParams.set(EMBEDDED_USER_ID_QUERY_KEY, String(userId))
      }
      if (authToken) {
        url.searchParams.set(EMBEDDED_AUTH_TOKEN_QUERY_KEY, authToken)
      }
      if (typeof window !== 'undefined') {
        url.searchParams.set(EMBEDDED_SRC_HOST_QUERY_KEY, window.location.origin)
        url.searchParams.set(EMBEDDED_SRC_QUERY_KEY, window.location.href)
      }
    }
    return url.toString()
  } catch {
    return baseUrl
  }
}

export function detectTheme(): 'light' | 'dark' {
  if (typeof document === 'undefined') return 'light'
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}
