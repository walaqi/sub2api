const EMAIL_SUFFIX_TOKEN_SPLIT_RE = /[\s,，]+/
const EMAIL_SUFFIX_INVALID_CHAR_RE = /[^a-z0-9.-]/g
const EMAIL_SUFFIX_INVALID_CHAR_CHECK_RE = /[^a-z0-9.-]/
const EMAIL_SUFFIX_PREFIX_RE = /^@+/
const EMAIL_SUFFIX_WILDCARD_PREFIX = '*.'
const EMAIL_SUFFIX_MESSAGE_VISIBLE_LIMIT = 5
const EMAIL_SUFFIX_DOMAIN_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/

// Regex whitelist entries take the form "re:<pattern>#<label>". The pattern is
// matched against the whole email and must be anchored (^...$); the label is the
// only part shown to end users. "#" is a literal in JS/RE2 regex, so it never
// clashes with the pattern and the label may contain "|".
const EMAIL_SUFFIX_REGEX_PREFIX = 're:'
const EMAIL_SUFFIX_REGEX_LABEL_SEP = '#'

export function isRegistrationEmailSuffixRegexEntry(value: string): boolean {
  return String(value || '')
    .trim()
    .startsWith(EMAIL_SUFFIX_REGEX_PREFIX)
}

interface ParsedRegistrationEmailRegex {
  pattern: string
  label: string
}

function parseRegistrationEmailRegexEntry(entry: string): ParsedRegistrationEmailRegex | null {
  const trimmed = String(entry || '').trim()
  if (!trimmed.startsWith(EMAIL_SUFFIX_REGEX_PREFIX)) {
    return null
  }
  const body = trimmed.slice(EMAIL_SUFFIX_REGEX_PREFIX.length)
  const sepIndex = body.indexOf(EMAIL_SUFFIX_REGEX_LABEL_SEP)
  if (sepIndex < 0) {
    return null
  }
  const pattern = body.slice(0, sepIndex)
  const label = body.slice(sepIndex + 1).trim()
  if (!pattern || !label) {
    return null
  }
  return { pattern, label }
}

// isRegistrationEmailSuffixRegexEntryValid mirrors the backend rules: the entry
// must split into pattern + non-empty label, the pattern must be anchored, and
// it must compile as a regular expression.
export function isRegistrationEmailSuffixRegexEntryValid(entry: string): boolean {
  const parsed = parseRegistrationEmailRegexEntry(entry)
  if (!parsed) {
    return false
  }
  if (!parsed.pattern.startsWith('^') || !parsed.pattern.endsWith('$')) {
    return false
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(parsed.pattern)
    return true
  } catch {
    return false
  }
}

// normalizeRegistrationEmailSuffixDomain converts raw input into a canonical domain token.
// Exact domains are returned without "@"; wildcard domains keep the "*." prefix.
// Regex entries ("re:...") are returned untouched (only outer whitespace trimmed),
// so their special characters and case are preserved.
export function normalizeRegistrationEmailSuffixDomain(raw: string): string {
  const trimmed = String(raw || '').trim()
  if (isRegistrationEmailSuffixRegexEntry(trimmed)) {
    return trimmed
  }

  let value = trimmed.toLowerCase()
  if (!value) {
    return ''
  }

  value = value.replace(EMAIL_SUFFIX_PREFIX_RE, '')
  return normalizeRegistrationEmailSuffixToken(value, false)
}

export function normalizeRegistrationEmailSuffixDomains(
  items: string[] | null | undefined
): string[] {
  if (!items || items.length === 0) {
    return []
  }

  const seen = new Set<string>()
  const normalized: string[] = []
  for (const item of items) {
    const domain = normalizeRegistrationEmailSuffixDomain(item)
    const isValid = isRegistrationEmailSuffixRegexEntry(domain)
      ? isRegistrationEmailSuffixRegexEntryValid(domain)
      : isRegistrationEmailSuffixDomainValid(domain)
    if (!isValid || seen.has(domain)) {
      continue
    }
    seen.add(domain)
    normalized.push(domain)
  }
  return normalized
}

export function parseRegistrationEmailSuffixWhitelistInput(input: string): string[] {
  if (!input || !input.trim()) {
    return []
  }

  const seen = new Set<string>()
  const normalized: string[] = []

  const pushToken = (domain: string) => {
    const isValid = isRegistrationEmailSuffixRegexEntry(domain)
      ? isRegistrationEmailSuffixRegexEntryValid(domain)
      : isRegistrationEmailSuffixDomainValid(domain)
    if (!isValid || seen.has(domain)) {
      return
    }
    seen.add(domain)
    normalized.push(domain)
  }

  // Split on lines first so a regex entry (which may contain spaces/commas) is
  // never broken apart by the domain token separators.
  for (const line of input.split(/[\r\n]+/)) {
    const trimmedLine = line.trim()
    if (!trimmedLine) {
      continue
    }
    if (isRegistrationEmailSuffixRegexEntry(trimmedLine)) {
      pushToken(trimmedLine)
      continue
    }
    for (const token of trimmedLine.split(EMAIL_SUFFIX_TOKEN_SPLIT_RE)) {
      pushToken(normalizeRegistrationEmailSuffixDomainStrict(token))
    }
  }

  return normalized
}

export function normalizeRegistrationEmailSuffixWhitelist(
  items: string[] | null | undefined
): string[] {
  return normalizeRegistrationEmailSuffixDomains(items).map(toCanonicalRegistrationEmailSuffix)
}

function extractRegistrationEmailDomain(email: string): string {
  const raw = String(email || '').trim().toLowerCase()
  if (!raw) {
    return ''
  }
  const atIndex = raw.indexOf('@')
  if (atIndex <= 0 || atIndex >= raw.length - 1) {
    return ''
  }
  if (raw.indexOf('@', atIndex + 1) !== -1) {
    return ''
  }
  return raw.slice(atIndex + 1)
}

export function isRegistrationEmailSuffixAllowed(
  email: string,
  whitelist: string[] | null | undefined
): boolean {
  const normalizedWhitelist = normalizeRegistrationEmailSuffixWhitelist(whitelist)
  if (normalizedWhitelist.length === 0) {
    return true
  }
  const emailDomain = extractRegistrationEmailDomain(email)
  if (!emailDomain) {
    return false
  }
  const emailSuffix = `@${emailDomain}`
  const normalizedEmail = String(email || '')
    .trim()
    .toLowerCase()
  return normalizedWhitelist.some((allowed) => {
    if (allowed.startsWith(EMAIL_SUFFIX_REGEX_PREFIX)) {
      const parsed = parseRegistrationEmailRegexEntry(allowed)
      if (!parsed) {
        return false
      }
      try {
        return new RegExp(parsed.pattern).test(normalizedEmail)
      } catch {
        return false
      }
    }
    if (allowed.startsWith('@')) {
      return allowed === emailSuffix
    }
    if (allowed.startsWith(EMAIL_SUFFIX_WILDCARD_PREFIX)) {
      const base = allowed.slice(EMAIL_SUFFIX_WILDCARD_PREFIX.length)
      return emailDomain === base || emailDomain.endsWith(`.${base}`)
    }
    return false
  })
}

export function formatRegistrationEmailSuffixWhitelistForMessage(
  whitelist: string[] | null | undefined,
  options: {
    separator: string
    more: (count: number) => string
  }
): string {
  const normalizedWhitelist = normalizeRegistrationEmailSuffixWhitelist(whitelist)
  const visible = normalizedWhitelist
    .slice(0, EMAIL_SUFFIX_MESSAGE_VISIBLE_LIMIT)
    .map(registrationEmailSuffixDisplay)
  const hiddenCount = normalizedWhitelist.length - visible.length
  if (hiddenCount > 0) {
    visible.push(options.more(hiddenCount))
  }
  return visible.join(options.separator)
}

// Pasted domains should be strict: any invalid character drops the whole token.
function normalizeRegistrationEmailSuffixDomainStrict(raw: string): string {
  let value = String(raw || '').trim().toLowerCase()
  if (!value) {
    return ''
  }
  value = value.replace(EMAIL_SUFFIX_PREFIX_RE, '')
  return normalizeRegistrationEmailSuffixToken(value, true)
}

export function isRegistrationEmailSuffixDomainValid(domain: string): boolean {
  if (!domain) {
    return false
  }
  if (domain.startsWith(EMAIL_SUFFIX_WILDCARD_PREFIX)) {
    return EMAIL_SUFFIX_DOMAIN_PATTERN.test(domain.slice(EMAIL_SUFFIX_WILDCARD_PREFIX.length))
  }
  return !domain.includes('*') && EMAIL_SUFFIX_DOMAIN_PATTERN.test(domain)
}

function normalizeRegistrationEmailSuffixToken(value: string, strict: boolean): string {
  if (value.startsWith(EMAIL_SUFFIX_WILDCARD_PREFIX)) {
    const domain = value.slice(EMAIL_SUFFIX_WILDCARD_PREFIX.length)
    if (strict && (!domain || EMAIL_SUFFIX_INVALID_CHAR_CHECK_RE.test(domain))) {
      return ''
    }
    return `${EMAIL_SUFFIX_WILDCARD_PREFIX}${domain.replace(EMAIL_SUFFIX_INVALID_CHAR_RE, '')}`
  }

  if (value === '*') {
    return strict ? '' : value
  }

  if (strict && EMAIL_SUFFIX_INVALID_CHAR_CHECK_RE.test(value)) {
    return ''
  }
  return value.replace(/[*]/g, '').replace(EMAIL_SUFFIX_INVALID_CHAR_RE, '')
}

function toCanonicalRegistrationEmailSuffix(domain: string): string {
  if (domain.startsWith(EMAIL_SUFFIX_REGEX_PREFIX)) {
    return domain
  }
  return domain.startsWith(EMAIL_SUFFIX_WILDCARD_PREFIX) ? domain : `@${domain}`
}

// registrationEmailSuffixDisplay returns the user-facing label for a whitelist
// entry. Regex entries expose only their display label, never the raw pattern.
export function registrationEmailSuffixDisplay(entry: string): string {
  const parsed = parseRegistrationEmailRegexEntry(entry)
  if (parsed) {
    return parsed.label
  }
  return entry
}
