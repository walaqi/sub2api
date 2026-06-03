import { describe, expect, it } from 'vitest'
import {
  formatRegistrationEmailSuffixWhitelistForMessage,
  isRegistrationEmailSuffixAllowed,
  isRegistrationEmailSuffixDomainValid,
  isRegistrationEmailSuffixRegexEntry,
  isRegistrationEmailSuffixRegexEntryValid,
  normalizeRegistrationEmailSuffixDomain,
  normalizeRegistrationEmailSuffixDomains,
  normalizeRegistrationEmailSuffixWhitelist,
  parseRegistrationEmailSuffixWhitelistInput,
  registrationEmailSuffixDisplay
} from '@/utils/registrationEmailPolicy'

const REGEX_RULE = 're:^\\d+@qq\\.com$#仅限纯数字QQ邮箱'

describe('registrationEmailPolicy utils', () => {
  it('normalizeRegistrationEmailSuffixDomain lowercases, strips @, and ignores invalid chars', () => {
    expect(normalizeRegistrationEmailSuffixDomain(' @Exa!mple.COM ')).toBe('example.com')
    expect(normalizeRegistrationEmailSuffixDomain(' *.EDU!.CN ')).toBe('*.edu.cn')
  })

  it('normalizeRegistrationEmailSuffixDomains deduplicates normalized domains', () => {
    expect(
      normalizeRegistrationEmailSuffixDomains([
        '@example.com',
        'Example.com',
        '',
        '-invalid.com',
        'foo..bar.com',
        ' @foo.bar ',
        '@foo.bar',
        '*.EDU.CN',
        '*.edu.cn'
      ])
    ).toEqual(['example.com', 'foo.bar', '*.edu.cn'])
  })

  it('parseRegistrationEmailSuffixWhitelistInput supports separators and deduplicates', () => {
    const input = '\n  @example.com,example.com，@foo.bar\t@FOO.bar *.EDU.CN  '
    expect(parseRegistrationEmailSuffixWhitelistInput(input)).toEqual([
      'example.com',
      'foo.bar',
      '*.edu.cn'
    ])
  })

  it('parseRegistrationEmailSuffixWhitelistInput drops tokens containing invalid chars', () => {
    const input = '@exa!mple.com, @foo.bar, @bad#token.com, @ok-domain.com'
    expect(parseRegistrationEmailSuffixWhitelistInput(input)).toEqual(['foo.bar', 'ok-domain.com'])
  })

  it('parseRegistrationEmailSuffixWhitelistInput drops structurally invalid domains', () => {
    const input = '@-bad.com, @foo..bar.com, @foo.bar, @xn--ok.com, *., *, *.@, *.foo'
    expect(parseRegistrationEmailSuffixWhitelistInput(input)).toEqual(['foo.bar', 'xn--ok.com'])
  })

  it('parseRegistrationEmailSuffixWhitelistInput returns empty list for blank input', () => {
    expect(parseRegistrationEmailSuffixWhitelistInput('   \n \n')).toEqual([])
  })

  it('normalizeRegistrationEmailSuffixWhitelist returns canonical @domain list', () => {
    expect(
      normalizeRegistrationEmailSuffixWhitelist([
        '@Example.com',
        'foo.bar',
        '',
        '-invalid.com',
        ' @foo.bar ',
        '*.EDU.CN'
      ])
    ).toEqual(['@example.com', '@foo.bar', '*.edu.cn'])
  })

  it('isRegistrationEmailSuffixDomainValid matches backend-compatible domain rules', () => {
    expect(isRegistrationEmailSuffixDomainValid('example.com')).toBe(true)
    expect(isRegistrationEmailSuffixDomainValid('foo-bar.example.com')).toBe(true)
    expect(isRegistrationEmailSuffixDomainValid('*.edu.cn')).toBe(true)
    expect(isRegistrationEmailSuffixDomainValid('-bad.com')).toBe(false)
    expect(isRegistrationEmailSuffixDomainValid('foo..bar.com')).toBe(false)
    expect(isRegistrationEmailSuffixDomainValid('localhost')).toBe(false)
    expect(isRegistrationEmailSuffixDomainValid('*.foo')).toBe(false)
    expect(isRegistrationEmailSuffixDomainValid('*')).toBe(false)
    expect(isRegistrationEmailSuffixDomainValid('*.@')).toBe(false)
  })

  it('isRegistrationEmailSuffixAllowed allows any email when whitelist is empty', () => {
    expect(isRegistrationEmailSuffixAllowed('user@example.com', [])).toBe(true)
  })

  it('isRegistrationEmailSuffixAllowed applies exact suffix matching', () => {
    expect(isRegistrationEmailSuffixAllowed('user@example.com', ['@example.com'])).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('user@sub.example.com', ['@example.com'])).toBe(false)
    expect(isRegistrationEmailSuffixAllowed('user@qq.com', ['@qq.com'])).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('user@sub.qq.com', ['@qq.com'])).toBe(false)
  })

  it('isRegistrationEmailSuffixAllowed applies wildcard suffix matching', () => {
    expect(isRegistrationEmailSuffixAllowed('student@cs.edu.cn', ['*.edu.cn'])).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('student@edu.cn', ['*.edu.cn'])).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('student@foo.cn', ['*.edu.cn'])).toBe(false)
  })

  it('isRegistrationEmailSuffixAllowed supports mixed exact and wildcard entries', () => {
    const whitelist = ['@a.com', '*.b.cn']
    expect(isRegistrationEmailSuffixAllowed('user@a.com', whitelist)).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('user@school.b.cn', whitelist)).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('user@b.cn', whitelist)).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('user@c.cn', whitelist)).toBe(false)
  })

  it('formatRegistrationEmailSuffixWhitelistForMessage lists up to five entries', () => {
    expect(
      formatRegistrationEmailSuffixWhitelistForMessage(
        ['@a.com', '@b.com', '@c.com', '@d.com', '@e.com'],
        { separator: ', ', more: (count) => `and ${count} more` }
      )
    ).toBe('@a.com, @b.com, @c.com, @d.com, @e.com')
    expect(
      formatRegistrationEmailSuffixWhitelistForMessage(
        ['@a.com', '@b.com', '@c.com', '@d.com', '@e.com', '*.edu.cn', '@f.com'],
        { separator: ', ', more: (count) => `and ${count} more` }
      )
    ).toBe('@a.com, @b.com, @c.com, @d.com, @e.com, and 2 more')
  })

  it('isRegistrationEmailSuffixRegexEntry detects re: entries', () => {
    expect(isRegistrationEmailSuffixRegexEntry(REGEX_RULE)).toBe(true)
    expect(isRegistrationEmailSuffixRegexEntry('  re:^x$#label')).toBe(true)
    expect(isRegistrationEmailSuffixRegexEntry('@qq.com')).toBe(false)
  })

  it('isRegistrationEmailSuffixRegexEntryValid enforces anchoring, label, and compilability', () => {
    expect(isRegistrationEmailSuffixRegexEntryValid(REGEX_RULE)).toBe(true)
    // missing separator
    expect(isRegistrationEmailSuffixRegexEntryValid('re:^\\d+@qq\\.com$')).toBe(false)
    // empty label
    expect(isRegistrationEmailSuffixRegexEntryValid('re:^\\d+@qq\\.com$#')).toBe(false)
    // empty pattern
    expect(isRegistrationEmailSuffixRegexEntryValid('re:#label')).toBe(false)
    // not anchored
    expect(isRegistrationEmailSuffixRegexEntryValid('re:\\d+@qq\\.com$#label')).toBe(false)
    expect(isRegistrationEmailSuffixRegexEntryValid('re:^\\d+@qq\\.com#label')).toBe(false)
    // invalid regex
    expect(isRegistrationEmailSuffixRegexEntryValid('re:^[a-z$#label')).toBe(false)
  })

  it('normalizeRegistrationEmailSuffixDomain leaves re: entries untouched (except outer trim)', () => {
    expect(normalizeRegistrationEmailSuffixDomain(`  ${REGEX_RULE}  `)).toBe(REGEX_RULE)
  })

  it('normalizeRegistrationEmailSuffixDomains keeps valid re: entries and drops invalid ones', () => {
    expect(
      normalizeRegistrationEmailSuffixDomains([REGEX_RULE, '@foo.bar', 're:no-anchor#x', REGEX_RULE])
    ).toEqual([REGEX_RULE, 'foo.bar'])
  })

  it('normalizeRegistrationEmailSuffixWhitelist preserves re: entries verbatim', () => {
    expect(normalizeRegistrationEmailSuffixWhitelist([REGEX_RULE, '@Foo.bar'])).toEqual([
      REGEX_RULE,
      '@foo.bar'
    ])
  })

  it('parseRegistrationEmailSuffixWhitelistInput keeps a re: line intact across spaces/commas', () => {
    const input = `@foo.bar, example.com\nre:^(\\d+|a)@qq\\.com$#数字或a开头\n*.edu.cn`
    expect(parseRegistrationEmailSuffixWhitelistInput(input)).toEqual([
      'foo.bar',
      'example.com',
      're:^(\\d+|a)@qq\\.com$#数字或a开头',
      '*.edu.cn'
    ])
  })

  it('isRegistrationEmailSuffixAllowed applies anchored regex matching against the whole email', () => {
    expect(isRegistrationEmailSuffixAllowed('12345@qq.com', [REGEX_RULE])).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('abc1@qq.com', [REGEX_RULE])).toBe(false)
    expect(isRegistrationEmailSuffixAllowed('x12345@qq.com', [REGEX_RULE])).toBe(false)
    expect(isRegistrationEmailSuffixAllowed('12345@163.com', [REGEX_RULE])).toBe(false)
    // input is lowercased before matching
    expect(isRegistrationEmailSuffixAllowed('12345@QQ.com', [REGEX_RULE])).toBe(true)
  })

  it('isRegistrationEmailSuffixAllowed mixes regex and plain entries', () => {
    const whitelist = ['@foo.bar', REGEX_RULE]
    expect(isRegistrationEmailSuffixAllowed('user@foo.bar', whitelist)).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('999@qq.com', whitelist)).toBe(true)
    expect(isRegistrationEmailSuffixAllowed('user@other.com', whitelist)).toBe(false)
  })

  it('registrationEmailSuffixDisplay exposes only the label for regex entries', () => {
    expect(registrationEmailSuffixDisplay('@foo.bar')).toBe('@foo.bar')
    expect(registrationEmailSuffixDisplay(REGEX_RULE)).toBe('仅限纯数字QQ邮箱')
    expect(registrationEmailSuffixDisplay('re:^x$#a|b 提示')).toBe('a|b 提示')
  })

  it('formatRegistrationEmailSuffixWhitelistForMessage shows regex labels, not patterns', () => {
    expect(
      formatRegistrationEmailSuffixWhitelistForMessage(['@foo.bar', REGEX_RULE], {
        separator: ', ',
        more: (count) => `and ${count} more`
      })
    ).toBe('@foo.bar, 仅限纯数字QQ邮箱')
  })
})
