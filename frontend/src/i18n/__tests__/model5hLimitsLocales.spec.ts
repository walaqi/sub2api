import { describe, expect, it } from 'vitest'

import en from '../locales/en'
import zh from '../locales/zh'

// 回归测试：分组「按模型 5h 限额」的 hint 文案曾内联 JSON 示例 {"claude-opus-4-8": 3.5}。
// vue-i18n 的完整构建在运行时编译消息，会把 `{...}` 当作插值占位符解析，
// 非法占位符名（如 `"claude-opus-4-8":`）触发 "Invalid token in placeholder" 崩溃，
// 导致点击「编辑分组」时白屏。
//
// 注意：vitest 用的是 vue-i18n runtime-only 构建（无消息编译器，t() 直接返回 key），
// 无法在测试里通过 t() 复现浏览器崩溃。因此这里静态校验根因约束本身：
// 该 i18n 块内任何 `{` 只能作为合法占位符 `{name}` 出现，不得有裸花括号。

// 剥离所有合法占位符 `{identifier}` 后，字符串中不应再残留任何花括号。
const VALID_PLACEHOLDER = /\{[a-zA-Z0-9_]+\}/g

function assertNoStrayBraces(value: string, path: string) {
  const stripped = value.replace(VALID_PLACEHOLDER, '')
  expect(stripped, `stray "{" in ${path}: ${value}`).not.toContain('{')
  expect(stripped, `stray "}" in ${path}: ${value}`).not.toContain('}')
}

describe('model5hLimits locale copy has no vue-i18n placeholder hazards', () => {
  for (const [locale, messages] of [['en', en], ['zh', zh]] as const) {
    const block = (messages as any).admin.groups.model5hLimits as Record<string, string>

    it(`exists and has expected keys (${locale})`, () => {
      expect(block).toBeTruthy()
      for (const key of ['label', 'hint', 'invalidJson', 'notObject', 'valueNotPositive']) {
        expect(typeof block[key], `${locale}.${key}`).toBe('string')
      }
    })

    it(`contains no stray braces that vue-i18n would misparse (${locale})`, () => {
      for (const [key, value] of Object.entries(block)) {
        assertNoStrayBraces(value, `${locale}.admin.groups.model5hLimits.${key}`)
      }
    })

    it(`keeps the {key} placeholder in valueNotPositive (${locale})`, () => {
      expect(block.valueNotPositive).toContain('{key}')
    })

    it(`hint no longer inlines a JSON example object (${locale})`, () => {
      expect(block.hint).not.toContain('claude-opus-4-8')
    })
  }
})
