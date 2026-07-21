import { afterEach, describe, expect, it } from 'vitest'

import { getPersistedPageSize } from '@/composables/usePersistedPageSize'

describe('usePersistedPageSize', () => {
  afterEach(() => {
    localStorage.clear()
    delete window.__APP_CONFIG__
  })

  it('prefers a valid persisted localStorage value over the system default', () => {
    // 契约：本地选择永远优先。localStorage 存有合法值时直接采用，
    // 即使系统默认（table_default_page_size）不同也不覆盖。
    window.__APP_CONFIG__ = {
      table_default_page_size: 1000,
      table_page_size_options: [20, 50, 1000]
    } as any
    localStorage.setItem('table-page-size', '50')

    expect(getPersistedPageSize()).toBe(50)
  })

  it('falls back to the system table default when nothing is persisted', () => {
    window.__APP_CONFIG__ = {
      table_default_page_size: 1000,
      table_page_size_options: [20, 50, 1000]
    } as any

    expect(getPersistedPageSize()).toBe(1000)
  })
})
