import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ProviderCard from '@/components/payment/ProviderCard.vue'
import type { ProviderInstance } from '@/types/payment'

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => {
      if (key === 'admin.settings.payment.providerEasypay') return '易支付'
      if (key === 'common.enabled') return '启用'
      if (key === 'admin.settings.payment.refundEnabled') return '允许退款'
      return key
    },
  }),
}))

vi.mock('@/components/icons/Icon.vue', () => ({
  default: { name: 'Icon', template: '<i />' },
}))

vi.mock('@/components/payment/ToggleSwitch.vue', () => ({
  default: { name: 'ToggleSwitch', template: '<button />', props: ['label', 'checked'] },
}))

function providerFactory(overrides: Partial<ProviderInstance> = {}): ProviderInstance {
  return {
    id: 1,
    provider_key: 'easypay',
    name: 'EasyPay 主账户',
    config: {},
    supported_types: ['alipay'],
    enabled: true,
    payment_mode: '',
    refund_enabled: false,
    allow_user_refund: false,
    limits: '',
    sort_order: 0,
    ...overrides,
  }
}

function mountCard(provider: ProviderInstance) {
  return mount(ProviderCard, {
    props: {
      provider,
      enabled: true,
      availableTypes: [],
    },
  })
}

describe('ProviderCard name fallback', () => {
  it('renders the provider name when present', () => {
    const wrapper = mountCard(providerFactory({ name: 'EasyPay 主账户' }))
    expect(wrapper.text()).toContain('EasyPay 主账户')
  })

  it('falls back to the provider-key label when name is empty', () => {
    const wrapper = mountCard(providerFactory({ name: '' }))
    expect(wrapper.text()).toContain('易支付')
  })

  it('falls back when name is whitespace only', () => {
    const wrapper = mountCard(providerFactory({ name: '   ' }))
    expect(wrapper.text()).toContain('易支付')
  })

  it('does not crash when supported_types is null', () => {
    const provider = providerFactory({ supported_types: null as unknown as string[] })
    expect(() => mountCard(provider)).not.toThrow()
  })
})
