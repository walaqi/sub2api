import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import PaymentMethodSelector, {
  type PaymentMethodOption,
} from '@/components/payment/PaymentMethodSelector.vue'

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string, fallback?: string) => fallback ?? key,
  }),
}))

function methodFactory(overrides: Partial<PaymentMethodOption> = {}): PaymentMethodOption {
  return { type: 'alipay', fee_rate: 0, available: true, ...overrides }
}

describe('PaymentMethodSelector custom EasyPay channel rendering', () => {
  it('uses admin-defined label and icon_url over the fallback', () => {
    const wrapper = mount(PaymentMethodSelector, {
      props: {
        methods: [
          methodFactory({
            type: 'epay',
            label: '聚合支付',
            icon_url: 'https://cdn.example/epay.png',
          }),
        ],
        selected: '',
      },
    })

    expect(wrapper.text()).toContain('聚合支付')
    const img = wrapper.find('img[alt="聚合支付"]')
    expect(img.exists()).toBe(true)
    expect(img.attributes('src')).toBe('https://cdn.example/epay.png')
  })

  it('falls back to i18n key when label is missing', () => {
    const wrapper = mount(PaymentMethodSelector, {
      props: {
        methods: [methodFactory({ type: 'epay' })],
        selected: '',
      },
    })

    // mocked t() returns the fallback (the type itself) when no label provided
    expect(wrapper.text()).toContain('epay')
  })

  it('orders methods by sort_order ascending, falling back to METHOD_ORDER', () => {
    const wrapper = mount(PaymentMethodSelector, {
      props: {
        methods: [
          methodFactory({ type: 'qqpay', label: 'QQ', sort_order: 2 }),
          methodFactory({ type: 'epay', label: 'EPay', sort_order: 1 }),
          methodFactory({ type: 'alipay' }), // no sort_order — falls back to METHOD_ORDER
        ],
        selected: '',
      },
    })

    const buttons = wrapper.findAll('button')
    // Buttons with sort_order come first; alipay (no sort_order) sorts last via fallback.
    expect(buttons[0].text()).toContain('EPay')
    expect(buttons[1].text()).toContain('QQ')
    expect(buttons[2].text()).toContain('alipay')
  })
})
