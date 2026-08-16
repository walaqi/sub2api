import { flushPromises, mount } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import AdminOrdersView from '../AdminOrdersView.vue'

const { getOrders, refundOrder } = vi.hoisted(() => ({
  getOrders: vi.fn(),
  refundOrder: vi.fn(),
}))

vi.mock('@/api/admin/payment', () => {
  const adminPaymentAPI = {
    getOrders,
    refundOrder,
  }
  return { adminPaymentAPI, default: adminPaymentAPI }
})

vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({ t: (key: string) => key }),
  }
})

const OrderTableStub = {
  props: ['orders'],
  template: '<div><div v-for="row in orders" :key="row.id"><slot name="actions" :row="row" /></div></div>',
}

const AdminRefundDialogStub = {
  name: 'AdminRefundDialog',
  props: ['show', 'order', 'submitting', 'requireForce', 'warning'],
  emits: ['confirm', 'cancel'],
  template: '<div data-test="refund-dialog" />',
}

describe('AdminOrdersView refund force confirmation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getOrders.mockResolvedValue({
      data: {
        items: [{ id: 42, status: 'COMPLETED', amount: 10 }],
        total: 1,
      },
    })
  })

  it('requires an explicit force retry after the backend requests it', async () => {
    refundOrder
      .mockResolvedValueOnce({
        data: { success: false, require_force: true, warning: 'Balance was already spent' },
      })
      .mockResolvedValueOnce({ data: { success: true } })

    const wrapper = mount(AdminOrdersView, {
      global: {
        plugins: [createPinia()],
        stubs: {
          AppLayout: { template: '<div><slot /></div>' },
          OrderTable: OrderTableStub,
          AdminRefundDialog: AdminRefundDialogStub,
          Pagination: true,
          BaseDialog: true,
          Select: true,
          Icon: true,
          OrderStatusBadge: true,
        },
      },
    })
    await flushPromises()

    const refundButton = wrapper.findAll('button').find((button) =>
      button.text().includes('payment.admin.refund')
    )
    expect(refundButton).toBeDefined()
    await refundButton!.trigger('click')

    const dialog = wrapper.findComponent({ name: 'AdminRefundDialog' })
    expect(dialog.props('show')).toBe(true)
    expect(dialog.props('requireForce')).toBe(false)

    dialog.vm.$emit('confirm', {
      amount: 10,
      reason: 'requested by customer',
      deduct_balance: true,
      force: false,
    })
    await flushPromises()

    expect(refundOrder).toHaveBeenNthCalledWith(1, 42, {
      amount: 10,
      reason: 'requested by customer',
      deduct_balance: true,
      force: false,
    })
    expect(dialog.props('show')).toBe(true)
    expect(dialog.props('requireForce')).toBe(true)
    expect(dialog.props('warning')).toBe('Balance was already spent')

    dialog.vm.$emit('confirm', {
      amount: 10,
      reason: 'requested by customer',
      deduct_balance: true,
      force: true,
    })
    await flushPromises()

    expect(refundOrder).toHaveBeenNthCalledWith(2, 42, {
      amount: 10,
      reason: 'requested by customer',
      deduct_balance: true,
      force: true,
    })
    expect(dialog.props('show')).toBe(false)
    expect(dialog.props('requireForce')).toBe(false)
    expect(dialog.props('warning')).toBe('')
  })
})
