import { describe, expect, it } from 'vitest'

import { resolveGiftBonusDisplay } from '@/components/payment/giftBonus'
import type { OrderGiftBonus } from '@/types/payment'

describe('resolveGiftBonusDisplay', () => {
  it('returns null when there is no bonus', () => {
    expect(resolveGiftBonusDisplay(undefined)).toBeNull()
    expect(resolveGiftBonusDisplay(null)).toBeNull()
  })

  it('returns null when the bonus amount is not positive', () => {
    expect(resolveGiftBonusDisplay({ bonus_amount: 0, deduction_mode: 'priority' })).toBeNull()
    expect(resolveGiftBonusDisplay({ bonus_amount: -5, deduction_mode: 'priority' })).toBeNull()
  })

  it('formats a priority-mode bonus with USD amount and priority label key', () => {
    const bonus: OrderGiftBonus = { bonus_amount: 2, deduction_mode: 'priority' }
    const display = resolveGiftBonusDisplay(bonus)
    expect(display).toEqual({
      amountText: '$2.00',
      labelKey: 'payment.orders.giftBonusWithMode',
      labelModeKey: 'gifts.modePriority',
    })
  })

  it('maps ratio mode to the ratio label key', () => {
    const bonus: OrderGiftBonus = { bonus_amount: 8.5, deduction_mode: 'ratio', ratio_recharge: 2 }
    const display = resolveGiftBonusDisplay(bonus)
    expect(display?.labelModeKey).toBe('gifts.modeRatio')
    expect(display?.amountText).toBe('$8.50')
  })
})
