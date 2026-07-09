import type { OrderGiftBonus } from '@/types/payment'

/** 充值成功页赠金行的展示描述：null 表示无赠金、不展示该行。 */
export interface GiftBonusDisplay {
  /** 赠金金额，固定美元展示（赠金子账本单位为 USD，与支付币种无关）。 */
  amountText: string
  /** i18n key，用于渲染标签"赠金(扣除模式)"。 */
  labelKey: string
  /** 传给 labelKey 的插值参数中 mode 的 i18n key（priority/ratio 的可读文案）。 */
  labelModeKey: string
}

/**
 * 计算充值成功页应展示的赠金行。返回 null 表示无赠金（bonus 缺省或 <=0），调用方隐藏该行。
 * 标签形如「赠金(优先扣除)」，括号内为扣除模式（priority→gifts.modePriority / ratio→gifts.modeRatio）。
 */
export function resolveGiftBonusDisplay(bonus: OrderGiftBonus | null | undefined): GiftBonusDisplay | null {
  if (!bonus || !(bonus.bonus_amount > 0)) return null
  return {
    amountText: '$' + bonus.bonus_amount.toFixed(2),
    labelKey: 'payment.orders.giftBonusWithMode',
    labelModeKey: bonus.deduction_mode === 'ratio' ? 'gifts.modeRatio' : 'gifts.modePriority',
  }
}
