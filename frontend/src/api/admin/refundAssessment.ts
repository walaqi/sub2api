/**
 * Admin Refund Assessment API
 * 退费评估：查询用户充值池消耗的 FIFO 分摊明细
 */

import { apiClient } from '../client'

export interface PoolSlotDTO {
  source: string
  source_id: number
  credited_at: number // unix ms
  amount: number
  pay_amount: number
  ratio: number
  consumed: number
  consumed_money: number
  remaining: number
  refund_status: string
  refund_deducted: number
  note: string
}

export interface AssessmentSummaryDTO {
  total_paid_credited: number
  total_free_credited: number
  total_paid_consumed: number
  total_free_consumed: number
  total_paid_money_spent: number
}

export interface RefundAssessmentResponse {
  user_id: number
  email: string
  total_recharge_used: number
  total_gift_used: number
  total_refund_deducted: number
  effective_used: number
  current_pool: number
  slots: PoolSlotDTO[]
  summary: AssessmentSummaryDTO
}

export function getRefundAssessment(email: string) {
  return apiClient.get<RefundAssessmentResponse>(
    '/admin/refund-assessment',
    { params: { email } }
  )
}
