<template>
  <AppLayout>
    <div class="space-y-4">
      <!-- 搜索区 -->
      <div class="card p-4">
        <div class="flex items-center gap-3">
          <div class="flex-1 sm:max-w-80">
            <input
              v-model="email"
              type="email"
              :placeholder="t('refundAssessment.emailPlaceholder')"
              class="input"
              @keyup.enter="doSearch"
            />
          </div>
          <button
            class="btn btn-primary"
            :disabled="loading || !email.trim()"
            @click="doSearch"
          >
            <Icon v-if="loading" name="refresh" size="md" class="animate-spin" />
            <span v-else>{{ t('refundAssessment.search') }}</span>
          </button>
        </div>
      </div>

      <!-- 错误提示 -->
      <div v-if="error" class="card border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
        <p class="text-sm text-red-700 dark:text-red-300">{{ error }}</p>
      </div>

      <!-- 结果区 -->
      <template v-if="result">
        <!-- 用户概览 -->
        <div class="card p-4">
          <h3 class="mb-3 text-sm font-semibold text-gray-700 dark:text-gray-300">{{ t('refundAssessment.userOverview') }}</h3>
          <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.email') }}</span>
              <p class="text-sm font-medium">{{ result.email }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.currentPool') }}</span>
              <p class="text-sm font-medium text-green-600">¥{{ fmt(result.current_pool) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.apiUsedRecharge') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(result.total_recharge_used) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.giftUsed') }}</span>
              <p class="text-sm font-medium text-purple-600">¥{{ fmt(result.total_gift_used) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.refundDeducted') }}</span>
              <p class="text-sm font-medium text-orange-600">¥{{ fmt(result.total_refund_deducted) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.effectiveUsed') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(result.effective_used) }}</p>
            </div>
          </div>
        </div>

        <!-- 汇总 -->
        <div class="card p-4">
          <h3 class="mb-3 text-sm font-semibold text-gray-700 dark:text-gray-300">{{ t('refundAssessment.consumptionSummary') }}</h3>
          <div class="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.totalPaidCredited') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_paid_credited) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.totalFreeCredited') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_free_credited) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.paidConsumedBalance') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_paid_consumed) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.freeConsumedBalance') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_free_consumed) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.paidConsumedMoney') }}</span>
              <p class="text-sm font-bold text-red-600">¥{{ fmt(result.summary.total_paid_money_spent) }}</p>
            </div>
          </div>
        </div>

        <!-- 可退建议 -->
        <div v-if="paidSlots.length > 0" class="card border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-900/20">
          <h3 class="mb-3 text-sm font-semibold text-gray-700 dark:text-gray-300">{{ t('refundAssessment.refundSuggestion') }}</h3>
          <div class="flex items-center gap-8">
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.totalPaidByUser') }}</span>
              <p class="text-sm font-medium">¥{{ fmt(totalPaid) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.paidConsumed') }}</span>
              <p class="text-sm font-medium text-red-600">¥{{ fmt(result.summary.total_paid_money_spent) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">{{ t('refundAssessment.suggestedRefund') }}</span>
              <p class="text-lg font-bold text-green-600">¥{{ fmt(totalRefundable) }}</p>
            </div>
          </div>
          <div v-if="paidSlots.length > 1" class="mt-3 space-y-2">
            <div
              v-for="slot in paidSlots"
              :key="slot.source_id"
              class="flex items-center justify-between rounded border border-green-100 px-3 py-2 text-sm dark:border-green-800/50"
              :class="slot.refund_status ? 'opacity-50' : ''"
            >
              <span class="text-gray-600 dark:text-gray-400">{{ slot.note }}</span>
              <span v-if="!slot.refund_status" class="font-medium text-green-600">{{ t('refundAssessment.refundable') }} ¥{{ fmt(refundableAmount(slot)) }}</span>
              <span v-else class="text-xs text-gray-500">
                {{ slot.refund_status === 'refunded' ? t('refundAssessment.statusRefunded') : t('refundAssessment.statusPartial') }}
                <span v-if="slot.refund_deducted > 0">({{ t('refundAssessment.deducted') }} ¥{{ fmt(slot.refund_deducted) }})</span>
              </span>
            </div>
          </div>
        </div>

        <!-- FIFO 明细表格 -->
        <div class="card overflow-hidden">
          <div class="border-b border-gray-200 px-4 py-3 dark:border-dark-600">
            <h3 class="text-sm font-semibold text-gray-700 dark:text-gray-300">{{ t('refundAssessment.fifoDetail') }}</h3>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="border-b bg-gray-50 text-xs text-gray-600 dark:bg-dark-700 dark:text-gray-400">
                <tr>
                  <th class="px-3 py-2">#</th>
                  <th class="px-3 py-2">{{ t('refundAssessment.colSource') }}</th>
                  <th class="px-3 py-2">{{ t('refundAssessment.colCreditedAt') }}</th>
                  <th class="px-3 py-2 text-right">{{ t('refundAssessment.colAmount') }}</th>
                  <th class="px-3 py-2 text-right">{{ t('refundAssessment.colPayAmount') }}</th>
                  <th class="px-3 py-2 text-center">{{ t('refundAssessment.colRatio') }}</th>
                  <th class="px-3 py-2 text-right">{{ t('refundAssessment.colConsumed') }}</th>
                  <th class="px-3 py-2 text-right">{{ t('refundAssessment.colConsumedMoney') }}</th>
                  <th class="px-3 py-2 text-right">{{ t('refundAssessment.colRemaining') }}</th>
                  <th class="px-3 py-2">{{ t('refundAssessment.colRefundStatus') }}</th>
                  <th class="px-3 py-2">{{ t('refundAssessment.colNote') }}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100 dark:divide-dark-600">
                <tr
                  v-for="(slot, idx) in result.slots"
                  :key="`${slot.source}-${slot.source_id}`"
                  :class="slotRowClass(slot)"
                >
                  <td class="px-3 py-2 text-gray-500">{{ idx + 1 }}</td>
                  <td class="px-3 py-2">
                    <span :class="sourceTagClass(slot.source)" class="inline-block rounded px-1.5 py-0.5 text-xs font-medium">
                      {{ sourceLabel(slot.source) }}
                    </span>
                  </td>
                  <td class="px-3 py-2 text-gray-600 dark:text-gray-400">{{ formatDate(slot.credited_at) }}</td>
                  <td class="px-3 py-2 text-right font-mono">{{ fmt(slot.amount) }}</td>
                  <td class="px-3 py-2 text-right font-mono">{{ slot.pay_amount > 0 ? fmt(slot.pay_amount) : '-' }}</td>
                  <td class="px-3 py-2 text-center">
                    <span v-if="slot.ratio > 0" class="text-xs">1:{{ (1/slot.ratio).toFixed(1) }}</span>
                    <span v-else class="text-xs text-gray-400">{{ t('refundAssessment.free') }}</span>
                  </td>
                  <td class="px-3 py-2 text-right font-mono" :class="slot.consumed > 0 ? 'text-orange-600' : ''">
                    {{ fmt(slot.consumed) }}
                  </td>
                  <td class="px-3 py-2 text-right font-mono" :class="slot.consumed_money > 0 ? 'text-red-600 font-semibold' : ''">
                    {{ slot.consumed_money > 0 ? '¥' + fmt(slot.consumed_money) : '-' }}
                  </td>
                  <td class="px-3 py-2 text-right font-mono" :class="slot.remaining > 0 ? 'text-green-600' : 'text-gray-400'">
                    {{ fmt(slot.remaining) }}
                  </td>
                  <td class="px-3 py-2">
                    <span v-if="slot.refund_status === 'refunded'" class="rounded-full bg-red-100 px-2 py-0.5 text-xs text-red-700 dark:bg-red-900/30 dark:text-red-300">{{ t('refundAssessment.statusRefunded') }}</span>
                    <span v-else-if="slot.refund_status === 'partially_refunded'" class="rounded-full bg-yellow-100 px-2 py-0.5 text-xs text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300">{{ t('refundAssessment.statusPartial') }}</span>
                  </td>
                  <td class="max-w-48 truncate px-3 py-2 text-xs text-gray-500" :title="slot.note">{{ slot.note }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="result.slots.length === 0" class="p-8 text-center text-sm text-gray-500">
            {{ t('refundAssessment.noRecords') }}
          </div>
        </div>

      </template>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { getRefundAssessment, type RefundAssessmentResponse, type PoolSlotDTO } from '@/api/admin/refundAssessment'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'

const { t } = useI18n()

const email = ref('')
const loading = ref(false)
const error = ref('')
const result = ref<RefundAssessmentResponse | null>(null)

const paidSlots = computed(() => {
  if (!result.value) return []
  return result.value.slots.filter(s => s.ratio > 0 && s.pay_amount > 0)
})

const totalRefundable = computed(() => {
  return paidSlots.value
    .filter(s => !s.refund_status)
    .reduce((sum, s) => sum + refundableAmount(s), 0)
})

const totalPaid = computed(() => {
  return paidSlots.value.reduce((sum, s) => sum + s.pay_amount, 0)
})

async function doSearch() {
  const trimmed = email.value.trim()
  if (!trimmed) return

  loading.value = true
  error.value = ''
  result.value = null

  try {
    const resp = await getRefundAssessment(trimmed)
    result.value = resp.data
  } catch (e: any) {
    const msg = e?.response?.data?.message || e?.message || t('refundAssessment.searchFailed')
    error.value = msg
  } finally {
    loading.value = false
  }
}

function fmt(v: number): string {
  if (v === 0) return '0.00'
  return v.toFixed(2)
}

function formatDate(ms: number): string {
  if (!ms) return '-'
  const d = new Date(ms)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

function sourceLabel(source: string): string {
  switch (source) {
    case 'payment_order': return t('refundAssessment.sourcePayment')
    case 'redeem_balance': return t('refundAssessment.sourceRedeem')
    case 'admin_balance': return t('refundAssessment.sourceAdmin')
    case 'affiliate_transfer': return t('refundAssessment.sourceAffiliate')
    case 'signup_grant': return t('refundAssessment.sourceSignup')
    default: return source
  }
}

function sourceTagClass(source: string): string {
  switch (source) {
    case 'payment_order': return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
    case 'redeem_balance': return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
    case 'admin_balance': return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
    case 'affiliate_transfer': return 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300'
    case 'signup_grant': return 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300'
    default: return 'bg-gray-100 text-gray-700'
  }
}

function slotRowClass(slot: PoolSlotDTO): string {
  if (slot.refund_status) return 'bg-red-50/50 dark:bg-red-900/10'
  if (slot.ratio === 0) return 'bg-yellow-50/50 dark:bg-yellow-900/10'
  return ''
}

function refundableAmount(slot: PoolSlotDTO): number {
  const refundable = slot.pay_amount - slot.consumed_money
  return Math.max(0, refundable)
}
</script>
