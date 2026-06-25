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
              placeholder="输入用户注册邮箱"
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
            <span v-else>查询</span>
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
          <h3 class="mb-3 text-sm font-semibold text-gray-700 dark:text-gray-300">用户概览</h3>
          <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <span class="text-xs text-gray-500">邮箱</span>
              <p class="text-sm font-medium">{{ result.email }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">当前充值池余额</span>
              <p class="text-sm font-medium text-green-600">¥{{ fmt(result.current_pool) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">API 消耗 (充值池)</span>
              <p class="text-sm font-medium">¥{{ fmt(result.total_recharge_used) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">赠金消耗</span>
              <p class="text-sm font-medium text-purple-600">¥{{ fmt(result.total_gift_used) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">退费扣减累计</span>
              <p class="text-sm font-medium text-orange-600">¥{{ fmt(result.total_refund_deducted) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">有效总消耗 (API+退费)</span>
              <p class="text-sm font-medium">¥{{ fmt(result.effective_used) }}</p>
            </div>
          </div>
        </div>

        <!-- 汇总 -->
        <div class="card p-4">
          <h3 class="mb-3 text-sm font-semibold text-gray-700 dark:text-gray-300">消耗汇总</h3>
          <div class="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <div>
              <span class="text-xs text-gray-500">付费到账总额</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_paid_credited) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">免费到账总额</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_free_credited) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">付费已消耗 (余额)</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_paid_consumed) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">免费已消耗 (余额)</span>
              <p class="text-sm font-medium">¥{{ fmt(result.summary.total_free_consumed) }}</p>
            </div>
            <div>
              <span class="text-xs text-gray-500">付费已消耗 (实付)</span>
              <p class="text-sm font-bold text-red-600">¥{{ fmt(result.summary.total_paid_money_spent) }}</p>
            </div>
          </div>
        </div>

        <!-- FIFO 明细表格 -->
        <div class="card overflow-hidden">
          <div class="border-b border-gray-200 px-4 py-3 dark:border-dark-600">
            <h3 class="text-sm font-semibold text-gray-700 dark:text-gray-300">FIFO 分摊明细</h3>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="border-b bg-gray-50 text-xs text-gray-600 dark:bg-dark-700 dark:text-gray-400">
                <tr>
                  <th class="px-3 py-2">#</th>
                  <th class="px-3 py-2">来源</th>
                  <th class="px-3 py-2">入账时间</th>
                  <th class="px-3 py-2 text-right">到账余额</th>
                  <th class="px-3 py-2 text-right">实付金额</th>
                  <th class="px-3 py-2 text-center">倍率</th>
                  <th class="px-3 py-2 text-right">已消耗余额</th>
                  <th class="px-3 py-2 text-right">已消耗实付</th>
                  <th class="px-3 py-2 text-right">剩余余额</th>
                  <th class="px-3 py-2">退费状态</th>
                  <th class="px-3 py-2">备注</th>
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
                    <span v-else class="text-xs text-gray-400">免费</span>
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
                    <span v-if="slot.refund_status === 'refunded'" class="rounded-full bg-red-100 px-2 py-0.5 text-xs text-red-700 dark:bg-red-900/30 dark:text-red-300">已退</span>
                    <span v-else-if="slot.refund_status === 'partially_refunded'" class="rounded-full bg-yellow-100 px-2 py-0.5 text-xs text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300">部分退</span>
                  </td>
                  <td class="max-w-48 truncate px-3 py-2 text-xs text-gray-500" :title="slot.note">{{ slot.note }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="result.slots.length === 0" class="p-8 text-center text-sm text-gray-500">
            该用户无入账记录
          </div>
        </div>

        <!-- 退费建议 -->
        <div v-if="paidSlots.length > 0" class="card p-4">
          <h3 class="mb-3 text-sm font-semibold text-gray-700 dark:text-gray-300">退费建议（付费订单）</h3>
          <div class="space-y-3">
            <div
              v-for="slot in paidSlots"
              :key="slot.source_id"
              class="rounded-lg border border-gray-200 p-3 dark:border-dark-600"
              :class="slot.refund_status ? 'opacity-60' : ''"
            >
              <div class="flex items-center justify-between">
                <div class="text-sm font-medium">{{ slot.note }}</div>
                <div v-if="!slot.refund_status" class="text-right">
                  <span class="text-xs text-gray-500">可退实付: </span>
                  <span class="text-lg font-bold text-green-600">¥{{ fmt(refundableAmount(slot)) }}</span>
                </div>
                <div v-else class="text-xs text-gray-500">
                  {{ slot.refund_status === 'refunded' ? '已退费' : '部分退费' }}
                  <span v-if="slot.refund_deducted > 0">（扣减 ¥{{ fmt(slot.refund_deducted) }}）</span>
                </div>
              </div>
              <div class="mt-1 flex flex-wrap gap-4 text-xs text-gray-500">
                <span>到账: {{ fmt(slot.amount) }}</span>
                <span>实付: ¥{{ fmt(slot.pay_amount) }}</span>
                <span>倍率: 1:{{ (1/slot.ratio).toFixed(1) }}</span>
                <span>FIFO已消耗余额: {{ fmt(slot.consumed) }}</span>
                <span>换算实付消耗: ¥{{ fmt(slot.consumed_money) }}</span>
              </div>
            </div>
          </div>
        </div>
      </template>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { getRefundAssessment, type RefundAssessmentResponse, type PoolSlotDTO } from '@/api/admin/refundAssessment'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'

const email = ref('')
const loading = ref(false)
const error = ref('')
const result = ref<RefundAssessmentResponse | null>(null)

const paidSlots = computed(() => {
  if (!result.value) return []
  return result.value.slots.filter(s => s.source === 'payment_order')
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
    const msg = e?.response?.data?.message || e?.message || '查询失败'
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
    case 'payment_order': return '支付订单'
    case 'redeem_balance': return '兑换码'
    case 'admin_balance': return '管理员调整'
    case 'affiliate_transfer': return '推荐返佣'
    case 'signup_grant': return '注册赠送'
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
  // 可退实付 = 实付金额 - 已消耗实付
  const refundable = slot.pay_amount - slot.consumed_money
  return Math.max(0, refundable)
}
</script>
