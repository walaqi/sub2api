<template>
  <AppLayout>
    <div class="mx-auto max-w-[950px] space-y-4">
      <div class="flex items-center justify-between">
        <h1 class="text-lg font-semibold text-gray-800 dark:text-dark-100">{{ t('gifts.title') }}</h1>
      </div>

      <!-- Filter tabs -->
      <div class="flex gap-2">
        <button
          v-for="tab in tabs"
          :key="tab.value"
          class="rounded-lg px-3 py-1.5 text-sm font-medium transition-colors"
          :class="activeTab === tab.value
            ? 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
            : 'text-gray-500 hover:bg-gray-100 dark:text-dark-400 dark:hover:bg-dark-700'"
          @click="switchTab(tab.value)"
        >
          {{ tab.label }}
        </button>
      </div>

      <!-- Loading -->
      <div v-if="loading" class="flex justify-center py-12">
        <div class="h-6 w-6 animate-spin rounded-full border-2 border-primary-500 border-t-transparent"></div>
      </div>

      <!-- Gift list -->
      <div v-else-if="gifts.length" class="space-y-3">
        <div
          v-for="gift in gifts"
          :key="gift.id ?? gift.source + gift.expires_at_unix_ms"
          class="card flex items-center justify-between p-4"
        >
          <div class="flex-1 space-y-1">
            <div class="flex items-center gap-2">
              <span class="text-sm font-medium text-gray-800 dark:text-dark-100">
                ${{ gift.amount.toFixed(2) }}
              </span>
              <span
                class="rounded px-1.5 py-0.5 text-[11px] font-medium"
                :class="gift.deduction_mode === 'ratio'
                  ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                  : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'"
              >
                {{ gift.deduction_mode === 'ratio' ? ratioLabel(gift) : t('gifts.modePriority') }}
              </span>
              <span
                v-if="gift.status === 'expired'"
                class="rounded px-1.5 py-0.5 text-[11px] font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300"
              >
                {{ t('gifts.statusExpired') }}
              </span>
              <span
                v-else-if="gift.status === 'exhausted'"
                class="rounded px-1.5 py-0.5 text-[11px] font-medium bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-dark-300"
              >
                {{ t('gifts.statusExhausted') }}
              </span>
            </div>
            <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-dark-400">
              <span>{{ t('gifts.source') }}: {{ formatSource(gift.source) }}</span>
              <span v-if="gift.expires_at_unix_ms">
                {{ t('gifts.expiresAt') }}: {{ formatDate(gift.expires_at_unix_ms) }}
              </span>
              <span v-else>{{ t('gifts.neverExpires') }}</span>
              <span>{{ t('gifts.remaining') }}: ${{ gift.remaining.toFixed(2) }}</span>
            </div>
          </div>

          <!-- 右侧：全局/分组 列 + 置顶按钮 -->
          <div class="flex items-center gap-3 pl-3">
            <!-- 全局用默认文字色（非灰，避免误认为 disabled）；分组带色 -->
            <span
              v-if="gift.is_global"
              class="text-[11px] font-medium text-gray-800 dark:text-dark-100"
            >
              {{ t('gifts.scopeGlobal') }}
            </span>
            <span
              v-else
              class="rounded px-1.5 py-0.5 text-[11px] font-medium bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300"
            >
              {{ t('gifts.scopeGroup', { group: gift.group_name || `#${gift.group_id}` }) }}
            </span>

            <!-- 置顶按钮：仅对有 id 且未过期/未耗尽的行显示 -->
            <template v-if="gift.id && isPinnable(gift)">
              <button
                v-if="gift.pinned"
                :disabled="pinBusyId === gift.id"
                class="rounded-md border border-primary-300 px-2 py-1 text-[11px] font-medium text-primary-700 hover:bg-primary-50 disabled:opacity-40 dark:border-primary-700 dark:text-primary-300 dark:hover:bg-primary-900/20"
                @click="unpin(gift)"
              >
                {{ t('gifts.unpin') }}
              </button>
              <button
                v-else
                :disabled="pinBusyId === gift.id"
                class="rounded-md border border-gray-300 px-2 py-1 text-[11px] font-medium text-gray-600 hover:bg-gray-100 disabled:opacity-40 dark:border-dark-600 dark:text-dark-300 dark:hover:bg-dark-700"
                @click="pin(gift)"
              >
                {{ t('gifts.pin') }}
              </button>
            </template>
          </div>
        </div>

        <!-- Pagination -->
        <div v-if="totalPages > 1" class="flex items-center justify-center gap-2 pt-2">
          <button
            :disabled="page <= 1"
            class="rounded-md px-3 py-1 text-sm text-gray-600 hover:bg-gray-100 disabled:opacity-40 dark:text-dark-300 dark:hover:bg-dark-700"
            @click="goPage(page - 1)"
          >
            ←
          </button>
          <span class="text-sm text-gray-500 dark:text-dark-400">{{ page }} / {{ totalPages }}</span>
          <button
            :disabled="page >= totalPages"
            class="rounded-md px-3 py-1 text-sm text-gray-600 hover:bg-gray-100 disabled:opacity-40 dark:text-dark-300 dark:hover:bg-dark-700"
            @click="goPage(page + 1)"
          >
            →
          </button>
        </div>
      </div>

      <!-- Empty -->
      <div v-else class="card flex flex-col items-center justify-center py-12">
        <p class="text-sm text-gray-500 dark:text-dark-400">{{ t('gifts.empty') }}</p>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import { apiClient } from '@/api/client'

const { t } = useI18n()

interface GiftItem {
  id?: number
  remaining: number
  deduction_mode: 'priority' | 'ratio'
  ratio_recharge?: number | null
  expires_at_unix_ms?: number | null
  expiring_soon: boolean
  source: string
  source_ref: string
  amount: number
  status: string
  created_at_unix_ms?: number | null
  group_id?: number | null
  group_name?: string
  is_global: boolean
  pinned: boolean
}

interface GiftListResponse {
  items: GiftItem[]
  total: number
  page: number
}

const loading = ref(true)
const gifts = ref<GiftItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 20
const activeTab = ref('active')
const pinBusyId = ref<number | null>(null)

const tabs = computed(() => [
  { value: 'active', label: t('gifts.filterActive') },
  { value: 'expired', label: t('gifts.filterExpired') },
])

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))

async function fetchGifts() {
  loading.value = true
  try {
    const { data } = await apiClient.get<GiftListResponse>('/user/gifts', {
      params: { status: activeTab.value, page: page.value, page_size: pageSize },
    })
    gifts.value = data.items ?? []
    total.value = data.total
  } catch (e) {
    console.error('Failed to load gifts:', e)
    gifts.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function switchTab(tab: string) {
  activeTab.value = tab
  page.value = 1
}

// 仅 active 且未过期/未耗尽的赠金可置顶。
function isPinnable(gift: GiftItem): boolean {
  return gift.status !== 'expired' && gift.status !== 'exhausted'
}

async function pin(gift: GiftItem) {
  if (!gift.id) return
  pinBusyId.value = gift.id
  try {
    await apiClient.post(`/user/gifts/${gift.id}/pin`)
    // 置顶行须置顶展示：回到第 1 页并刷新（后端排序 pinned DESC）。
    page.value = 1
    await fetchGifts()
  } catch (e) {
    console.error('Failed to pin gift:', e)
  } finally {
    pinBusyId.value = null
  }
}

async function unpin(gift: GiftItem) {
  if (!gift.id) return
  pinBusyId.value = gift.id
  try {
    await apiClient.delete(`/user/gifts/${gift.id}/pin`)
    await fetchGifts()
  } catch (e) {
    console.error('Failed to unpin gift:', e)
  } finally {
    pinBusyId.value = null
  }
}

function goPage(p: number) {
  page.value = p
}

function formatSource(source: string): string {
  const map: Record<string, string> = {
    keybind: t('gifts.sourceKeybind'),
    referral_invitee: t('gifts.sourceReferralInvitee'),
    referral_inviter: t('gifts.sourceReferralInviter'),
    recharge_discount: t('gifts.sourceRechargeDiscount'),
    oauth_first_bind: t('gifts.sourceOAuthFirstBind'),
    promo_code: t('gifts.sourcePromoCode'),
  }
  return map[source] || source
}

// ratio 模式标签：拼上具体比例（每消耗 1 充值余额同步消耗 N 赠金）。
// 无 ratio_recharge 时退回纯文案，避免显示 "比例扣除 1:"。
function ratioLabel(gift: GiftItem): string {
  const base = t('gifts.modeRatio')
  const r = gift.ratio_recharge
  if (r == null || r <= 0) return base
  return `${base} 1:${formatRatio(r)}`
}

function formatRatio(r: number): string {
  // 去除尾部多余的 0（1.5000 → 1.5，2.0000 → 2）
  return Number(r.toFixed(4)).toString()
}

function formatDate(unixMs: number): string {
  const d = new Date(unixMs)
  if (Number.isNaN(d.getTime())) return ''
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const min = String(d.getMinutes()).padStart(2, '0')
  return `${yyyy}-${mm}-${dd} ${hh}:${min}`
}

watch([activeTab, page], () => fetchGifts())

onMounted(() => fetchGifts())
</script>
