<template>
  <AppLayout>
    <div class="space-y-6">
      <div v-if="loading" class="flex justify-center py-12">
        <div
          class="h-8 w-8 animate-spin rounded-full border-2 border-primary-500 border-t-transparent"
        ></div>
      </div>

      <template v-else-if="detail">
        <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div class="card p-5">
            <p class="flex items-center gap-1.5 text-sm text-gray-500 dark:text-dark-400">
              <Icon name="dollar" size="sm" class="text-primary-500" />
              {{ t('affiliate.stats.rebateRate') }}
            </p>
            <p class="mt-2 text-2xl font-semibold text-primary-600 dark:text-primary-400">
              {{ formattedRebateRate }}<span class="ml-0.5 text-base font-medium">%</span>
            </p>
            <p class="mt-1 text-xs text-gray-400 dark:text-dark-500">
              {{ t('affiliate.stats.rebateRateHint') }}
            </p>
          </div>
          <div class="card p-5">
            <p class="text-sm text-gray-500 dark:text-dark-400">{{ t('affiliate.stats.invitedUsers') }}</p>
            <p class="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">
              {{ formatCount(detail.aff_count) }}
            </p>
          </div>
          <div class="card p-5">
            <p class="text-sm text-gray-500 dark:text-dark-400">{{ t('affiliate.stats.availableQuota') }}</p>
            <p class="mt-2 text-2xl font-semibold text-emerald-600 dark:text-emerald-400">
              {{ formatCurrency(detail.aff_quota) }}
            </p>
          </div>
          <div class="card p-5">
            <p class="text-sm text-gray-500 dark:text-dark-400">{{ t('affiliate.stats.totalQuota') }}</p>
            <p class="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">
              {{ formatCurrency(detail.aff_history_quota) }}
            </p>
            <p v-if="detail.aff_frozen_quota > 0" class="mt-1 text-xs text-amber-600 dark:text-amber-400">
              {{ t('affiliate.stats.frozenQuota') }}: {{ formatCurrency(detail.aff_frozen_quota) }}
            </p>
          </div>
        </div>

        <!-- 超级邀请开启时：规则说明 + 资格进度（叠加在返利页上） -->
        <div
          v-if="superReferral?.enabled"
          class="card border-indigo-200 bg-indigo-50 p-6 dark:border-indigo-800/50 dark:bg-indigo-900/20"
        >
          <div class="flex items-center gap-2">
            <Icon name="sparkles" size="md" class="text-indigo-600 dark:text-indigo-400" />
            <span class="rounded-md bg-indigo-100 px-2 py-0.5 text-xs font-semibold text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
              {{ t('affiliate.superReferral.enabledBadge') }}
            </span>
          </div>
          <p class="mt-3 text-sm text-indigo-800 dark:text-indigo-200">{{ superReferralRule }}</p>
          <p
            v-if="!superReferral.eligible"
            class="mt-2 text-sm font-medium text-amber-700 dark:text-amber-300"
          >
            {{ eligibilityHint }}
          </p>

          <!-- 当前用户作为被邀请人的注册赠金状态（原 /referral 页能力，合并保留） -->
          <div
            v-if="superReferral.invitee_reward"
            class="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 p-3 dark:border-emerald-800/50 dark:bg-emerald-900/20"
          >
            <p class="text-sm font-medium text-emerald-800 dark:text-emerald-200">{{ t('affiliate.superReferral.inviteeRewardTitle') }}</p>
            <p class="mt-1 text-sm text-emerald-700 dark:text-emerald-300">
              {{ superReferral.invitee_reward.granted
                ? t('affiliate.superReferral.inviteeRewardGranted', { amount: formatCurrency(superReferral.invitee_reward.amount) })
                : t('affiliate.superReferral.inviteeRewardPending', { amount: formatCurrency(superReferral.invitee_reward.amount) }) }}
            </p>
          </div>

          <!-- 邀请人达标奖励发放机会（原 /referral 页能力，仅配额开关开时展示） -->
          <div
            v-if="superReferral.eligible && superReferral.inviter_reward_quota_enabled"
            class="mt-4 rounded-lg border border-indigo-200 bg-white/60 p-3 dark:border-indigo-800/50 dark:bg-dark-900/40"
          >
            <p class="text-sm font-medium text-indigo-800 dark:text-indigo-200">{{ t('affiliate.superReferral.rewardQuotaTitle') }}</p>
            <p class="mt-1 text-sm text-indigo-700 dark:text-indigo-300">
              {{ t('affiliate.superReferral.rewardQuotaRemaining', { count: superReferral.inviter_reward_quota ?? 0 }) }}
            </p>
            <p class="mt-1 text-xs text-indigo-600/80 dark:text-indigo-300/70">{{ t('affiliate.superReferral.rewardQuotaHint') }}</p>
          </div>
        </div>

        <div class="card p-6">
          <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('affiliate.title') }}</h3>
          <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">{{ t('affiliate.description') }}</p>

          <div class="mt-5 grid gap-4 md:grid-cols-2">
            <div class="space-y-2">
              <p class="text-sm font-medium text-gray-700 dark:text-gray-300">{{ t('affiliate.yourCode') }}</p>
              <div class="flex items-center gap-2 rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 dark:border-dark-700 dark:bg-dark-900">
                <code class="flex-1 truncate text-sm font-semibold text-gray-900 dark:text-white">{{ detail.aff_code }}</code>
                <button class="btn btn-secondary btn-sm" @click="copyCode">
                  <Icon name="copy" size="sm" />
                  <span>{{ t('affiliate.copyCode') }}</span>
                </button>
              </div>
            </div>

            <div class="space-y-2">
              <p class="text-sm font-medium text-gray-700 dark:text-gray-300">{{ t('affiliate.inviteLink') }}</p>
              <div class="flex items-center gap-2 rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 dark:border-dark-700 dark:bg-dark-900">
                <code class="flex-1 truncate text-sm text-gray-700 dark:text-gray-300">{{ inviteLink }}</code>
                <button class="btn btn-secondary btn-sm" @click="copyInviteLink">
                  <Icon name="copy" size="sm" />
                  <span>{{ t('affiliate.copyLink') }}</span>
                </button>
              </div>
            </div>
          </div>

          <div class="mt-5 rounded-xl border border-primary-200 bg-primary-50 p-4 dark:border-primary-900/40 dark:bg-primary-900/20">
            <p class="text-sm font-medium text-primary-800 dark:text-primary-200">{{ t('affiliate.tips.title') }}</p>
            <ul class="mt-2 space-y-1 text-sm text-primary-700 dark:text-primary-300">
              <li>1. {{ t('affiliate.tips.line1') }}</li>
              <li>2. {{ t('affiliate.tips.line2', { rate: `${formattedRebateRate}%` }) }}</li>
              <li>3. {{ t('affiliate.tips.line3') }}</li>
              <li v-if="detail.aff_frozen_quota > 0">4. {{ t('affiliate.tips.line4') }}</li>
            </ul>
          </div>
        </div>

        <div class="card p-6">
          <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('affiliate.transfer.title') }}</h3>
              <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">{{ t('affiliate.transfer.description') }}</p>
            </div>
            <button
              class="btn btn-primary"
              :disabled="transferring || detail.aff_quota <= 0"
              @click="transferQuota"
            >
              <Icon v-if="transferring" name="refresh" size="sm" class="animate-spin" />
              <Icon v-else name="dollar" size="sm" />
              <span>{{ transferring ? t('affiliate.transfer.transferring') : t('affiliate.transfer.button') }}</span>
            </button>
          </div>
          <p v-if="detail.aff_quota <= 0" class="mt-3 text-sm text-amber-600 dark:text-amber-400">
            {{ t('affiliate.transfer.empty') }}
          </p>
        </div>

        <div class="card p-6">
          <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('affiliate.invitees.title') }}</h3>
          <div v-if="detail.invitees.length === 0" class="mt-4 rounded-xl border border-dashed border-gray-300 p-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400">
            {{ t('affiliate.invitees.empty') }}
          </div>
          <div v-else class="mt-4 overflow-x-auto">
            <table class="w-full min-w-[560px] text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 text-gray-500 dark:border-dark-700 dark:text-dark-400">
                  <th class="px-3 py-2 font-medium">{{ t('affiliate.invitees.columns.email') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('affiliate.invitees.columns.username') }}</th>
                  <th class="px-3 py-2 font-medium text-right">{{ t('affiliate.invitees.columns.rebate') }}</th>
                  <th v-if="superReferral?.enabled && superReferral.eligible" class="px-3 py-2 font-medium">{{ t('affiliate.superReferral.progress.header') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('affiliate.invitees.columns.joinedAt') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="item in detail.invitees"
                  :key="item.user_id"
                  class="border-b border-gray-100 last:border-b-0 dark:border-dark-800"
                >
                  <td class="px-3 py-3 text-gray-900 dark:text-white">{{ item.email || '-' }}</td>
                  <td class="px-3 py-3 text-gray-700 dark:text-gray-300">{{ item.username || '-' }}</td>
                  <td class="px-3 py-3 text-right font-medium text-emerald-600 dark:text-emerald-400">{{ formatCurrency(item.total_rebate) }}</td>
                  <td v-if="superReferral?.enabled && superReferral.eligible" class="px-3 py-3">
                    <div v-if="progressByInvitee.get(item.user_id)" class="flex items-center gap-2">
                      <div class="h-1.5 w-20 overflow-hidden rounded-full bg-gray-200 dark:bg-dark-700">
                        <div
                          class="h-full rounded-full transition-all"
                          :class="progressByInvitee.get(item.user_id)!.granted ? 'bg-emerald-500' : 'bg-indigo-500'"
                          :style="{ width: progressPercent(progressByInvitee.get(item.user_id)!) + '%' }"
                        ></div>
                      </div>
                      <span class="text-xs text-gray-500 dark:text-dark-400">
                        {{ progressLabel(progressByInvitee.get(item.user_id)!) }}
                      </span>
                    </div>
                    <span v-else class="text-xs text-gray-400 dark:text-dark-500">-</span>
                  </td>
                  <td class="px-3 py-3 text-gray-700 dark:text-gray-300">{{ formatDateTime(item.created_at) || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'
import userAPI from '@/api/user'
import type { UserAffiliateDetail, ReferralStatus, ReferralInviteeProgress } from '@/types'
import { useAppStore } from '@/stores/app'
import { useAuthStore } from '@/stores/auth'
import { useClipboard } from '@/composables/useClipboard'
import { formatCurrency, formatDateTime } from '@/utils/format'
import { extractApiErrorMessage } from '@/utils/apiError'

const { t } = useI18n()
const appStore = useAppStore()
const authStore = useAuthStore()
const { copyToClipboard } = useClipboard()

const loading = ref(true)
const transferring = ref(false)
const detail = ref<UserAffiliateDetail | null>(null)
const superReferral = ref<ReferralStatus | null>(null)

// 被邀请人 id -> 超级邀请达标进度，用于在返利邀请列表里叠加进度列。
// 返利列表的 email 是打码的，无法按邮箱关联；后端在 inviter_progress 里带了 invitee_id。
const progressByInvitee = computed(() => {
  const map = new Map<number, ReferralInviteeProgress>()
  for (const p of superReferral.value?.inviter_progress ?? []) {
    map.set(p.invitee_id, p)
  }
  return map
})

// 超级邀请规则说明：注册即得 X / 消费达标 Y / 你得 Z。
const superReferralRule = computed(() => {
  const s = superReferral.value
  if (!s) return ''
  return t('affiliate.superReferral.rule', {
    invitee: formatCurrency(s.invitee_amount),
    threshold: formatCurrency(s.spend_threshold),
    inviter: formatCurrency(s.inviter_amount),
  })
})

// 资格未达标时的提示：recharge 模式给出"还需充值多少"，否则给出通用文案。
const eligibilityHint = computed(() => {
  const s = superReferral.value
  if (!s) return ''
  if (s.eligibility_grant_mode === 'recharge' && s.eligibility_recharge_remaining > 0) {
    return t('affiliate.superReferral.rechargeNeeded', {
      amount: formatCurrency(s.eligibility_recharge_remaining),
    })
  }
  return t('affiliate.superReferral.rechargeNeededAny')
})

function progressPercent(p: ReferralInviteeProgress): number {
  if (p.threshold <= 0) return p.granted ? 100 : 0
  return Math.min(100, (p.spend_tracked / p.threshold) * 100)
}

function progressLabel(p: ReferralInviteeProgress): string {
  if (p.granted) return t('affiliate.superReferral.progress.statusGranted')
  if (p.blocked_by_quota) return t('affiliate.superReferral.progress.statusBlockedByQuota')
  if (p.reward_eligible === false) return t('affiliate.superReferral.progress.statusIneligible')
  return `${formatCurrency(p.spend_tracked)} / ${formatCurrency(p.threshold)}`
}

const inviteLink = computed(() => {
  if (!detail.value) return ''
  if (typeof window === 'undefined') return `/register?aff=${encodeURIComponent(detail.value.aff_code)}`
  return `${window.location.origin}/register?aff=${encodeURIComponent(detail.value.aff_code)}`
})

// Rebate rate is a percentage in the range [0, 100]; backend already clamps it.
// We trim trailing zeros (e.g. 20.00 → "20", 12.50 → "12.5") for a cleaner UI.
const formattedRebateRate = computed(() => {
  const v = detail.value?.effective_rebate_rate_percent ?? 0
  const rounded = Math.round(v * 100) / 100
  return Number.isInteger(rounded) ? String(rounded) : rounded.toString()
})

function formatCount(value: number): string {
  return value.toLocaleString()
}

async function loadAffiliateDetail(silent = false): Promise<void> {
  if (!silent) {
    loading.value = true
  }
  try {
    // 返利明细为主数据；超级邀请状态为叠加信息，单独失败不应阻断返利页展示。
    const [affiliate, referral] = await Promise.all([
      userAPI.getAffiliateDetail(),
      userAPI.getReferralStatus().catch(() => null),
    ])
    detail.value = affiliate
    superReferral.value = referral
  } catch (error) {
    appStore.showError(extractApiErrorMessage(error, t('affiliate.loadFailed')))
  } finally {
    if (!silent) {
      loading.value = false
    }
  }
}

async function copyCode(): Promise<void> {
  if (!detail.value?.aff_code) return
  await copyToClipboard(detail.value.aff_code, t('affiliate.codeCopied'))
}

async function copyInviteLink(): Promise<void> {
  if (!inviteLink.value) return
  await copyToClipboard(inviteLink.value, t('affiliate.linkCopied'))
}

async function transferQuota(): Promise<void> {
  if (!detail.value || detail.value.aff_quota <= 0 || transferring.value) return
  transferring.value = true
  try {
    const resp = await userAPI.transferAffiliateQuota()
    appStore.showSuccess(t('affiliate.transfer.success', { amount: formatCurrency(resp.transferred_quota) }))
    await Promise.all([
      loadAffiliateDetail(true),
      authStore.refreshUser().catch(() => undefined),
    ])
  } catch (error) {
    appStore.showError(extractApiErrorMessage(error, t('affiliate.transferFailed')))
  } finally {
    transferring.value = false
  }
}

onMounted(() => {
  void loadAffiliateDetail()
})
</script>
