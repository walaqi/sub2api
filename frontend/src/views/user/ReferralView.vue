<template>
  <AppLayout>
    <div class="mx-auto max-w-3xl space-y-6">
      <!-- Loading -->
      <div v-if="loading" class="flex items-center justify-center py-20">
        <div class="h-8 w-8 animate-spin rounded-full border-4 border-primary-500 border-t-transparent"></div>
      </div>

      <template v-else>
        <!-- Header -->
        <div class="card overflow-hidden">
          <div class="bg-gradient-to-br from-indigo-500 to-indigo-600 px-6 py-8 text-center">
            <div class="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-white/20 backdrop-blur-sm">
              <Icon name="userPlus" size="xl" class="text-white" />
            </div>
            <h1 class="text-2xl font-bold text-white">{{ t('referral.title') }}</h1>
            <p class="mt-2 text-sm text-indigo-100">{{ t('referral.subtitle') }}</p>
          </div>
        </div>

        <!-- Feature disabled -->
        <div v-if="!status?.enabled" class="card border-gray-200 bg-gray-50 p-6 dark:border-dark-700 dark:bg-dark-800/40">
          <div class="flex items-start gap-4">
            <Icon name="exclamationCircle" size="md" class="mt-0.5 text-gray-400" />
            <div>
              <h3 class="text-sm font-semibold text-gray-700 dark:text-dark-200">{{ t('referral.disabledTitle') }}</h3>
              <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">{{ t('referral.disabledBody') }}</p>
            </div>
          </div>
        </div>

        <template v-else>
          <!-- Invite link card -->
          <div class="card p-6">
            <h2 class="text-sm font-semibold text-gray-700 dark:text-dark-200">{{ t('referral.inviteLinkTitle') }}</h2>
            <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('referral.inviteLinkHint') }}</p>
            <div class="mt-3 flex items-center gap-2">
              <input
                readonly
                :value="inviteLink"
                class="input flex-1 font-mono text-sm"
                @click="($event.target as HTMLInputElement)?.select()"
              />
              <button class="btn btn-primary shrink-0" @click="copyLink">
                {{ copied ? t('referral.copied') : t('referral.copyLink') }}
              </button>
            </div>
          </div>

          <!-- Invitee reward card (if current user is an invitee) -->
          <div v-if="status?.invitee_reward" class="card border-emerald-200 bg-emerald-50 p-6 dark:border-emerald-800/50 dark:bg-emerald-900/20">
            <div class="flex items-start gap-3">
              <Icon name="sparkles" size="md" class="mt-0.5 text-emerald-600 dark:text-emerald-400" />
              <div>
                <h3 class="text-sm font-semibold text-emerald-800 dark:text-emerald-200">{{ t('referral.inviteeRewardTitle') }}</h3>
                <p class="mt-1 text-sm text-emerald-700 dark:text-emerald-300">
                  {{ status.invitee_reward.granted ? t('referral.inviteeRewardGranted', { amount: status.invitee_reward.amount }) : t('referral.inviteeRewardPending', { amount: status.invitee_reward.amount }) }}
                </p>
              </div>
            </div>
          </div>

          <!-- Inviter progress -->
          <div class="card p-6">
            <h2 class="text-sm font-semibold text-gray-700 dark:text-dark-200">{{ t('referral.inviterProgressTitle') }}</h2>
            <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('referral.inviterProgressHint') }}</p>

            <div v-if="status?.inviter_progress?.length" class="mt-4 space-y-3">
              <div
                v-for="item in status.inviter_progress"
                :key="item.invitee_id"
                class="flex items-center justify-between rounded-lg border border-gray-200 p-3 dark:border-dark-700"
              >
                <div class="flex items-center gap-3">
                  <div class="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-100 text-xs font-bold text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-400">
                    {{ item.invitee_id.toString().slice(-2) }}
                  </div>
                  <div>
                    <p class="text-sm text-gray-700 dark:text-dark-200">
                      {{ t('referral.inviteeLabel', { id: item.invitee_id }) }}
                    </p>
                    <div class="mt-1 flex items-center gap-2">
                      <div class="h-1.5 w-24 overflow-hidden rounded-full bg-gray-200 dark:bg-dark-700">
                        <div
                          class="h-full rounded-full transition-all"
                          :class="item.granted ? 'bg-emerald-500' : 'bg-indigo-500'"
                          :style="{ width: Math.min(100, (item.spend_tracked / item.threshold) * 100) + '%' }"
                        ></div>
                      </div>
                      <span class="text-xs text-gray-500 dark:text-dark-400">
                        ${{ item.spend_tracked.toFixed(2) }} / ${{ item.threshold.toFixed(2) }}
                      </span>
                    </div>
                  </div>
                </div>
                <span
                  class="rounded-md px-2 py-0.5 text-xs font-medium"
                  :class="item.granted ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' : 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-dark-300'"
                >
                  {{ item.granted ? t('referral.statusGranted') : t('referral.statusPending') }}
                </span>
              </div>
            </div>

            <div v-else class="mt-4 rounded-lg border border-dashed border-gray-300 p-6 text-center dark:border-dark-600">
              <Icon name="userPlus" size="lg" class="mx-auto text-gray-300 dark:text-dark-600" />
              <p class="mt-2 text-sm text-gray-500 dark:text-dark-400">{{ t('referral.noInvitees') }}</p>
            </div>
          </div>

          <!-- Rules -->
          <div class="card border-indigo-200 bg-indigo-50 p-6 dark:border-indigo-800/50 dark:bg-indigo-900/20">
            <h3 class="text-sm font-semibold text-indigo-800 dark:text-indigo-200">{{ t('referral.rulesTitle') }}</h3>
            <ul class="mt-2 list-inside list-disc space-y-1 text-sm text-indigo-700 dark:text-indigo-300">
              <li>{{ t('referral.rule1') }}</li>
              <li>{{ t('referral.rule2') }}</li>
              <li>{{ t('referral.rule3') }}</li>
              <li>{{ t('referral.rule4') }}</li>
            </ul>
          </div>
        </template>
      </template>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiClient } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'

const { t } = useI18n()
const authStore = useAuthStore()

interface ReferralStatusResponse {
  enabled: boolean
  invitee_reward: { granted: boolean; amount: number } | null
  inviter_progress: Array<{
    invitee_id: number
    spend_tracked: number
    threshold: number
    granted: boolean
  }>
}

const loading = ref(true)
const status = ref<ReferralStatusResponse | null>(null)
const copied = ref(false)

const inviteLink = computed(() => {
  const user = authStore.user
  if (!user) return ''
  // Use the affiliate code from user profile as the invite link
  const base = window.location.origin
  const affCode = (user as any).aff_code || ''
  return affCode ? `${base}/register?aff=${affCode}` : `${base}/register`
})

async function copyLink() {
  try {
    await navigator.clipboard.writeText(inviteLink.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    // fallback
    const input = document.createElement('input')
    input.value = inviteLink.value
    document.body.appendChild(input)
    input.select()
    document.execCommand('copy')
    document.body.removeChild(input)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  }
}

onMounted(async () => {
  try {
    const { data } = await apiClient.get<ReferralStatusResponse>('/user/referral/status')
    status.value = (data as any)?.data ?? data ?? null
  } catch {
    status.value = null
  } finally {
    loading.value = false
  }
})
</script>
