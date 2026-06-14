<template>
  <AppLayout>
    <div class="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
      <!-- Header -->
      <div class="flex flex-col gap-1">
        <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
          {{ t('chatPlaza.title') }}
        </h1>
        <p class="text-sm text-gray-500 dark:text-gray-400">
          {{ t('chatPlaza.description') }}
        </p>
      </div>

      <!-- Intro / security note -->
      <div class="rounded-xl border border-blue-100 bg-blue-50 p-4 dark:border-blue-900/40 dark:bg-blue-900/20">
        <p class="text-sm text-blue-800 dark:text-blue-200">{{ t('chatPlaza.intro') }}</p>
      </div>

      <!-- Session config: group + quota cap -->
      <div class="card space-y-4 p-5">
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <!-- Group selector -->
          <div>
            <label class="input-label">{{ t('chatPlaza.group') }}</label>
            <select
              v-model="selectedGroupId"
              class="input"
              :disabled="groups.length === 0"
            >
              <option v-if="groups.length === 0" :value="null">
                {{ t('chatPlaza.noGroup') }}
              </option>
              <option v-for="g in groups" :key="g.id" :value="g.id">
                {{ g.name }} (×{{ g.rate_multiplier }})
              </option>
            </select>
          </div>

          <!-- Quota cap -->
          <div>
            <label class="input-label">{{ t('chatPlaza.quotaLimit') }}</label>
            <input
              v-model.number="quotaLimit"
              type="number"
              min="0"
              step="0.5"
              class="input"
              :placeholder="t('chatPlaza.quotaPlaceholder')"
            />
            <p class="input-hint">{{ t('chatPlaza.quotaLimitHint') }}</p>
          </div>
        </div>

        <div class="flex items-start gap-2 rounded-lg bg-amber-50 p-3 dark:bg-amber-900/20">
          <Icon name="infoCircle" size="md" class="mt-0.5 flex-shrink-0 text-amber-500" />
          <p class="text-sm text-amber-700 dark:text-amber-300">{{ t('chatPlaza.securityNote') }}</p>
        </div>
      </div>

      <!-- Clients -->
      <div class="space-y-3">
        <div class="flex flex-col gap-0.5">
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
            {{ t('chatPlaza.clients') }}
          </h2>
          <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('chatPlaza.clientsHint') }}</p>
        </div>

        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div
            v-for="preset in presets"
            :key="preset.id"
            class="card flex items-center justify-between gap-3 p-4"
          >
            <div class="min-w-0">
              <p class="truncate font-medium text-gray-900 dark:text-white">{{ preset.name }}</p>
              <span
                class="mt-1 inline-block rounded px-1.5 py-0.5 text-xs"
                :class="preset.type === 'web'
                  ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                  : 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300'"
              >
                {{ preset.type === 'web' ? t('chatPlaza.webClient') : t('chatPlaza.appClient') }}
              </span>
            </div>
            <button
              type="button"
              class="btn btn-primary flex-shrink-0"
              :disabled="opening"
              @click="launch(preset)"
            >
              {{ opening && openingId === preset.id ? t('chatPlaza.opening') : t('chatPlaza.open') }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'
import { keysAPI, userGroupsAPI } from '@/api'
import { useAppStore } from '@/stores/app'
import {
  CHAT_PRESETS,
  resolveChatUrl,
  resolveServerRoot,
  openChatLink,
  type ChatPreset,
} from '@/lib/chatLinks'
import type { Group } from '@/types'

const { t } = useI18n()
const appStore = useAppStore()

const presets = CHAT_PRESETS
const groups = ref<Group[]>([])
const selectedGroupId = ref<number | null>(null)
const quotaLimit = ref<number | null>(5)
const opening = ref(false)
const openingId = ref<string | null>(null)

// Temporary key lifetime. The keys API only supports day-level expiry, so 1 day
// is the shortest a deep-link key can live.
const TEMP_KEY_EXPIRES_IN_DAYS = 1

onMounted(async () => {
  try {
    const list = await userGroupsAPI.getAvailable()
    groups.value = list
    if (list.length > 0) {
      const def = list.find((g) => g.name === 'default') ?? list[0]
      selectedGroupId.value = def.id
    }
  } catch {
    // Non-fatal: group is optional; the temp key falls back to the user's default.
    appStore.showError(t('chatPlaza.failed'))
  }
})

async function launch(preset: ChatPreset) {
  if (opening.value) return

  const quota = quotaLimit.value
  if (quota == null || !(quota > 0)) {
    appStore.showError(t('chatPlaza.quotaInvalid'))
    return
  }

  opening.value = true
  openingId.value = preset.id
  appStore.showInfo(t('chatPlaza.creatingKey'))

  try {
    // 方案1: mint a short-lived, quota-capped key so the real key never leaves
    // this page. The plaintext key is returned on create.
    const name = `chat-plaza-${preset.id}-${Date.now()}`
    const created = await keysAPI.create(
      name,
      selectedGroupId.value ?? undefined,
      undefined,
      undefined,
      undefined,
      quota,
      TEMP_KEY_EXPIRES_IN_DAYS,
    )

    const serverAddress = resolveServerRoot(appStore.apiBaseUrl)
    const url = resolveChatUrl({
      template: preset.url,
      apiKey: created.key,
      serverAddress,
    })

    appStore.showSuccess(t('chatPlaza.keyReady', { client: preset.name }))
    openChatLink(url, preset.type)
  } catch {
    appStore.showError(t('chatPlaza.failed'))
  } finally {
    opening.value = false
    openingId.value = null
  }
}
</script>
