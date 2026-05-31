<template>
  <AppLayout>
    <div class="space-y-6">
    <!-- 页头 -->
    <div class="flex flex-col gap-1">
      <h1 class="text-xl font-semibold text-gray-900 dark:text-white">
        {{ t('admin.abuse.title') }}
      </h1>
      <p class="text-sm text-gray-500 dark:text-gray-400">
        {{ t('admin.abuse.description') }}
      </p>
    </div>

    <!-- 临时限流配置 -->
    <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-base font-medium text-gray-900 dark:text-white">
            {{ t('admin.abuse.throttle.title') }}
          </h2>
          <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {{ t('admin.abuse.throttle.hint') }}
          </p>
        </div>
        <Toggle v-model="throttleForm.enabled" />
      </div>

      <div class="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <label class="block">
          <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.abuse.throttle.ratePercent') }}</span>
          <input v-model.number="throttleForm.rate_percent" type="number" min="1" max="100"
            class="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <label class="block">
          <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.abuse.throttle.floorRpm') }}</span>
          <input v-model.number="throttleForm.floor_rpm" type="number" min="1"
            class="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <label class="block">
          <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.abuse.throttle.minUsers') }}</span>
          <input v-model.number="throttleForm.min_users" type="number" min="2"
            class="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <label class="block">
          <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.abuse.throttle.windowHours') }}</span>
          <input v-model.number="throttleForm.window_hours" type="number" min="1"
            class="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <label class="block">
          <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.abuse.throttle.intervalMin') }}</span>
          <input v-model.number="throttleForm.interval_min" type="number" min="1"
            class="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <label class="block">
          <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.abuse.throttle.ttlMinutes') }}</span>
          <input v-model.number="throttleForm.ttl_minutes" type="number" min="1"
            class="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
      </div>

      <div class="mt-4 flex items-center gap-3">
        <button type="button" :disabled="savingSettings"
          class="rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
          @click="saveSettings">
          {{ savingSettings ? t('common.saving') : t('common.save') }}
        </button>
        <span class="text-xs text-gray-400">{{ t('admin.abuse.throttle.crossGuardNote') }}</span>
      </div>
    </div>

    <!-- 当前被自动限流的用户（R8 可观测性） -->
    <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
      <div class="flex items-center justify-between">
        <h2 class="text-base font-medium text-gray-900 dark:text-white">
          {{ t('admin.abuse.throttled.title') }}
          <span class="ml-2 text-sm font-normal text-gray-400">({{ throttled.length }})</span>
        </h2>
        <div class="flex items-center gap-2">
          <button type="button" class="rounded-md border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 dark:border-dark-600 dark:hover:bg-dark-800"
            @click="loadThrottled">
            {{ t('common.refresh') }}
          </button>
          <button type="button" :disabled="!throttled.length"
            class="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:hover:bg-red-900/20"
            @click="showClearDialog = true">
            {{ t('admin.abuse.throttled.clearNow') }}
          </button>
        </div>
      </div>
      <div v-if="!throttled.length" class="mt-4 text-sm text-gray-400">
        {{ t('admin.abuse.throttled.empty') }}
      </div>
      <table v-else class="mt-4 w-full text-sm">
        <thead>
          <tr class="text-left text-gray-500 dark:text-gray-400">
            <th class="py-2 pr-4 font-medium">{{ t('admin.abuse.throttled.userId') }}</th>
            <th class="py-2 pr-4 font-medium">{{ t('admin.abuse.throttled.dimensions') }}</th>
            <th class="py-2 pr-4 font-medium">{{ t('admin.abuse.throttled.markedAt') }}</th>
            <th class="py-2 pr-4 font-medium">{{ t('admin.abuse.throttled.remaining') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in throttled" :key="e.user_id" class="border-t border-gray-100 dark:border-dark-800">
            <td class="py-2 pr-4 font-mono text-gray-900 dark:text-white">{{ e.user_id }}</td>
            <td class="py-2 pr-4">
              <span v-for="d in e.dimensions" :key="d"
                class="mr-1 inline-block rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600 dark:bg-dark-700 dark:text-gray-300">
                {{ dimensionLabel(d) }}
              </span>
            </td>
            <td class="py-2 pr-4 text-gray-500">{{ formatTime(e.marked_at) }}</td>
            <td class="py-2 pr-4 text-gray-500">{{ formatRemaining(e.ttl_seconds) }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 疑似团伙查询 -->
    <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
      <div class="flex flex-wrap items-end gap-3">
        <h2 class="mr-auto text-base font-medium text-gray-900 dark:text-white">
          {{ t('admin.abuse.suspects.title') }}
        </h2>
        <label class="block">
          <span class="text-xs text-gray-500">{{ t('admin.abuse.suspects.windowHours') }}</span>
          <input v-model.number="query.windowHours" type="number" min="1"
            class="mt-1 w-28 rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <label class="block">
          <span class="text-xs text-gray-500">{{ t('admin.abuse.suspects.minUsers') }}</span>
          <input v-model.number="query.minUsers" type="number" min="2"
            class="mt-1 w-24 rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-dark-600 dark:bg-dark-800 dark:text-white" />
        </label>
        <button type="button" :disabled="loadingSuspects"
          class="rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
          @click="loadSuspects">
          {{ loadingSuspects ? t('common.loading') : t('admin.abuse.suspects.scan') }}
        </button>
      </div>

      <!-- 批量操作栏 -->
      <div v-if="selectedUserIds.length"
        class="mt-4 flex items-center justify-between rounded-md bg-primary-50 px-4 py-2 dark:bg-primary-900/20">
        <span class="text-sm text-primary-700 dark:text-primary-300">
          {{ t('admin.abuse.suspects.selectedCount', { count: selectedUserIds.length }) }}
        </span>
        <button type="button" :disabled="disabling"
          class="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          @click="showDisableDialog = true">
          {{ t('admin.abuse.suspects.disableSelected') }}
        </button>
      </div>

      <div v-if="!groups.length && scanned" class="mt-4 text-sm text-gray-400">
        {{ t('admin.abuse.suspects.empty') }}
      </div>

      <div v-for="group in groups" :key="group.dimension + ':' + group.value"
        class="mt-4 rounded-md border border-gray-200 dark:border-dark-700">
        <div class="flex items-center justify-between gap-2 border-b border-gray-100 bg-gray-50 px-4 py-2 dark:border-dark-800 dark:bg-dark-800/50">
          <div class="flex items-center gap-2">
            <input type="checkbox" class="h-4 w-4 rounded border-gray-300"
              :checked="isGroupFullySelected(group)"
              :indeterminate.prop="isGroupPartiallySelected(group)"
              :title="t('admin.abuse.suspects.selectGroup')"
              @change="toggleGroup(group)" />
            <span class="rounded px-2 py-0.5 text-xs font-medium" :class="dimensionBadgeClass(group.dimension)">
              {{ dimensionLabel(group.dimension) }}
            </span>
            <span class="font-mono text-sm text-gray-700 dark:text-gray-200">{{ group.value }}</span>
            <span v-if="group.dimension === 'ip'" class="text-xs text-amber-600 dark:text-amber-400">
              {{ t('admin.abuse.suspects.ipDisplayOnly') }}
            </span>
          </div>
          <span class="text-xs text-gray-500">
            {{ t('admin.abuse.suspects.userCount', { count: group.user_count }) }} ·
            {{ t('admin.abuse.suspects.requests', { count: group.total_requests }) }}
          </span>
        </div>
        <table class="w-full text-sm">
          <tbody>
            <tr v-for="m in group.members" :key="group.value + ':' + m.user_id"
              class="border-t border-gray-100 dark:border-dark-800">
              <td class="w-10 py-2 pl-4">
                <input type="checkbox" :checked="selectedUserIds.includes(m.user_id)"
                  class="h-4 w-4 rounded border-gray-300"
                  @change="toggleUser(m.user_id)" />
              </td>
              <td class="py-2 pr-4 font-mono text-gray-900 dark:text-white">{{ m.user_id }}</td>
              <td class="py-2 pr-4 text-gray-600 dark:text-gray-300">{{ m.email || m.username || '-' }}</td>
              <td class="py-2 pr-4 text-gray-500">{{ t('admin.abuse.suspects.requests', { count: m.requests }) }}</td>
              <td class="py-2 pr-4 text-gray-400">{{ formatTime(m.first_seen) }} ~ {{ formatTime(m.last_seen) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <ConfirmDialog :show="showDisableDialog" :title="t('admin.abuse.suspects.disableTitle')"
      :message="t('admin.abuse.suspects.disableConfirm', { count: selectedUserIds.length })"
      :confirm-text="t('admin.abuse.suspects.disableSelected')" :cancel-text="t('common.cancel')" :danger="true"
      @confirm="confirmDisable" @cancel="showDisableDialog = false" />

    <ConfirmDialog :show="showClearDialog" :title="t('admin.abuse.throttled.clearNow')"
      :message="t('admin.abuse.throttled.clearConfirm')" :confirm-text="t('admin.abuse.throttled.clearNow')"
      :cancel-text="t('common.cancel')" :danger="true" @confirm="confirmClear" @cancel="showClearDialog = false" />
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import Toggle from '@/components/common/Toggle.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAppStore } from '@/stores/app'
import { abuseAPI } from '@/api/admin/abuse'
import type {
  SuspectGroup,
  SuspectThrottleSettings,
  ThrottledEntry,
} from '@/api/admin/abuse'

const { t } = useI18n()
const appStore = useAppStore()

// ── 限流配置 ──
const throttleForm = reactive<SuspectThrottleSettings>({
  enabled: false,
  rate_percent: 50,
  floor_rpm: 30,
  min_users: 3,
  window_hours: 24,
  interval_min: 5,
  ttl_minutes: 30,
})
const savingSettings = ref(false)

async function loadSettings() {
  try {
    const s = await abuseAPI.getThrottleSettings()
    Object.assign(throttleForm, s)
  } catch (e) {
    appStore.showError(t('admin.abuse.errors.loadSettings'))
  }
}

async function saveSettings() {
  savingSettings.value = true
  try {
    const saved = await abuseAPI.updateThrottleSettings({ ...throttleForm })
    Object.assign(throttleForm, saved)
    appStore.showSuccess(t('admin.abuse.throttle.saved'))
  } catch (e) {
    appStore.showError(t('admin.abuse.errors.saveSettings'))
  } finally {
    savingSettings.value = false
  }
}

// ── 被限流列表 ──
const throttled = ref<ThrottledEntry[]>([])
const showClearDialog = ref(false)

async function loadThrottled() {
  try {
    const resp = await abuseAPI.listThrottled()
    throttled.value = resp.entries || []
  } catch (e) {
    appStore.showError(t('admin.abuse.errors.loadThrottled'))
  }
}

async function confirmClear() {
  showClearDialog.value = false
  try {
    const resp = await abuseAPI.clearThrottled()
    appStore.showSuccess(t('admin.abuse.throttled.cleared', { count: resp.cleared }))
    await loadThrottled()
  } catch (e) {
    appStore.showError(t('admin.abuse.errors.clear'))
  }
}

// ── 疑似团伙 ──
const query = reactive({ windowHours: 24, minUsers: 3 })
const groups = ref<SuspectGroup[]>([])
const loadingSuspects = ref(false)
const scanned = ref(false)
const selectedUserIds = ref<number[]>([])

async function loadSuspects() {
  loadingSuspects.value = true
  try {
    const resp = await abuseAPI.listSuspects({
      window_hours: query.windowHours,
      min_users: query.minUsers,
    })
    groups.value = resp.groups || []
    scanned.value = true
    // 清理已不在结果中的选择。
    const present = new Set<number>()
    for (const g of groups.value) for (const m of g.members) present.add(m.user_id)
    selectedUserIds.value = selectedUserIds.value.filter((id) => present.has(id))
  } catch (e) {
    appStore.showError(t('admin.abuse.errors.loadSuspects'))
  } finally {
    loadingSuspects.value = false
  }
}

function toggleUser(userId: number) {
  const idx = selectedUserIds.value.indexOf(userId)
  if (idx >= 0) selectedUserIds.value.splice(idx, 1)
  else selectedUserIds.value.push(userId)
}

// 团伙级一键全选：勾选即选中该组所有成员，取消则移除该组所有成员。
function isGroupFullySelected(group: SuspectGroup): boolean {
  return group.members.length > 0 && group.members.every((m) => selectedUserIds.value.includes(m.user_id))
}

function isGroupPartiallySelected(group: SuspectGroup): boolean {
  const some = group.members.some((m) => selectedUserIds.value.includes(m.user_id))
  return some && !isGroupFullySelected(group)
}

function toggleGroup(group: SuspectGroup) {
  const ids = group.members.map((m) => m.user_id)
  if (isGroupFullySelected(group)) {
    selectedUserIds.value = selectedUserIds.value.filter((id) => !ids.includes(id))
  } else {
    const set = new Set(selectedUserIds.value)
    for (const id of ids) set.add(id)
    selectedUserIds.value = Array.from(set)
  }
}

// ── 批量禁用 ──
const showDisableDialog = ref(false)
const disabling = ref(false)

async function confirmDisable() {
  showDisableDialog.value = false
  if (!selectedUserIds.value.length) return
  disabling.value = true
  try {
    const result = await abuseAPI.bulkUpdateUsers({
      user_ids: [...selectedUserIds.value],
      status: 'disabled',
    })
    appStore.showSuccess(
      t('admin.abuse.suspects.disableResult', {
        success: result.success,
        skipped: result.skipped,
        failed: result.failed,
      })
    )
    selectedUserIds.value = []
    await loadSuspects()
  } catch (e) {
    appStore.showError(t('admin.abuse.errors.disable'))
  } finally {
    disabling.value = false
  }
}

// ── 展示辅助 ──
function dimensionLabel(dim: string): string {
  const key = `admin.abuse.dimensions.${dim}`
  const label = t(key)
  return label === key ? dim : label
}

function dimensionBadgeClass(dim: string): string {
  switch (dim) {
    case 'device':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
    case 'fingerprint':
      return 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300'
    case 'ip':
      return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-gray-300'
  }
}

function formatTime(iso: string): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '-'
  return d.toLocaleString()
}

function formatRemaining(seconds: number): string {
  if (!seconds || seconds <= 0) return '-'
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  if (m <= 0) return `${s}s`
  return `${m}m ${s}s`
}

onMounted(async () => {
  await Promise.all([loadSettings(), loadThrottled()])
})
</script>

