<template>
  <div class="card overflow-hidden">
    <table class="w-full border-collapse text-sm">
      <thead>
        <tr
          class="border-b border-gray-100 bg-gray-50/50 text-xs font-medium uppercase tracking-wide text-gray-500 dark:border-dark-700 dark:bg-dark-800/50 dark:text-gray-400"
        >
          <th class="px-4 py-3 text-left">{{ t('modelsPlaza.columns.model') }}</th>
          <th class="px-4 py-3 text-left">{{ t('modelsPlaza.columns.standardPrice') }}</th>
          <th class="px-4 py-3 text-left">{{ t('modelsPlaza.columns.rechargePrice') }}</th>
          <th class="w-[140px] px-4 py-3 text-left">{{ t('modelsPlaza.columns.platform') }}</th>
        </tr>
      </thead>

      <tbody v-if="loading && rows.length === 0">
        <tr>
          <td colspan="4" class="py-10 text-center">
            <Icon name="refresh" size="lg" class="inline-block animate-spin text-gray-400" />
          </td>
        </tr>
      </tbody>

      <tbody v-else-if="rows.length === 0">
        <tr>
          <td colspan="4" class="py-12 text-center">
            <Icon name="inbox" size="xl" class="mx-auto mb-3 h-12 w-12 text-gray-400" />
            <p class="text-sm text-gray-500 dark:text-gray-400">{{ emptyLabel }}</p>
          </td>
        </tr>
      </tbody>

      <tbody v-else>
        <tr
          v-for="row in rows"
          :key="`${row.model.platform}-${row.model.name}`"
          class="border-b border-gray-100/70 transition-colors last:border-b-0 hover:bg-gray-50/40 dark:border-dark-700/50 dark:hover:bg-dark-800/40"
        >
          <!-- Model name + capabilities -->
          <td class="px-4 py-3 align-top">
            <div class="font-mono text-sm font-medium text-gray-900 dark:text-white">
              {{ row.model.name }}
            </div>
            <div
              v-if="row.model.capabilities.length > 0"
              class="mt-1 flex flex-wrap gap-1"
            >
              <span
                v-for="cap in row.model.capabilities.slice(0, 4)"
                :key="cap"
                class="inline-flex items-center rounded bg-gray-100 px-1 py-0.5 text-[10px] text-gray-500 dark:bg-dark-700 dark:text-gray-400"
              >
                {{ capabilityLabel(cap) }}
              </span>
              <span
                v-if="row.model.capabilities.length > 4"
                class="text-[10px] text-gray-400"
              >
                +{{ row.model.capabilities.length - 4 }}
              </span>
            </div>
          </td>

          <!-- Standard price (input / output) -->
          <td class="px-4 py-3 align-top">
            <div class="space-y-0.5">
              <ModelPlazaPriceLine :label="t('modelsPlaza.price.input')" :value="row.standard.input" />
              <ModelPlazaPriceLine :label="t('modelsPlaza.price.output')" :value="row.standard.output" />
            </div>
          </td>

          <!-- Recharge price (input / output) -->
          <td class="px-4 py-3 align-top">
            <div class="space-y-0.5">
              <ModelPlazaPriceLine :label="t('modelsPlaza.price.input')" :value="row.recharge.input" accent />
              <ModelPlazaPriceLine :label="t('modelsPlaza.price.output')" :value="row.recharge.output" accent />
            </div>
          </td>

          <!-- Platform badge -->
          <td class="px-4 py-3 align-top">
            <span
              class="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase"
              :class="platformBadgeClass(row.model.platform as Platform)"
            >
              <PlatformIcon :platform="row.model.platform as GroupPlatform" size="xs" />
              {{ row.model.platform }}
            </span>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Icon from '@/components/icons/Icon.vue'
import PlatformIcon from '@/components/common/PlatformIcon.vue'
import ModelPlazaPriceLine from './ModelPlazaPriceLine.vue'
import type { PlazaModelRow } from '@/composables/useModelsPlaza'
import type { GroupPlatform } from '@/types'
import { platformBadgeClass, type Platform } from '@/utils/platformColors'

defineProps<{
  rows: PlazaModelRow[]
  loading: boolean
  emptyLabel: string
}>()

const { t } = useI18n()

function capabilityLabel(cap: string): string {
  return t(`modelsPlaza.capability.${cap}`, cap)
}
</script>
