<template>
  <div
    class="group flex flex-col rounded-2xl border border-gray-200/80 bg-white/70 p-5 shadow-card backdrop-blur-xl transition-all duration-300 ease-out hover:-translate-y-1 hover:border-gray-300 hover:shadow-card-hover dark:border-dark-700/70 dark:bg-dark-800/60 dark:hover:border-primary-500/30"
  >
    <!-- Header: platform icon + model name + platform badge -->
    <div class="flex items-start gap-3">
      <span
        class="grid h-9 w-9 flex-shrink-0 place-items-center rounded-xl ring-1 ring-black/5 dark:ring-white/10"
        :class="platformTintClass"
      >
        <PlatformIcon :platform="row.model.platform as GroupPlatform" size="md" />
      </span>
      <div class="min-w-0 flex-1">
        <div class="truncate font-mono text-sm font-semibold text-gray-900 dark:text-gray-100">
          {{ row.model.name }}
        </div>
        <span
          class="mt-1 inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium uppercase"
          :class="platformBadgeClass(row.model.platform as Platform)"
        >
          {{ row.model.platform }}
        </span>
      </div>
    </div>

    <!-- Prices: standard + recharge side by side -->
    <div class="mt-4 grid grid-cols-2 gap-3">
      <div class="rounded-xl bg-gray-50/70 p-3 dark:bg-dark-900/40">
        <div class="mb-1.5 text-[11px] font-medium text-gray-500 dark:text-gray-400">
          {{ t('modelsPlaza.standardPrice') }}
        </div>
        <ModelPlazaPriceLine
          :label="t('modelsPlaza.price.input')"
          :value="row.standard.input"
        />
        <ModelPlazaPriceLine
          :label="t('modelsPlaza.price.output')"
          :value="row.standard.output"
        />
        <ModelPlazaPriceLine
          v-if="row.standard.cacheRead != null"
          :label="t('modelsPlaza.price.cacheRead')"
          :value="row.standard.cacheRead"
        />
      </div>
      <div class="rounded-xl bg-primary-50/50 p-3 dark:bg-primary-900/10">
        <div class="mb-1.5 text-[11px] font-medium text-primary-600 dark:text-primary-400">
          {{ t('modelsPlaza.rechargePrice') }}
        </div>
        <ModelPlazaPriceLine
          :label="t('modelsPlaza.price.input')"
          :value="row.recharge.input"
          accent
        />
        <ModelPlazaPriceLine
          :label="t('modelsPlaza.price.output')"
          :value="row.recharge.output"
          accent
        />
        <ModelPlazaPriceLine
          v-if="row.recharge.cacheRead != null"
          :label="t('modelsPlaza.price.cacheRead')"
          :value="row.recharge.cacheRead"
          accent
        />
      </div>
    </div>

    <!-- Per-request / image price (non-token billing modes) -->
    <div
      v-if="row.model.billing_mode !== 'token' && row.standard.perRequest != null"
      class="mt-2 flex items-center justify-between rounded-lg bg-gray-50/70 px-3 py-1.5 text-xs dark:bg-dark-900/40"
    >
      <span class="text-gray-500 dark:text-gray-400">{{ t('modelsPlaza.price.perRequest') }}</span>
      <span class="font-mono text-gray-700 dark:text-gray-300">
        {{ formatScaled(row.standard.perRequest, 1) }}
      </span>
    </div>

    <!-- Divider -->
    <div class="my-4 border-t border-gray-100 dark:border-dark-700/60"></div>

    <!-- Metadata: context / max output -->
    <div class="grid grid-cols-2 gap-2 text-xs">
      <div>
        <div class="text-[11px] text-gray-400 dark:text-gray-500">
          {{ t('modelsPlaza.contextLength') }}
        </div>
        <div class="font-mono text-gray-700 dark:text-gray-300">
          {{ formatTokens(row.model.context_length) }}
        </div>
      </div>
      <div>
        <div class="text-[11px] text-gray-400 dark:text-gray-500">
          {{ t('modelsPlaza.maxOutput') }}
        </div>
        <div class="font-mono text-gray-700 dark:text-gray-300">
          {{ formatTokens(row.model.max_output_tokens) }}
        </div>
      </div>
    </div>

    <!-- Capabilities -->
    <div v-if="row.model.capabilities.length > 0" class="mt-3 flex flex-wrap gap-1">
      <span
        v-for="cap in row.model.capabilities"
        :key="cap"
        class="inline-flex items-center rounded-md bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-600 dark:bg-dark-700 dark:text-gray-300"
      >
        {{ capabilityLabel(cap) }}
      </span>
    </div>

    <!-- Modalities -->
    <div
      v-if="row.model.input_modalities.length > 0 || row.model.output_modalities.length > 0"
      class="mt-2 flex flex-col gap-1 text-[11px] text-gray-500 dark:text-gray-400"
    >
      <div v-if="row.model.input_modalities.length > 0" class="flex items-center gap-1.5">
        <span class="text-gray-400 dark:text-gray-500">{{ t('modelsPlaza.inputModalities') }}</span>
        <span>{{ row.model.input_modalities.map(modalityLabel).join(' · ') }}</span>
      </div>
      <div v-if="row.model.output_modalities.length > 0" class="flex items-center gap-1.5">
        <span class="text-gray-400 dark:text-gray-500">{{ t('modelsPlaza.outputModalities') }}</span>
        <span>{{ row.model.output_modalities.map(modalityLabel).join(' · ') }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import PlatformIcon from '@/components/common/PlatformIcon.vue'
import ModelPlazaPriceLine from './ModelPlazaPriceLine.vue'
import type { PlazaModelRow } from '@/composables/useModelsPlaza'
import type { GroupPlatform } from '@/types'
import { platformBadgeClass, type Platform } from '@/utils/platformColors'
import { formatScaled } from '@/utils/pricing'

const props = defineProps<{
  row: PlazaModelRow
}>()

const { t } = useI18n()

const PLATFORM_TINT: Record<string, string> = {
  openai: 'text-emerald-600 dark:text-emerald-300',
  anthropic: 'text-orange-600 dark:text-orange-300',
  gemini: 'text-sky-600 dark:text-sky-300',
  antigravity: 'text-purple-600 dark:text-purple-300',
}

const platformTintClass =
  PLATFORM_TINT[props.row.model.platform] ?? 'text-gray-500 dark:text-gray-300'

function capabilityLabel(cap: string): string {
  return t(`modelsPlaza.capability.${cap}`, cap)
}

function modalityLabel(m: string): string {
  return t(`modelsPlaza.modality.${m}`, m)
}

function formatTokens(n: number): string {
  if (!n || n <= 0) return t('modelsPlaza.price.dash')
  if (n >= 1000) return `${Math.round(n / 1000)}K ${t('modelsPlaza.tokensUnit')}`
  return `${n} ${t('modelsPlaza.tokensUnit')}`
}
</script>
