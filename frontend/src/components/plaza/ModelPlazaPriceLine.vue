<template>
  <div class="flex items-baseline justify-between gap-2">
    <span class="text-[11px] uppercase tracking-wide text-gray-400 dark:text-gray-500">
      {{ label }}
    </span>
    <span class="font-mono text-xs" :class="valueClass">{{ display }}</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatScaled } from '@/utils/pricing'

/**
 * ModelPlazaPriceLine — 一行价格展示（标签 + 值）。
 *
 * value 为按 token 的 USD 单价，默认按「每 1M token」放大显示；perRequest
 * 模式传 scale=1。null → 显示占位符 "-"。
 */
const props = withDefaults(
  defineProps<{
    label: string
    value: number | null
    /** 放大系数：token 价用 1_000_000，按次价用 1。 */
    scale?: number
    /** 强调色（充值价用主题色，标准价用常规灰）。 */
    accent?: boolean
  }>(),
  { value: null, scale: 1_000_000, accent: false },
)

const { t } = useI18n()

const display = computed(() => {
  if (props.value == null) return t('modelsPlaza.price.dash')
  if (props.value === 0) return t('modelsPlaza.price.free')
  return formatScaled(props.value, props.scale)
})

const valueClass = computed(() =>
  props.accent
    ? 'font-semibold text-primary-600 dark:text-primary-400'
    : 'text-gray-700 dark:text-gray-300',
)
</script>
