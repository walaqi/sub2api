<template>
  <div class="w-full">
    <label v-if="label" class="input-label mb-1.5 block">
      {{ label }}
    </label>
    <div class="relative">
      <textarea
        ref="textareaRef"
        :value="jsonText"
        :disabled="disabled"
        :placeholder="placeholderText"
        :rows="rows"
        :class="[
          'input w-full font-mono text-sm transition-all duration-200 resize-y',
          hasError ? 'input-error ring-2 ring-red-500/20' : '',
          disabled ? 'cursor-not-allowed bg-gray-100 opacity-60 dark:bg-dark-900' : ''
        ]"
        @input="handleInput"
        @blur="handleBlur"
      ></textarea>
    </div>
    <p v-if="hasError" class="input-error-text mt-1.5">
      {{ errorMessage }}
    </p>
    <p v-else-if="hint" class="input-hint mt-1.5">
      {{ hint }}
    </p>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useI18n } from 'vue-i18n'

// 分组「按模型的 5h USD 限额」JSON 编辑器：值为正数（USD 上限），精确模型名为 key。
// 与 ModelMappingJsonEditor 结构一致，但值类型为 number 并校验为正数。
interface Props {
  modelValue: Record<string, number> | null
  label?: string
  placeholder?: string
  hint?: string
  disabled?: boolean
  rows?: number | string
}

const props = withDefaults(defineProps<Props>(), {
  modelValue: null,
  disabled: false,
  rows: 5
})

const emit = defineEmits<{
  (e: 'update:modelValue', value: Record<string, number> | null): void
  (e: 'validation', valid: boolean): void
}>()

const { t } = useI18n()
const textareaRef = ref<HTMLTextAreaElement | null>(null)
const jsonText = ref('')
const parseError = ref('')
const dirty = ref(false)

const hasError = computed(() => dirty.value && parseError.value !== '')
const errorMessage = computed(() => parseError.value)

const placeholderText = computed(
  () =>
    props.placeholder ||
    '{\n  "claude-opus-4-8": 3.5,\n  "gpt-5.3-codex": 2\n}'
)

function modelToJson(mapping: Record<string, number> | null): string {
  if (!mapping || Object.keys(mapping).length === 0) return ''
  return JSON.stringify(mapping, null, 2)
}

// Parse JSON text into Record<string, number>. Empty → null. Throws on invalid
// JSON, non-object, or non-positive/non-number values.
function parseJson(text: string): Record<string, number> | null {
  const trimmed = text.trim()
  if (!trimmed) return null

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    throw new Error(t('admin.groups.model5hLimits.invalidJson'))
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(t('admin.groups.model5hLimits.notObject'))
  }

  const result: Record<string, number> = {}
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    const k = key.trim()
    if (!k) continue
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
      throw new Error(t('admin.groups.model5hLimits.valueNotPositive', { key: k }))
    }
    result[k] = value
  }

  return Object.keys(result).length > 0 ? result : null
}

watch(
  () => props.modelValue,
  (newVal) => {
    const newJson = modelToJson(newVal)
    if (!dirty.value || newJson !== modelToJson(parseJsonSilent(jsonText.value))) {
      jsonText.value = newJson
      parseError.value = ''
      dirty.value = false
    }
  },
  { immediate: true }
)

function parseJsonSilent(text: string): Record<string, number> | null {
  try {
    return parseJson(text)
  } catch {
    return null
  }
}

function handleInput(event: Event) {
  const value = (event.target as HTMLTextAreaElement).value
  jsonText.value = value
  dirty.value = true
  try {
    const parsed = parseJson(value)
    parseError.value = ''
    emit('update:modelValue', parsed)
    emit('validation', true)
  } catch (err) {
    parseError.value = err instanceof Error ? err.message : String(err)
    emit('validation', false)
  }
}

function handleBlur() {
  dirty.value = true
  try {
    const parsed = parseJson(jsonText.value)
    parseError.value = ''
    if (parsed) {
      jsonText.value = modelToJson(parsed)
    }
    emit('update:modelValue', parsed)
    emit('validation', true)
  } catch (err) {
    parseError.value = err instanceof Error ? err.message : String(err)
    emit('validation', false)
  }
}

defineExpose({
  validate: (): boolean => {
    dirty.value = true
    try {
      parseJson(jsonText.value)
      parseError.value = ''
      return true
    } catch (err) {
      parseError.value = err instanceof Error ? err.message : String(err)
      return false
    }
  },
  focus: () => textareaRef.value?.focus()
})
</script>
