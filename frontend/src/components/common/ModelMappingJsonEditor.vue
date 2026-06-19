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
import { isValidWildcardPattern } from '@/composables/useModelWhitelist'

interface Props {
  modelValue: Record<string, string> | null
  label?: string
  placeholder?: string
  hint?: string
  disabled?: boolean
  rows?: number | string
  // When true, enforce the same wildcard rules the per-row editor used:
  // keys may only use a trailing "*", and values must not contain "*".
  // Without this, such entries would be silently dropped at save time.
  validateWildcards?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  modelValue: null,
  disabled: false,
  rows: 5,
  validateWildcards: false
})

const emit = defineEmits<{
  (e: 'update:modelValue', value: Record<string, string> | null): void
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
    '{\n  "request-model": "upstream-model",\n  "claude-sonnet-4-5": "claude-sonnet-4-5-20250929"\n}'
)

/**
 * Serialize a Record<string, string> to pretty JSON.
 */
function modelToJson(mapping: Record<string, string> | null): string {
  if (!mapping || Object.keys(mapping).length === 0) return ''
  return JSON.stringify(mapping, null, 2)
}

/**
 * Parse JSON text into a Record<string, string>. Returns null for empty input.
 * Throws on invalid JSON or incorrect value types.
 */
function parseJson(text: string): Record<string, string> | null {
  const trimmed = text.trim()
  if (!trimmed) return null

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    throw new Error(t('admin.accounts.modelMappingJsonInvalid'))
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(t('admin.accounts.modelMappingJsonNotObject'))
  }

  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== 'string') {
      throw new Error(t('admin.accounts.modelMappingJsonValueNotString', { key }))
    }
    const k = key.trim()
    const v = (value as string).trim()
    if (!k) continue
    if (props.validateWildcards) {
      // Key may only carry a trailing "*"; value must not contain "*".
      if (!isValidWildcardPattern(k)) {
        throw new Error(t('admin.accounts.modelMappingJsonKeyWildcard', { key: k }))
      }
      if (v.includes('*')) {
        throw new Error(t('admin.accounts.modelMappingJsonValueWildcard', { key: k }))
      }
    }
    result[k] = v
  }

  return Object.keys(result).length > 0 ? result : null
}

// Initialize from prop
watch(
  () => props.modelValue,
  (newVal) => {
    // Only reset text when the external value changes meaningfully
    // (avoid overwriting user edits with the same data)
    const newJson = modelToJson(newVal)
    // If user hasn't touched the field or the external value is truly different, sync
    if (!dirty.value || newJson !== modelToJson(parseJsonSilent(jsonText.value))) {
      jsonText.value = newJson
      parseError.value = ''
      dirty.value = false
    }
  },
  { immediate: true }
)

function parseJsonSilent(text: string): Record<string, string> | null {
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

  // Validate on every keystroke but only emit on valid
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
  // Re-validate and format on blur
  try {
    const parsed = parseJson(jsonText.value)
    parseError.value = ''
    // Auto-format on blur if valid
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

// Expose for parent validation
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
