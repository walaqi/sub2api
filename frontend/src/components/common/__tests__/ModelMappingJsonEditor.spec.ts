import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import ModelMappingJsonEditor from '../ModelMappingJsonEditor.vue'

// Mock vue-i18n (partial: keep createI18n etc. for transitive imports)
vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string, params?: Record<string, unknown>) => {
        const messages: Record<string, string> = {
          'admin.accounts.modelMappingJsonInvalid': 'Invalid JSON format',
          'admin.accounts.modelMappingJsonNotObject': 'Must be a JSON object',
          'admin.accounts.modelMappingJsonValueNotString':
            `All values must be strings. Key "${params?.key}" has a non-string value.`,
          'admin.accounts.modelMappingJsonKeyWildcard':
            `Key "${params?.key}": wildcard * can only be at the end`,
          'admin.accounts.modelMappingJsonValueWildcard':
            `Key "${params?.key}": target model cannot contain wildcard *`
        }
        return messages[key] ?? key
      }
    })
  }
})

function mountEditor(props: Record<string, unknown> = {}) {
  return mount(ModelMappingJsonEditor, {
    props: {
      modelValue: null,
      ...props
    }
  })
}

describe('ModelMappingJsonEditor', () => {
  describe('rendering', () => {
    it('renders textarea with default 5 rows', () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')
      expect(textarea.exists()).toBe(true)
      expect(textarea.attributes('rows')).toBe('5')
    })

    it('renders label when provided', () => {
      const wrapper = mountEditor({ label: 'Model Mapping' })
      expect(wrapper.find('label').text()).toBe('Model Mapping')
    })

    it('does not render label when not provided', () => {
      const wrapper = mountEditor()
      expect(wrapper.find('label').exists()).toBe(false)
    })

    it('renders hint when provided and no error', () => {
      const wrapper = mountEditor({ hint: 'Enter JSON mapping' })
      expect(wrapper.find('.input-hint').text()).toBe('Enter JSON mapping')
    })

    it('respects custom rows prop', () => {
      const wrapper = mountEditor({ rows: 8 })
      const textarea = wrapper.find('textarea')
      expect(textarea.attributes('rows')).toBe('8')
    })

    it('applies disabled state', () => {
      const wrapper = mountEditor({ disabled: true })
      const textarea = wrapper.find('textarea')
      expect(textarea.attributes('disabled')).toBeDefined()
    })
  })

  describe('initialization from modelValue', () => {
    it('shows empty textarea for null modelValue', () => {
      const wrapper = mountEditor({ modelValue: null })
      const textarea = wrapper.find('textarea')
      expect((textarea.element as HTMLTextAreaElement).value).toBe('')
    })

    it('shows empty textarea for empty object', () => {
      const wrapper = mountEditor({ modelValue: {} })
      const textarea = wrapper.find('textarea')
      expect((textarea.element as HTMLTextAreaElement).value).toBe('')
    })

    it('serializes modelValue to pretty JSON', () => {
      const mapping = { 'claude-sonnet-4-5': 'claude-sonnet-4-5-20250929' }
      const wrapper = mountEditor({ modelValue: mapping })
      const textarea = wrapper.find('textarea')
      const value = (textarea.element as HTMLTextAreaElement).value
      expect(JSON.parse(value)).toEqual(mapping)
      // Should be pretty-printed
      expect(value).toContain('\n')
    })

    it('updates textarea when modelValue prop changes externally', async () => {
      const wrapper = mountEditor({ modelValue: null })
      await wrapper.setProps({ modelValue: { 'model-a': 'model-b' } })
      await nextTick()
      const value = (wrapper.find('textarea').element as HTMLTextAreaElement).value
      expect(JSON.parse(value)).toEqual({ 'model-a': 'model-b' })
    })
  })

  describe('input handling', () => {
    it('emits update:modelValue with parsed object on valid JSON input', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')
      const validJson = '{"gpt-4": "gpt-4-turbo"}'

      await textarea.setValue(validJson)
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      expect(emitted).toBeTruthy()
      const lastEmit = emitted![emitted!.length - 1][0]
      expect(lastEmit).toEqual({ 'gpt-4': 'gpt-4-turbo' })
    })

    it('emits null for empty input', async () => {
      const wrapper = mountEditor({ modelValue: { a: 'b' } })
      const textarea = wrapper.find('textarea')

      await textarea.setValue('')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      expect(emitted).toBeTruthy()
      const lastEmit = emitted![emitted!.length - 1][0]
      expect(lastEmit).toBeNull()
    })

    it('emits validation:true on valid input', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"a": "b"}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('validation')
      expect(emitted).toBeTruthy()
      expect(emitted![emitted!.length - 1][0]).toBe(true)
    })

    it('emits validation:false on invalid JSON input', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{invalid json}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('validation')
      expect(emitted).toBeTruthy()
      expect(emitted![emitted!.length - 1][0]).toBe(false)
    })

    it('trims whitespace from keys and values', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"  model-a  ": "  model-b  "}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      const lastEmit = emitted![emitted!.length - 1][0]
      expect(lastEmit).toEqual({ 'model-a': 'model-b' })
    })

    it('skips entries with empty keys after trimming', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"": "model-b", "model-a": "model-c"}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      const lastEmit = emitted![emitted!.length - 1][0]
      expect(lastEmit).toEqual({ 'model-a': 'model-c' })
    })
  })

  describe('validation', () => {
    it('shows error for invalid JSON after blur', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('not json')
      await textarea.trigger('input')
      await textarea.trigger('blur')

      expect(wrapper.find('.input-error-text').exists()).toBe(true)
      expect(wrapper.find('.input-error-text').text()).toContain('Invalid JSON format')
    })

    it('shows error when value is an array instead of object', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('["model-a", "model-b"]')
      await textarea.trigger('input')
      await textarea.trigger('blur')

      expect(wrapper.find('.input-error-text').exists()).toBe(true)
      expect(wrapper.find('.input-error-text').text()).toContain('Must be a JSON object')
    })

    it('shows error when values are not strings', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"model-a": 123}')
      await textarea.trigger('input')
      await textarea.trigger('blur')

      expect(wrapper.find('.input-error-text').exists()).toBe(true)
      expect(wrapper.find('.input-error-text').text()).toContain('non-string value')
    })

    it('does not show error before user interaction', () => {
      const wrapper = mountEditor()
      expect(wrapper.find('.input-error-text').exists()).toBe(false)
    })

    it('clears error when input becomes valid', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      // First make it invalid
      await textarea.setValue('bad json')
      await textarea.trigger('input')
      await textarea.trigger('blur')
      expect(wrapper.find('.input-error-text').exists()).toBe(true)

      // Then fix it
      await textarea.setValue('{"a": "b"}')
      await textarea.trigger('input')
      expect(wrapper.find('.input-error-text').exists()).toBe(false)
    })

    it('hides hint when error is shown', async () => {
      const wrapper = mountEditor({ hint: 'Some hint' })
      const textarea = wrapper.find('textarea')

      await textarea.setValue('invalid')
      await textarea.trigger('input')
      await textarea.trigger('blur')

      expect(wrapper.find('.input-hint').exists()).toBe(false)
      expect(wrapper.find('.input-error-text').exists()).toBe(true)
    })
  })

  describe('blur behavior', () => {
    it('auto-formats valid JSON on blur', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      // Input compact JSON
      await textarea.setValue('{"a":"b","c":"d"}')
      await textarea.trigger('input')
      await textarea.trigger('blur')
      await nextTick()

      const value = (textarea.element as HTMLTextAreaElement).value
      // Should be pretty-printed after blur
      expect(value).toBe('{\n  "a": "b",\n  "c": "d"\n}')
    })
  })

  describe('expose: validate()', () => {
    it('returns true for valid JSON', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"a": "b"}')
      await textarea.trigger('input')

      const result = (wrapper.vm as any).validate()
      expect(result).toBe(true)
    })

    it('returns true for empty input (no mapping)', () => {
      const wrapper = mountEditor()
      const result = (wrapper.vm as any).validate()
      expect(result).toBe(true)
    })

    it('returns false for invalid JSON and sets error', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('invalid')
      await textarea.trigger('input')

      const result = (wrapper.vm as any).validate()
      expect(result).toBe(false)
      expect(wrapper.find('.input-error-text').exists()).toBe(true)
    })
  })

  describe('wildcard validation (validateWildcards)', () => {
    it('accepts trailing wildcard in key when enabled', async () => {
      const wrapper = mountEditor({ validateWildcards: true })
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"claude-*": "claude-sonnet-4-5"}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('validation')
      expect(emitted![emitted!.length - 1][0]).toBe(true)
      expect(wrapper.find('.input-error-text').exists()).toBe(false)
    })

    it('rejects wildcard in the middle of a key when enabled', async () => {
      const wrapper = mountEditor({ validateWildcards: true })
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"cla*ude": "claude-sonnet-4-5"}')
      await textarea.trigger('input')
      await textarea.trigger('blur')

      const emitted = wrapper.emitted('validation')
      expect(emitted![emitted!.length - 1][0]).toBe(false)
      expect(wrapper.find('.input-error-text').text()).toContain('wildcard * can only be at the end')
    })

    it('rejects wildcard in the value when enabled', async () => {
      const wrapper = mountEditor({ validateWildcards: true })
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"claude-3": "claude-*"}')
      await textarea.trigger('input')
      await textarea.trigger('blur')

      const emitted = wrapper.emitted('validation')
      expect(emitted![emitted!.length - 1][0]).toBe(false)
      expect(wrapper.find('.input-error-text').text()).toContain('target model cannot contain wildcard')
    })

    it('allows wildcards through when validation is disabled (default)', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"cla*ude": "claude-*"}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('validation')
      expect(emitted![emitted!.length - 1][0]).toBe(true)
      const updateEmitted = wrapper.emitted('update:modelValue')
      expect(updateEmitted![updateEmitted!.length - 1][0]).toEqual({ 'cla*ude': 'claude-*' })
    })
  })

  describe('edge cases', () => {
    it('handles multiple mappings', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      const input = JSON.stringify({
        'model-a': 'upstream-a',
        'model-b': 'upstream-b',
        'model-c': 'upstream-c'
      })
      await textarea.setValue(input)
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      const lastEmit = emitted![emitted!.length - 1][0] as Record<string, string>
      expect(Object.keys(lastEmit)).toHaveLength(3)
    })

    it('preserves key order from user input', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('{"z-model": "a", "a-model": "z"}')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      const lastEmit = emitted![emitted!.length - 1][0] as Record<string, string>
      const keys = Object.keys(lastEmit)
      expect(keys[0]).toBe('z-model')
      expect(keys[1]).toBe('a-model')
    })

    it('handles JSON with trailing whitespace', async () => {
      const wrapper = mountEditor()
      const textarea = wrapper.find('textarea')

      await textarea.setValue('  {"a": "b"}  \n')
      await textarea.trigger('input')

      const emitted = wrapper.emitted('update:modelValue')
      const lastEmit = emitted![emitted!.length - 1][0]
      expect(lastEmit).toEqual({ a: 'b' })
    })
  })
})
