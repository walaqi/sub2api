<template>
  <BaseDialog
    :show="show"
    :title="editing ? t('admin.settings.payment.editProvider') : t('admin.settings.payment.createProvider')"
    width="wide"
    @close="emit('close')"
  >
    <form id="provider-form" @submit.prevent="handleSave" class="space-y-4">
      <!-- Name + Key -->
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="input-label">
            {{ t('admin.settings.payment.providerName') }}
            <span class="text-red-500">*</span>
          </label>
          <input v-model="form.name" type="text" class="input" required />
        </div>
        <div>
          <label class="input-label">
            {{ t('admin.settings.payment.providerKey') }}
            <span class="text-red-500">*</span>
          </label>
          <Select
            v-model="form.provider_key"
            :options="(!!editing ? allKeyOptions : enabledKeyOptions) as SelectOption[]"
            :disabled="!!editing"
            @change="onKeyChange"
          />
        </div>
      </div>

      <!-- Toggles + Payment mode + Supported types (single row) -->
      <div class="flex flex-wrap items-center gap-x-5 gap-y-2">
        <ToggleSwitch :label="t('common.enabled')" :checked="form.enabled" @toggle="form.enabled = !form.enabled" />
        <ToggleSwitch :label="t('admin.settings.payment.refundEnabled')" :checked="form.refund_enabled" @toggle="form.refund_enabled = !form.refund_enabled; if (!form.refund_enabled) form.allow_user_refund = false" />
        <ToggleSwitch v-if="form.refund_enabled" :label="t('admin.settings.payment.allowUserRefund')" :checked="form.allow_user_refund" @toggle="form.allow_user_refund = !form.allow_user_refund" />
        <div v-if="supportsPaymentMode" class="flex items-center gap-2">
          <span class="text-xs font-medium text-gray-500 dark:text-gray-400">{{ t('admin.settings.payment.paymentMode') }}</span>
          <div class="flex gap-1.5">
            <button
              v-for="mode in paymentModeOptions"
              :key="mode.value"
              type="button"
              @click="form.payment_mode = mode.value"
              :class="[
                'rounded-lg border px-2.5 py-1 text-xs font-medium transition-all',
                form.payment_mode === mode.value
                  ? 'border-primary-500 bg-primary-500 text-white shadow-sm'
                  : 'border-gray-300 bg-white text-gray-600 hover:border-gray-400 hover:bg-gray-50 dark:border-dark-600 dark:bg-dark-800 dark:text-gray-300 dark:hover:border-dark-500',
              ]"
            >{{ mode.label }}</button>
          </div>
        </div>
        <div v-if="availableTypes.length > 1 || isEasypay" class="flex items-center gap-2">
          <span class="text-xs font-medium text-gray-500 dark:text-gray-400">{{ t('admin.settings.payment.supportedTypes') }}</span>
          <div class="flex flex-wrap gap-1.5">
            <button
              v-for="pt in availableTypes"
              :key="pt.value"
              type="button"
              :disabled="isEasypay && useCustomChannel"
              @click="toggleType(pt.value)"
              :class="[
                'rounded-lg border px-2.5 py-1 text-xs font-medium transition-all',
                isEasypay && useCustomChannel
                  ? 'cursor-not-allowed border-gray-200 bg-gray-50 text-gray-400 dark:border-dark-700 dark:bg-dark-800/50 dark:text-gray-600'
                  : isTypeSelected(pt.value)
                    ? 'border-primary-500 bg-primary-500 text-white shadow-sm'
                    : 'border-gray-300 bg-white text-gray-600 hover:border-gray-400 hover:bg-gray-50 dark:border-dark-600 dark:bg-dark-800 dark:text-gray-300 dark:hover:border-dark-500',
              ]"
            >{{ pt.label }}</button>
            <button
              v-if="isEasypay"
              type="button"
              @click="toggleCustomChannel"
              :class="[
                'rounded-lg border px-2.5 py-1 text-xs font-medium transition-all',
                useCustomChannel
                  ? 'border-primary-500 bg-primary-500 text-white shadow-sm'
                  : 'border-gray-300 bg-white text-gray-600 hover:border-gray-400 hover:bg-gray-50 dark:border-dark-600 dark:bg-dark-800 dark:text-gray-300 dark:hover:border-dark-500',
              ]"
            >{{ t('admin.settings.payment.easypayCustomType') }}</button>
          </div>
        </div>
      </div>

      <!-- EasyPay custom channel inputs -->
      <div v-if="isEasypay && useCustomChannel" class="rounded-lg border border-primary-200 bg-primary-50/40 p-3 dark:border-primary-900/40 dark:bg-primary-950/30">
        <p class="mb-2 text-xs leading-relaxed text-primary-700 dark:text-primary-300">
          {{ t('admin.settings.payment.easypayCustomTypeHint') }}
        </p>
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label">
              {{ t('admin.settings.payment.easypayCustomTypeLabel') }}
              <span class="text-red-500">*</span>
            </label>
            <input
              v-model="customChannel.type"
              type="text"
              class="input"
              placeholder="epay / qqpay / usdt"
              autocomplete="off"
            />
          </div>
          <div>
            <label class="input-label">
              {{ t('admin.settings.payment.easypayCustomLabel') }}
              <span class="text-red-500">*</span>
            </label>
            <input v-model="customChannel.label" type="text" class="input" autocomplete="off" />
          </div>
          <div class="sm:col-span-2">
            <label class="input-label">
              {{ t('admin.settings.payment.easypayCustomIconUrl') }}
              <span class="text-red-500">*</span>
            </label>
            <input v-model="customChannel.iconUrl" type="text" class="input" placeholder="https://..." autocomplete="off" />
          </div>
          <div>
            <label class="input-label">
              {{ t('admin.settings.payment.easypayCustomMultiplier') }}
              <span class="text-xs text-gray-400">({{ t('common.optional') }})</span>
            </label>
            <input
              type="number"
              step="0.01"
              min="0"
              class="input"
              autocomplete="off"
              :value="customChannel.multiplier"
              @input="customChannel.multiplier = ($event.target as HTMLInputElement).value"
            />
          </div>
          <div>
            <label class="input-label">
              {{ t('admin.settings.payment.easypayCustomPrefix') }}
              <span class="text-xs text-gray-400">({{ t('common.optional') }})</span>
            </label>
            <input v-model="customChannel.productNamePrefix" type="text" class="input" autocomplete="off" />
          </div>
          <div>
            <label class="input-label">
              {{ t('admin.settings.payment.easypayCustomSuffix') }}
              <span class="text-xs text-gray-400">({{ t('common.optional') }})</span>
            </label>
            <input v-model="customChannel.productNameSuffix" type="text" class="input" autocomplete="off" />
          </div>
        </div>
      </div>


      <!-- Config fields -->
      <div class="border-t border-gray-200 pt-4 dark:border-dark-700">
        <div class="mb-3 flex items-center gap-2">
          <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
            {{ t('admin.settings.payment.providerConfig') }}
          </h4>
          <HelpTooltip v-if="paymentGuide" trigger="click" width-class="w-80">
            <template #trigger>
              <button
                type="button"
                class="inline-flex h-5 w-5 items-center justify-center rounded-full border border-gray-300 text-[11px] font-semibold text-gray-400 transition-colors hover:border-primary-500 hover:text-primary-600 dark:border-dark-500 dark:text-gray-500 dark:hover:border-primary-400 dark:hover:text-primary-400"
                :aria-label="t('admin.settings.payment.paymentGuideTrigger')"
                :title="t('admin.settings.payment.paymentGuideTrigger')"
              >
                ?
              </button>
            </template>
            <div class="space-y-3">
              <p class="font-medium text-white">{{ paymentGuide.summary }}</p>
              <div
                v-for="item in paymentGuide.items"
                :key="item.title"
                class="space-y-1.5 border-t border-white/10 pt-2 first:border-t-0 first:pt-0"
              >
                <p class="font-medium text-white">{{ item.title }}</p>
                <p><span class="text-gray-300">{{ t('admin.settings.payment.guideOpenLabel') }}</span>{{ item.open }}</p>
                <p><span class="text-gray-300">{{ t('admin.settings.payment.guideCallLabel') }}</span>{{ item.call }}</p>
                <p><span class="text-gray-300">{{ t('admin.settings.payment.guideFallbackLabel') }}</span>{{ item.fallback }}</p>
              </div>
              <p v-if="paymentGuide.note" class="border-t border-white/10 pt-2 text-[11px] text-gray-300">
                {{ paymentGuide.note }}
              </p>
            </div>
          </HelpTooltip>
        </div>
        <p v-if="paymentGuide" class="mb-3 text-xs text-gray-500 dark:text-gray-400">
          {{ paymentGuide.summary }}
        </p>
        <div class="space-y-3">
          <div v-for="field in resolvedFields" :key="field.key">
            <label class="input-label">
              {{ field.label }}
              <span v-if="field.optional" class="text-xs text-gray-400">({{ t('common.optional') }})</span>
              <span v-else class="text-red-500"> *</span>
            </label>
            <textarea
              v-if="field.sensitive && field.key.toLowerCase().includes('key') && field.key !== 'pkey'"
              v-model="config[field.key]"
              rows="3"
              class="input font-mono text-xs"
              autocomplete="new-password"
              data-1p-ignore
              data-lpignore="true"
              data-bwignore="true"
              spellcheck="false"
              :placeholder="editing ? t('admin.accounts.leaveEmptyToKeep') : ''"
            />
            <div v-else-if="field.sensitive" class="relative">
              <input
                :type="visibleFields[field.key] ? 'text' : 'password'"
                v-model="config[field.key]"
                class="input pr-10"
                autocomplete="new-password"
                data-1p-ignore
                data-lpignore="true"
                data-bwignore="true"
                spellcheck="false"
                :placeholder="editing ? t('admin.accounts.leaveEmptyToKeep') : (field.defaultValue || '')"
              />
              <button
                type="button"
                @click="visibleFields[field.key] = !visibleFields[field.key]"
                class="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <svg v-if="visibleFields[field.key]" class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" /></svg>
                <svg v-else class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
              </button>
            </div>
            <Select
              v-else-if="field.options?.length"
              v-model="config[field.key]"
              :options="field.options"
              :searchable="field.options.length > 5"
            />
            <input
              v-else
              type="text"
              v-model="config[field.key]"
              class="input"
              :placeholder="field.defaultValue || ''"
            />
            <p v-if="field.hintKey" class="mt-1 text-xs leading-relaxed text-gray-500 dark:text-gray-400">
              {{ t(field.hintKey) }}
            </p>
          </div>
        </div>

        <!-- Callback URLs (each = editable URL + fixed path) -->
        <div v-if="callbackPaths" class="mt-4 space-y-3">
          <div v-if="callbackPaths.notifyUrl">
            <label class="input-label">{{ t('admin.settings.payment.field_notifyUrl') }} <span class="text-red-500">*</span></label>
            <div class="flex">
              <input v-model="notifyBaseUrl" type="text" class="input min-w-0 flex-1 !rounded-r-none !border-r-0" :placeholder="defaultBaseUrl" />
              <span class="inline-flex items-center whitespace-nowrap rounded-r-lg border border-gray-300 bg-gray-50 px-3 text-xs text-gray-500 dark:border-dark-600 dark:bg-dark-700 dark:text-gray-400">{{ callbackPaths.notifyUrl }}</span>
            </div>
          </div>
          <div v-if="callbackPaths.returnUrl">
            <label class="input-label">{{ t('admin.settings.payment.field_returnUrl') }} <span class="text-red-500">*</span></label>
            <div class="flex">
              <input v-model="returnBaseUrl" type="text" class="input min-w-0 flex-1 !rounded-r-none !border-r-0" :placeholder="defaultBaseUrl" />
              <span class="inline-flex items-center whitespace-nowrap rounded-r-lg border border-gray-300 bg-gray-50 px-3 text-xs text-gray-500 dark:border-dark-600 dark:bg-dark-700 dark:text-gray-400">{{ callbackPaths.returnUrl }}</span>
            </div>
          </div>
        </div>

        <!-- 服务商 Webhook 提示 -->
        <div v-if="providerWebhookUrl" class="mt-3 rounded-lg border border-blue-200 bg-blue-50 p-3 dark:border-blue-800/50 dark:bg-blue-900/20">
          <p class="text-xs text-blue-700 dark:text-blue-300">
            {{ t(providerWebhookHint) }}
          </p>
          <code class="mt-1 block break-all rounded bg-blue-100 px-2 py-1 text-xs text-blue-800 dark:bg-blue-900/40 dark:text-blue-200">
            {{ providerWebhookUrl }}
          </code>
          <p v-if="form.provider_key === 'stripe'" class="mt-2 text-xs leading-relaxed text-blue-700 dark:text-blue-300">
            {{ t('admin.settings.payment.stripeWebhookApiVersionHint', { version: STRIPE_SDK_API_VERSION }) }}
          </p>
        </div>
      </div>

      <!-- Per-type limits (collapsible) -->
      <div v-if="limitableTypes.length" class="border-t border-gray-200 pt-4 dark:border-dark-700">
        <button type="button" @click="limitsExpanded = !limitsExpanded" class="flex w-full items-center justify-between">
          <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
            {{ t('admin.settings.payment.limitsTitle') }}
          </h4>
          <svg :class="['h-4 w-4 text-gray-400 transition-transform', limitsExpanded && 'rotate-180']" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" /></svg>
        </button>
        <div v-show="limitsExpanded" class="mt-3 space-y-3">
          <div
            v-for="lt in limitableTypes"
            :key="lt.value"
            class="rounded-lg border border-gray-100 p-3 dark:border-dark-700"
          >
            <p class="mb-2 text-xs font-medium text-gray-700 dark:text-gray-300">{{ lt.label }}</p>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.settings.payment.limitSingleMin') }}</label>
                <input
                  type="number"
                  :value="getLimitVal(lt.value, 'singleMin')"
                  @input="setLimitVal(lt.value, 'singleMin', ($event.target as HTMLInputElement).value)"
                  class="input mt-0.5" min="1" step="0.01" :placeholder="limitPlaceholder(lt.value)"
                />
              </div>
              <div>
                <label class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.settings.payment.limitSingleMax') }}</label>
                <input
                  type="number"
                  :value="getLimitVal(lt.value, 'singleMax')"
                  @input="setLimitVal(lt.value, 'singleMax', ($event.target as HTMLInputElement).value)"
                  class="input mt-0.5" min="1" step="0.01" :placeholder="limitPlaceholder(lt.value)"
                />
              </div>
              <div>
                <label class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.settings.payment.limitDaily') }}</label>
                <input
                  type="number"
                  :value="getLimitVal(lt.value, 'dailyLimit')"
                  @input="setLimitVal(lt.value, 'dailyLimit', ($event.target as HTMLInputElement).value)"
                  class="input mt-0.5" min="1" step="0.01" :placeholder="limitPlaceholder(lt.value)"
                />
              </div>
            </div>
          </div>
          <p class="text-xs text-gray-400 dark:text-gray-500">{{ t('admin.settings.payment.limitsHint') }}</p>
        </div>
      </div>
    </form>

    <template #footer>
      <div class="flex justify-end gap-3">
        <button type="button" @click="emit('close')" class="btn btn-secondary">{{ t('common.cancel') }}</button>
        <button type="submit" form="provider-form" :disabled="saving" class="btn btn-primary">
          {{ saving ? t('common.saving') : t('common.save') }}
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { reactive, computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import HelpTooltip from '@/components/common/HelpTooltip.vue'
import Select from '@/components/common/Select.vue'
import type { SelectOption } from '@/components/common/Select.vue'
import ToggleSwitch from './ToggleSwitch.vue'
import type { ProviderInstance } from '@/types/payment'
import type { TypeOption } from './providerConfig'
import {
  PROVIDER_CONFIG_FIELDS,
  PROVIDER_SUPPORTED_TYPES,
  PROVIDER_CALLBACK_PATHS,
  WEBHOOK_PATHS,
  PAYMENT_MODE_QRCODE,
  PAYMENT_MODE_POPUP,
  PAYMENT_MODE_REDIRECT,
  STRIPE_SDK_API_VERSION,
  EASYPAY_STANDARD_TYPES,
  getAvailableTypes,
  extractBaseUrl,
} from './providerConfig'

/** Default payment_mode per provider key — "" means "no preference, use
 * provider's built-in default behavior". */
function defaultPaymentMode(providerKey: string): string {
  if (providerKey === 'easypay') return PAYMENT_MODE_QRCODE
  return ''
}

/** Provider keys whose admin UI exposes a payment_mode selector.
 * Other providers always send payment_mode = ''. */
function providerSupportsPaymentMode(providerKey: string): boolean {
  return providerKey === 'easypay' || providerKey === 'alipay'
}

/** Allowed payment_mode values per provider. Used to coerce DB values
 * from a different provider (or stale data) back to the default. */
function isValidPaymentMode(providerKey: string, mode: string): boolean {
  if (providerKey === 'easypay') {
    return mode === PAYMENT_MODE_QRCODE || mode === PAYMENT_MODE_POPUP
  }
  if (providerKey === 'alipay') {
    return mode === '' || mode === PAYMENT_MODE_REDIRECT
  }
  return mode === ''
}

const props = defineProps<{
  show: boolean
  saving: boolean
  editing: ProviderInstance | null
  allKeyOptions: TypeOption[]
  enabledKeyOptions: TypeOption[]
  allPaymentTypes: TypeOption[]
  redirectLabel: string
}>()

const emit = defineEmits<{
  close: []
  save: [payload: {
    provider_key: string
    name: string
    supported_types: string[]
    enabled: boolean
    payment_mode: string
    refund_enabled: boolean
    allow_user_refund: boolean
    config: Record<string, string>
    limits: string
    metadata: string
  }]
}>()

const { t } = useI18n()

interface PaymentGuideItem {
  title: string
  open: string
  call: string
  fallback: string
}

interface PaymentGuide {
  summary: string
  items: PaymentGuideItem[]
  note?: string
}

// --- Form state ---
const form = reactive({
  name: '',
  provider_key: 'easypay',
  supported_types: [] as string[],
  enabled: true,
  payment_mode: PAYMENT_MODE_QRCODE,
  refund_enabled: false,
  allow_user_refund: false,
})

/** EasyPay-only: when true, supported_types becomes a single admin-defined
 * free-form string (e.g. "epay" / "qqpay"), and the standard alipay/wxpay
 * checkboxes are mutually disabled. */
const useCustomChannel = ref(false)
const customChannel = reactive({
  type: '',
  label: '',
  iconUrl: '',
  multiplier: '' as string,
  productNamePrefix: '',
  productNameSuffix: '',
})
const config = reactive<Record<string, string>>({})
const limits = reactive<Record<string, Record<string, number>>>({})
const notifyBaseUrl = ref('')
const returnBaseUrl = ref('')
const limitsExpanded = ref(false)
const visibleFields = reactive<Record<string, boolean>>({})

// --- Computed ---
const defaultBaseUrl = typeof window !== 'undefined' ? window.location.origin : ''

const providerWebhookHintMap: Record<string, string> = {
  stripe: 'admin.settings.payment.stripeWebhookHint',
  airwallex: 'admin.settings.payment.airwallexWebhookHint',
}

const providerWebhookUrl = computed(() => {
  const path = WEBHOOK_PATHS[form.provider_key]
  return providerWebhookHintMap[form.provider_key] && path ? defaultBaseUrl + path : ''
})

const providerWebhookHint = computed(() =>
  providerWebhookHintMap[form.provider_key] || 'admin.settings.payment.stripeWebhookHint',
)

const callbackPaths = computed(() => PROVIDER_CALLBACK_PATHS[form.provider_key] || null)

const supportsPaymentMode = computed(() => providerSupportsPaymentMode(form.provider_key))

const paymentModeOptions = computed(() => {
  if (form.provider_key === 'alipay') {
    // For Alipay official: "" = default (precreate → page.pay fallback);
    // "redirect" = always open the Alipay checkout page in a new tab.
    return [
      { value: '', label: t('admin.settings.payment.modeQRCode') },
      { value: PAYMENT_MODE_REDIRECT, label: t('admin.settings.payment.modeRedirect') },
    ]
  }
  return [
    { value: PAYMENT_MODE_QRCODE, label: t('admin.settings.payment.modeQRCode') },
    { value: PAYMENT_MODE_POPUP, label: t('admin.settings.payment.modePopup') },
  ]
})

const availableTypes = computed(() => {
  const base = getAvailableTypes(form.provider_key, props.allPaymentTypes, props.redirectLabel)
  // Resolve i18n labels for types not in allPaymentTypes (e.g. card, link inside stripe)
  return base.map(opt =>
    opt.label === opt.value
      ? { ...opt, label: t(`payment.methods.${opt.value}`, opt.value) }
      : opt,
  )
})

const resolvedFields = computed(() => {
  const fields = PROVIDER_CONFIG_FIELDS[form.provider_key] || []
  return fields.map(f => ({
    ...f,
    label: f.label || t(`admin.settings.payment.field_${f.key}`),
  }))
})

const paymentGuide = computed<PaymentGuide | null>(() => {
  if (form.provider_key === 'alipay') {
    return {
      summary: t('admin.settings.payment.alipayGuideSummary'),
      items: [
        {
          title: t('admin.settings.payment.alipayGuideFaceToFaceTitle'),
          open: t('admin.settings.payment.alipayGuideFaceToFaceOpen'),
          call: t('admin.settings.payment.alipayGuideFaceToFaceCall'),
          fallback: t('admin.settings.payment.alipayGuideFaceToFaceFallback'),
        },
        {
          title: t('admin.settings.payment.alipayGuidePagePayTitle'),
          open: t('admin.settings.payment.alipayGuidePagePayOpen'),
          call: t('admin.settings.payment.alipayGuidePagePayCall'),
          fallback: t('admin.settings.payment.alipayGuidePagePayFallback'),
        },
        {
          title: t('admin.settings.payment.alipayGuideWapTitle'),
          open: t('admin.settings.payment.alipayGuideWapOpen'),
          call: t('admin.settings.payment.alipayGuideWapCall'),
          fallback: t('admin.settings.payment.alipayGuideWapFallback'),
        },
      ],
    }
  }

  if (form.provider_key === 'wxpay') {
    return {
      summary: t('admin.settings.payment.wxpayGuideSummary'),
      note: t('admin.settings.payment.wxpayGuideNote'),
      items: [
        {
          title: t('admin.settings.payment.wxpayGuideNativeTitle'),
          open: t('admin.settings.payment.wxpayGuideNativeOpen'),
          call: t('admin.settings.payment.wxpayGuideNativeCall'),
          fallback: t('admin.settings.payment.wxpayGuideNativeFallback'),
        },
        {
          title: t('admin.settings.payment.wxpayGuideJsapiTitle'),
          open: t('admin.settings.payment.wxpayGuideJsapiOpen'),
          call: t('admin.settings.payment.wxpayGuideJsapiCall'),
          fallback: t('admin.settings.payment.wxpayGuideJsapiFallback'),
        },
        {
          title: t('admin.settings.payment.wxpayGuideH5Title'),
          open: t('admin.settings.payment.wxpayGuideH5Open'),
          call: t('admin.settings.payment.wxpayGuideH5Call'),
          fallback: t('admin.settings.payment.wxpayGuideH5Fallback'),
        },
      ],
    }
  }

  if (form.provider_key === 'airwallex') {
    return {
      summary: t('admin.settings.payment.airwallexGuideSummary'),
      note: t('admin.settings.payment.airwallexGuideNote'),
      items: [],
    }
  }

  return null
})

const limitableTypes = computed(() => {
  // Stripe: single "stripe" entry (one set of shared limits)
  if (form.provider_key === 'stripe') {
    return [{ value: 'stripe', label: 'Stripe' }]
  }
  const selected = form.supported_types.filter(t => t !== 'easypay')
  return selected.map(v => {
    const found = props.allPaymentTypes.find(pt => pt.value === v)
    return found || { value: v, label: v }
  })
})

// --- Methods ---
const isEasypay = computed(() => form.provider_key === 'easypay')

function isStandardEasypayType(type: string): boolean {
  return (EASYPAY_STANDARD_TYPES as readonly string[]).includes(type)
}

function isTypeSelected(type: string): boolean {
  return form.supported_types.includes(type)
}

function toggleType(type: string) {
  // EasyPay: toggling a standard type while in custom-channel mode
  // first exits custom mode (clears its inputs) so we don't end up with both
  // a custom channel and standard checkboxes selected.
  if (isEasypay.value && useCustomChannel.value && isStandardEasypayType(type)) {
    useCustomChannel.value = false
    resetCustomChannel()
  }
  if (form.supported_types.includes(type)) {
    form.supported_types = form.supported_types.filter(t => t !== type)
  } else {
    form.supported_types = [...form.supported_types, type]
  }
}

function toggleCustomChannel() {
  useCustomChannel.value = !useCustomChannel.value
  if (useCustomChannel.value) {
    // Clear the standard alipay/wxpay selection — they are mutually exclusive
    // with the custom channel within a single instance.
    form.supported_types = []
    // Custom EasyPay channels only support hosted-page redirect. The QR flow
    // does not apply because the aggregate gateway picks the sub-method itself.
    form.payment_mode = PAYMENT_MODE_POPUP
  } else {
    resetCustomChannel()
  }
}

function resetCustomChannel() {
  customChannel.type = ''
  customChannel.label = ''
  customChannel.iconUrl = ''
  customChannel.multiplier = ''
  customChannel.productNamePrefix = ''
  customChannel.productNameSuffix = ''
}

function onKeyChange() {
  form.supported_types = [...(PROVIDER_SUPPORTED_TYPES[form.provider_key] || [])]
  form.payment_mode = defaultPaymentMode(form.provider_key)
  useCustomChannel.value = false
  resetCustomChannel()
  clearConfig()
  applyDefaults()
}

function clearConfig() {
  Object.keys(config).forEach(k => delete config[k])
  Object.keys(limits).forEach(k => delete limits[k])
  Object.keys(visibleFields).forEach(k => delete visibleFields[k])
  notifyBaseUrl.value = ''
  returnBaseUrl.value = ''
  limitsExpanded.value = false
}

function applyDefaults() {
  for (const f of PROVIDER_CONFIG_FIELDS[form.provider_key] || []) {
    if (f.defaultValue && !config[f.key]) config[f.key] = f.defaultValue
  }
}

function getLimitVal(paymentType: string, field: string): string {
  const val = limits[paymentType]?.[field]
  return val && val > 0 ? String(val) : ''
}

/** Returns true if any limit field for this payment type has a value */
function hasAnyLimit(paymentType: string): boolean {
  const l = limits[paymentType]
  if (!l) return false
  return (l.singleMin > 0) || (l.singleMax > 0) || (l.dailyLimit > 0)
}

/** Dynamic placeholder: "不限制" if sibling has value, "使用全局配置" if all empty */
function limitPlaceholder(paymentType: string): string {
  return hasAnyLimit(paymentType)
    ? t('admin.settings.payment.limitsNoLimit')
    : t('admin.settings.payment.limitsUseGlobal')
}

function setLimitVal(paymentType: string, field: string, val: string) {
  if (!limits[paymentType]) limits[paymentType] = {}
  const num = Number(val)
  // Empty → clear the field (use global); reject ≤0
  if (val === '' || isNaN(num)) {
    delete limits[paymentType][field]
    return
  }
  if (num <= 0) return
  limits[paymentType][field] = num
}

function serializeLimits(): string {
  const result: Record<string, Record<string, number>> = {}
  for (const [pt, fields] of Object.entries(limits)) {
    const clean: Record<string, number> = {}
    for (const [k, v] of Object.entries(fields)) {
      if (v > 0) clean[k] = v
    }
    if (Object.keys(clean).length > 0) result[pt] = clean
  }
  return Object.keys(result).length > 0 ? JSON.stringify(result) : ''
}

function serializeMetadata(): string {
  if (!useCustomChannel.value) return ''
  const type = customChannel.type.trim()
  const payload: {
    channels: Record<string, { label: string; icon_url: string }>
    balance_recharge_multiplier?: number
    product_name_prefix?: string
    product_name_suffix?: string
  } = {
    channels: {
      [type]: {
        label: customChannel.label.trim(),
        icon_url: customChannel.iconUrl.trim(),
      },
    },
  }
  const m = String(customChannel.multiplier ?? '').trim()
  if (m !== '') {
    const num = Number(m)
    if (Number.isFinite(num) && num > 0) payload.balance_recharge_multiplier = num
  }
  const prefix = customChannel.productNamePrefix
  if (prefix !== '') payload.product_name_prefix = prefix
  const suffix = customChannel.productNameSuffix
  if (suffix !== '') payload.product_name_suffix = suffix
  return JSON.stringify(payload)
}

function validateCustomChannel(): string {
  const type = customChannel.type.trim()
  if (!type) return t('admin.settings.payment.easypayCustomTypeRequired')
  if (!/^[a-zA-Z0-9_]+$/.test(type)) return t('admin.settings.payment.easypayCustomTypeInvalid')
  if (isStandardEasypayType(type)) return t('admin.settings.payment.easypayCustomTypeReserved')
  if (!customChannel.label.trim()) return t('admin.settings.payment.easypayCustomLabelRequired')
  if (!customChannel.iconUrl.trim()) return t('admin.settings.payment.easypayCustomIconUrlRequired')
  if (!/^https?:\/\//i.test(customChannel.iconUrl.trim())) {
    return t('admin.settings.payment.easypayCustomIconUrlInvalid')
  }
  const m = String(customChannel.multiplier ?? '').trim()
  if (m !== '') {
    const num = Number(m)
    if (!Number.isFinite(num) || num <= 0) {
      return t('admin.settings.payment.easypayCustomMultiplierInvalid')
    }
  }
  return ''
}

function handleSave() {
  // Validate required fields
  if (!form.name.trim()) {
    emitValidationError(t('admin.settings.payment.validationNameRequired'))
    return
  }
  // EasyPay custom channel: validate the inline metadata inputs.
  if (useCustomChannel.value) {
    const err = validateCustomChannel()
    if (err) {
      emitValidationError(err)
      return
    }
  }
  // Validate required config fields — all non-optional fields must be filled.
  // In edit mode, sensitive fields may be left blank to preserve the stored
  // value (backend merges blanks by preserving the existing secret).
  for (const f of PROVIDER_CONFIG_FIELDS[form.provider_key] || []) {
    if (f.optional) continue
    if (props.editing && f.sensitive) continue
    const val = (config[f.key] || '').trim()
    if (!val) {
      const label = f.label || t(`admin.settings.payment.field_${f.key}`)
      emitValidationError(t('admin.settings.payment.validationFieldRequired', { field: label }))
      return
    }
  }

  const clearableConfigKeys = new Set(
    (PROVIDER_CONFIG_FIELDS[form.provider_key] || [])
      .filter(field => field.clearable)
      .map(field => field.key),
  )
  const filteredConfig: Record<string, string> = {}
  for (const [k, v] of Object.entries(config)) {
    if (!v || !v.trim()) {
      if (clearableConfigKeys.has(k)) {
        filteredConfig[k] = ''
      }
      continue
    }
    filteredConfig[k] = v
  }

  // Inject computed callback URLs (each URL = independent base + fixed path)
  // If base URL is empty, auto-fill with current domain
  const paths = PROVIDER_CALLBACK_PATHS[form.provider_key]
  if (paths) {
    const notifyBase = notifyBaseUrl.value.trim() || defaultBaseUrl
    const returnBase = returnBaseUrl.value.trim() || defaultBaseUrl
    notifyBaseUrl.value = notifyBase
    returnBaseUrl.value = returnBase
    if (paths.notifyUrl) filteredConfig['notifyUrl'] = notifyBase + paths.notifyUrl
    if (paths.returnUrl) filteredConfig['returnUrl'] = returnBase + paths.returnUrl
  }

  const supportedTypes = useCustomChannel.value
    ? [customChannel.type.trim()]
    : form.supported_types

  emit('save', {
    provider_key: form.provider_key,
    name: form.name,
    supported_types: supportedTypes,
    enabled: form.enabled,
    payment_mode: supportsPaymentMode.value ? form.payment_mode : '',
    refund_enabled: form.refund_enabled,
    allow_user_refund: form.refund_enabled ? form.allow_user_refund : false,
    config: filteredConfig,
    limits: serializeLimits(),
    metadata: serializeMetadata(),
  })
}

function emitValidationError(msg: string) {
  // Use a custom event or inject appStore — for now use window alert fallback
  // The parent handles this via the save event validation
  import('@/stores').then(m => m.useAppStore().showError(msg))
}

// --- Public API for parent to call ---
function reset(defaultKey: string) {
  form.name = ''
  form.provider_key = defaultKey
  form.supported_types = [...(PROVIDER_SUPPORTED_TYPES[defaultKey] || [])]
  form.enabled = true
  form.payment_mode = defaultPaymentMode(defaultKey)
  form.refund_enabled = false
  form.allow_user_refund = false
  useCustomChannel.value = false
  resetCustomChannel()
  clearConfig()
  applyDefaults()
}

function loadProvider(provider: ProviderInstance) {
  form.name = provider.name
  form.provider_key = provider.provider_key
  form.supported_types = provider.supported_types
  form.enabled = provider.enabled
  // Coerce to a valid value for this provider. Guards against stale data
  // (e.g. "popup" written by an older client) showing up as an unselected
  // button in the dialog.
  form.payment_mode = isValidPaymentMode(provider.provider_key, provider.payment_mode || '')
    ? (provider.payment_mode || '')
    : defaultPaymentMode(provider.provider_key)
  form.refund_enabled = provider.refund_enabled
  form.allow_user_refund = provider.allow_user_refund

  // EasyPay custom channel detection: a single supported_type that is not
  // 'alipay' or 'wxpay' means metadata-driven custom channel.
  useCustomChannel.value = false
  resetCustomChannel()
  if (
    provider.provider_key === 'easypay'
    && provider.supported_types.length === 1
    && !isStandardEasypayType(provider.supported_types[0])
  ) {
    useCustomChannel.value = true
    customChannel.type = provider.supported_types[0]
    try {
      const meta = provider.metadata ? JSON.parse(provider.metadata) : null
      if (meta && typeof meta === 'object') {
        const ch = meta.channels?.[customChannel.type]
        if (ch && typeof ch === 'object') {
          customChannel.label = typeof ch.label === 'string' ? ch.label : ''
          customChannel.iconUrl = typeof ch.icon_url === 'string' ? ch.icon_url : ''
        }
        if (typeof meta.balance_recharge_multiplier === 'number') {
          customChannel.multiplier = String(meta.balance_recharge_multiplier)
        }
        if (typeof meta.product_name_prefix === 'string') {
          customChannel.productNamePrefix = meta.product_name_prefix
        }
        if (typeof meta.product_name_suffix === 'string') {
          customChannel.productNameSuffix = meta.product_name_suffix
        }
      }
    } catch { /* ignore malformed metadata */ }
  }

  clearConfig()
  // Pre-fill config from API response. Backend omits sensitive fields entirely,
  // so those inputs stay blank — submitting blank preserves the stored secret.
  if (provider.config) {
    for (const [k, v] of Object.entries(provider.config)) {
      // Skip notifyUrl/returnUrl — they are derived from callbackBaseUrl
      if (k === 'notifyUrl' || k === 'returnUrl') continue
      config[k] = v
    }
    // Extract base URLs from existing callback URLs
    const paths = PROVIDER_CALLBACK_PATHS[provider.provider_key]
    if (paths?.notifyUrl && provider.config['notifyUrl']) {
      notifyBaseUrl.value = extractBaseUrl(provider.config['notifyUrl'], paths.notifyUrl)
    }
    if (paths?.returnUrl && provider.config['returnUrl']) {
      returnBaseUrl.value = extractBaseUrl(provider.config['returnUrl'], paths.returnUrl)
    }
  }
  applyDefaults()
  // Parse existing limits
  if (provider.limits) {
    try {
      const parsed = JSON.parse(provider.limits)
      for (const [pt, fields] of Object.entries(parsed as Record<string, Record<string, number>>)) {
        limits[pt] = { ...fields }
      }
      limitsExpanded.value = Object.keys(limits).length > 0
    } catch { /* ignore */ }
  }
}

defineExpose({ reset, loadProvider })
</script>
