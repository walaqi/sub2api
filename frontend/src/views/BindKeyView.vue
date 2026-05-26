<template>
  <component :is="layoutComponent">
    <div class="mx-auto w-full max-w-2xl md:max-w-3xl space-y-6 p-4 md:p-6">
      <!-- Title card -->
      <div class="card overflow-hidden">
        <div class="bg-gradient-to-br from-primary-500 to-primary-600 px-6 py-8 md:py-10 text-center">
          <div
            class="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-white/20 backdrop-blur-sm"
          >
            <Icon name="key" size="xl" class="text-white" />
          </div>
          <h1 class="text-2xl font-bold text-white">{{ tr.title }}</h1>
          <p class="mt-2 text-sm text-primary-100">{{ tr.subtitle }}</p>
        </div>
      </div>

      <!-- Storage unavailable banner -->
      <div
        v-if="!storageOk"
        class="card border-amber-200 bg-amber-50 dark:border-amber-800/50 dark:bg-amber-900/20"
      >
        <div class="p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/30"
            >
              <Icon name="exclamationCircle" size="md" class="text-amber-600 dark:text-amber-400" />
            </div>
            <div class="flex-1">
              <h3 class="text-sm font-semibold text-amber-800 dark:text-amber-300">
                {{ tr.storageUnavailableTitle }}
              </h3>
              <p class="mt-2 text-sm text-amber-700 dark:text-amber-400">
                {{ tr.storageUnavailableBody }}
              </p>
              <button class="btn btn-primary mt-4" @click="recheckStorage">
                {{ tr.recheckStorage }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Main flow (only when storage works) -->
      <template v-else>
        <!-- Success message (shown across eligibility branches so users see
             confirmation even after we flip to the monthly-blocked card). -->
        <transition name="fade">
          <div
            v-if="successMessage"
            class="card border-emerald-200 bg-emerald-50 dark:border-emerald-800/50 dark:bg-emerald-900/20"
          >
            <div class="p-6 md:p-8">
              <div class="flex items-start gap-4">
                <div
                  class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-emerald-100 dark:bg-emerald-900/30"
                >
                  <Icon name="checkCircle" size="md" class="text-emerald-600 dark:text-emerald-400" />
                </div>
                <div class="flex-1">
                  <h3 class="text-sm font-semibold text-emerald-800 dark:text-emerald-300">
                    {{ tr.successTitle }}
                  </h3>
                  <p class="mt-2 text-sm text-emerald-700 dark:text-emerald-400">
                    {{ successMessage }}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </transition>

        <!-- Eligibility checking spinner -->
        <div v-if="loadingEligibility" class="card">
          <div class="p-6 flex items-center gap-3 text-sm text-gray-600 dark:text-dark-300">
            <Icon name="clock" size="md" class="text-primary-500 animate-pulse" />
            {{ tr.eligibilityChecking }}
          </div>
        </div>

        <!-- Feature disabled card -->
        <div
          v-else-if="featureDisabled"
          class="card border-gray-200 bg-gray-50 dark:border-dark-700 dark:bg-dark-800/40"
        >
          <div class="p-6 md:p-8">
            <div class="flex items-start gap-4">
              <div
                class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-gray-200 dark:bg-dark-700"
              >
                <Icon name="exclamationCircle" size="md" class="text-gray-600 dark:text-dark-300" />
              </div>
              <div class="flex-1">
                <h3 class="text-sm font-semibold text-gray-800 dark:text-dark-100">
                  {{ tr.featureDisabledTitle }}
                </h3>
                <p class="mt-2 text-sm text-gray-700 dark:text-dark-300">
                  {{ tr.featureDisabledBody }}
                </p>
              </div>
            </div>
          </div>
        </div>

        <!-- Monthly limit reached -->
        <div
          v-else-if="monthlyBlocked"
          class="card border-purple-200 bg-purple-50 dark:border-purple-800/50 dark:bg-purple-900/20"
        >
          <div class="p-6 md:p-8">
            <div class="flex items-start gap-4">
              <div
                class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-purple-100 dark:bg-purple-900/30"
              >
                <Icon name="checkCircle" size="md" class="text-purple-600 dark:text-purple-400" />
              </div>
              <div class="flex-1">
                <h3 class="text-sm font-semibold text-purple-800 dark:text-purple-300">
                  {{ tr.monthlyLimitTitle }}
                </h3>
                <p class="mt-2 text-sm text-purple-700 dark:text-purple-400">
                  {{ tr.monthlyLimitBody }}
                </p>
                <p
                  v-if="resetCountdown"
                  class="mt-3 text-sm text-purple-700 dark:text-purple-400"
                >
                  {{ tr.nextResetLabel }}:
                  <span class="font-mono font-semibold">{{ resetCountdown }}</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        <div v-else class="space-y-6">
          <!-- Pending reservation banner -->
            <div
              v-if="pending"
              class="card border-primary-200 bg-primary-50 dark:border-primary-800/50 dark:bg-primary-900/20"
            >
              <div class="p-6 md:p-8 space-y-3">
                <div class="flex items-center gap-3">
                  <Icon name="clock" size="md" class="text-primary-600 dark:text-primary-400" />
                  <h3 class="text-sm font-semibold text-primary-800 dark:text-primary-300">
                    {{ tr.pendingTitle }}
                  </h3>
                </div>
                <p class="text-sm text-primary-700 dark:text-primary-400">
                  {{ tr.pendingMatched }}: <span class="font-mono">{{ pending.masked_key }}</span>
                </p>
                <p class="text-sm text-primary-700 dark:text-primary-400">
                  {{ tr.pendingExpires }}: <span class="font-mono">{{ remainingMmSs }}</span>
                </p>
                <div class="flex flex-wrap gap-2 pt-2">
                  <button
                    v-if="isAuthenticated"
                    class="btn btn-primary"
                    :disabled="committing"
                    @click="commitReservation"
                  >
                    {{ committing ? tr.committing : tr.confirmBind }}
                  </button>
                  <button class="btn btn-ghost" @click="cancelPending">
                    {{ tr.cancelPending }}
                  </button>
                </div>
              </div>
            </div>

            <!-- Paste & reserve form -->
            <div v-if="!pending" class="card">
              <div class="p-6 md:p-8">
                <form class="space-y-5" @submit.prevent="reserveKeys">
                  <div>
                    <label for="bindkey-textarea" class="input-label">{{ tr.pasteLabel }}</label>
                    <textarea
                      id="bindkey-textarea"
                      v-model="rawInput"
                      :placeholder="tr.pastePlaceholder"
                      :disabled="reserving"
                      rows="6"
                      class="input mt-1 font-mono text-sm"
                    ></textarea>
                    <p class="input-hint">{{ tr.pasteHint }}</p>
                  </div>

                  <button
                    type="submit"
                    class="btn btn-primary w-full py-3"
                    :disabled="!hasInput || reserving"
                  >
                    <Icon v-if="!reserving" name="key" size="md" class="mr-2" />
                    {{ reserving ? tr.reserving : tr.bindButton }}
                  </button>
                </form>
              </div>
            </div>

            <!-- Inline auth panel for anonymous user with a pending reservation -->
            <div v-if="pending && !isAuthenticated" class="card">
              <div class="p-6 md:p-8 space-y-4">
                <div class="flex gap-2">
                  <button
                    class="btn"
                    :class="authMode === 'login' ? 'btn-primary' : 'btn-ghost'"
                    @click="authMode = 'login'"
                  >
                    {{ tr.loginTab }}
                  </button>
                  <button
                    class="btn"
                    :class="authMode === 'register' ? 'btn-primary' : 'btn-ghost'"
                    @click="authMode = 'register'"
                  >
                    {{ tr.registerTab }}
                  </button>
                </div>

                <form class="space-y-4" @submit.prevent="submitAuth">
                  <div>
                    <label for="bindkey-email" class="input-label">{{ tr.emailLabel }}</label>
                    <input
                      id="bindkey-email"
                      v-model="authEmail"
                      type="email"
                      required
                      :placeholder="tr.emailPlaceholder"
                      :disabled="authing || verifyStep === 'code'"
                      class="input mt-1"
                    />
                  </div>
                  <div>
                    <label for="bindkey-password" class="input-label">{{ tr.passwordLabel }}</label>
                    <input
                      id="bindkey-password"
                      v-model="authPassword"
                      type="password"
                      required
                      :placeholder="tr.passwordPlaceholder"
                      :disabled="authing || verifyStep === 'code'"
                      class="input mt-1"
                    />
                  </div>

                  <!-- Turnstile (rendered when enabled and we still need a token) -->
                  <div
                    v-if="turnstileEnabled && turnstileSiteKey && (authMode === 'login' || verifyStep === 'credentials')"
                  >
                    <TurnstileWidget
                      :key="turnstileWidgetKey"
                      :site-key="turnstileSiteKey"
                      @verify="(t: string) => (turnstileToken = t)"
                      @expire="turnstileToken = ''"
                      @error="turnstileToken = ''"
                    />
                  </div>

                  <!-- Verification code step (register + email_verify_enabled) -->
                  <div v-if="authMode === 'register' && emailVerifyEnabled && verifyStep === 'code'">
                    <label for="bindkey-verify-code" class="input-label">
                      {{ tr.verifyCodeLabel }}
                    </label>
                    <input
                      id="bindkey-verify-code"
                      v-model="verifyCode"
                      type="text"
                      inputmode="numeric"
                      maxlength="6"
                      required
                      :placeholder="tr.verifyCodePlaceholder"
                      :disabled="authing"
                      class="input mt-1 font-mono tracking-widest"
                    />
                    <p class="input-hint">{{ tr.codeSentHint }}</p>
                    <div class="mt-2 flex items-center justify-between text-xs">
                      <button
                        type="button"
                        class="text-primary-600 dark:text-primary-400 hover:underline disabled:opacity-50 disabled:no-underline"
                        :disabled="codeSending || codeCountdown > 0"
                        @click="sendRegisterCode"
                      >
                        {{
                          codeSending
                            ? tr.sendingCode
                            : codeCountdown > 0
                              ? tr.resendCodeIn.replace('{s}', String(codeCountdown))
                              : tr.resendCode
                        }}
                      </button>
                    </div>
                  </div>

                  <button type="submit" class="btn btn-primary w-full py-3" :disabled="authing || codeSending">
                    {{
                      authing
                        ? tr.authing
                        : authMode === 'login'
                          ? tr.loginButton
                          : emailVerifyEnabled
                            ? verifyStep === 'credentials'
                              ? (codeSending ? tr.sendingCode : tr.sendCodeButton)
                              : tr.verifyAndRegisterButton
                            : tr.registerButton
                    }}
                  </button>
                </form>

                <p class="text-xs text-gray-500 dark:text-dark-400">
                  {{ tr.authFooterHint }}
                </p>
                <p class="text-xs text-gray-500 dark:text-dark-400">
                  {{ tr.fullRegisterHintPrefix }}
                  <a
                    :href="fullRegisterUrl"
                    class="text-primary-600 hover:underline dark:text-primary-400"
                    >{{ fullRegisterUrl }}</a
                  >
                </p>
              </div>
            </div>

            <!-- Error message -->
            <transition name="fade">
              <div
                v-if="errorMessage"
                class="card border-red-200 bg-red-50 dark:border-red-800/50 dark:bg-red-900/20"
              >
                <div class="p-6 md:p-8">
                  <div class="flex items-start gap-4">
                    <div
                      class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-red-100 dark:bg-red-900/30"
                    >
                      <Icon name="exclamationCircle" size="md" class="text-red-600 dark:text-red-400" />
                    </div>
                    <div class="flex-1">
                      <h3 class="text-sm font-semibold text-red-800 dark:text-red-300">
                        {{ tr.errorTitle }}
                      </h3>
                      <p class="mt-2 text-sm text-red-700 dark:text-red-400">{{ errorMessage }}</p>
                    </div>
                  </div>
                </div>
              </div>
            </transition>

          <!-- Info card -->
          <div
            class="card border-primary-200 bg-primary-50 dark:border-primary-800/50 dark:bg-primary-900/20"
          >
            <div class="p-6 md:p-8">
              <div class="flex items-start gap-4">
                <div
                  class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-primary-100 dark:bg-primary-900/30"
                >
                  <Icon name="infoCircle" size="md" class="text-primary-600 dark:text-primary-400" />
                </div>
                <div class="flex-1">
                  <h3 class="text-sm font-semibold text-primary-800 dark:text-primary-300">
                    {{ tr.howItWorksTitle }}
                  </h3>
                  <ul
                    class="mt-2 list-inside list-disc space-y-1 text-sm text-primary-700 dark:text-primary-400"
                  >
                    <li>{{ tr.howItWorks1 }}</li>
                    <li>{{ tr.howItWorks2 }}</li>
                    <li>{{ tr.howItWorks3 }}</li>
                    <li>{{ tr.howItWorks4 }}</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </template>
    </div>
  </component>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiClient } from '@/api/client'
import { getPublicSettings, sendVerifyCode } from '@/api/auth'
import { useAuthStore } from '@/stores/auth'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'
import TurnstileWidget from '@/components/TurnstileWidget.vue'

// Anonymous wrapper: gives the page a full-width canvas without clamping
// content to AuthLayout's max-w-md (which is sized for login cards).
const AnonShell = defineComponent({
  name: 'BindKeyAnonShell',
  setup(_, { slots }) {
    return () =>
      h(
        'div',
        { class: 'relative min-h-screen bg-gray-50 dark:bg-dark-950' },
        [
          h('div', {
            class:
              'pointer-events-none fixed inset-0 bg-gradient-to-br from-gray-50 via-primary-50/30 to-gray-100 dark:from-dark-950 dark:via-dark-900 dark:to-dark-950',
          }),
          h(
            'div',
            { class: 'pointer-events-none fixed inset-0 overflow-hidden' },
            [
              h('div', {
                class:
                  'absolute -right-40 -top-40 h-80 w-80 rounded-full bg-primary-400/20 blur-3xl',
              }),
              h('div', {
                class:
                  'absolute -bottom-40 -left-40 h-80 w-80 rounded-full bg-primary-500/15 blur-3xl',
              }),
              h('div', {
                class:
                  'absolute inset-0 bg-[linear-gradient(rgba(20,184,166,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(20,184,166,0.03)_1px,transparent_1px)] bg-[size:64px_64px]',
              }),
            ]
          ),
          h('main', { class: 'relative z-10 p-4 md:p-6 lg:p-8' }, slots.default?.()),
        ]
      )
  },
})

// ----- Bilingual copy (kept inline so we don't touch i18n locale files) -----
type Copy = Record<string, string>
const en: Copy = {
  title: 'Bind API Keys',
  subtitle: 'Paste one or more keys (one per line) to bind to your account.',
  pasteLabel: 'API Keys',
  pastePlaceholder: 'sk-xxxxxxxxxxxxxxxxxxxx\nsk-yyyyyyyyyyyyyyyyyyyy',
  pasteHint: 'Up to 50 keys per request. The first eligible key (unbound, >50% remaining quota) will be reserved for 5 minutes.',
  bindButton: 'Reserve & Bind',
  reserving: 'Reserving…',
  pendingTitle: 'Reservation in progress',
  pendingMatched: 'Matched key',
  pendingExpires: 'Expires in',
  confirmBind: 'Confirm Binding',
  committing: 'Binding…',
  cancelPending: 'Discard',
  loginTab: 'Login',
  registerTab: 'Register',
  emailLabel: 'Email',
  emailPlaceholder: 'you@example.com',
  passwordLabel: 'Password',
  passwordPlaceholder: '••••••••',
  loginButton: 'Login & Bind',
  registerButton: 'Register & Bind',
  authing: 'Processing…',
  authFooterHint: 'Your reservation is held for up to 5 minutes. Login or register to claim it.',
  fullRegisterHintPrefix: 'For the full registration flow, visit',
  successTitle: 'Key bound successfully',
  errorTitle: 'Something went wrong',
  storageUnavailableTitle: 'Browser storage is unavailable',
  storageUnavailableBody:
    'This page needs local storage to remember your reservation across the login or registration step. Please disable private/incognito mode, allow cookies and storage for this site, then click "Re-check".',
  recheckStorage: 'Re-check',
  howItWorksTitle: 'How it works',
  howItWorks1: 'We scan your input top-to-bottom and pick the first eligible key.',
  howItWorks2: 'Reserved keys are locked for 5 minutes so no one else can bind them.',
  howItWorks3: 'If you are not logged in, register or log in below to complete the binding.',
  howItWorks4: 'Eligibility: key is active, unclaimed, and has more than 50% remaining quota.',
  expired: 'Reservation expired. Please paste your keys again.',
  noEligible: 'No eligible key found in your list. The keys may already be claimed or have less than 50% quota left.',
  emptyInput: 'Please paste at least one key.',
  successBound: 'The key {key} is now bound to your account.',
  monthlyLimitTitle: 'You have already bound a key this month',
  monthlyLimitBody: 'Each account can claim one key per natural month. Eligibility resets on the 1st of next month.',
  nextResetLabel: 'Next reset in',
  daysShort: 'd',
  hoursShort: 'h',
  minutesShort: 'm',
  featureDisabledTitle: 'This feature is currently unavailable',
  featureDisabledBody: 'The key pool has not been configured by the administrator. Please try again later.',
  eligibilityChecking: 'Checking your eligibility…',
  verifyCodeLabel: 'Verification Code',
  verifyCodePlaceholder: '6-digit code',
  sendCodeButton: 'Send Code',
  sendingCode: 'Sending…',
  resendCodeIn: 'Resend in {s}s',
  resendCode: 'Resend',
  verifyAndRegisterButton: 'Verify & Register',
  codeSentHint: 'A 6-digit code has been sent to your email. It expires in a few minutes.',
  codeRequired: 'Please enter the 6-digit verification code.',
  invalidCode: 'The code must be 6 digits.',
  turnstileRequired: 'Please complete the human verification.',
}
const zh: Copy = {
  title: '绑定 API Key',
  subtitle: '粘贴一行或多行 Key（每行一个），系统将帮你绑定到账户。',
  pasteLabel: 'API Key 列表',
  pastePlaceholder: 'sk-xxxxxxxxxxxxxxxxxxxx\nsk-yyyyyyyyyyyyyyyyyyyy',
  pasteHint: '单次最多 50 行。系统将自动从上到下选择第一个符合条件的 Key（未被绑定、剩余配额 > 50%）并预留 5 分钟。',
  bindButton: '预留并绑定',
  reserving: '预留中…',
  pendingTitle: '绑定预留中',
  pendingMatched: '匹配到的 Key',
  pendingExpires: '剩余时间',
  confirmBind: '确认绑定',
  committing: '绑定中…',
  cancelPending: '放弃',
  loginTab: '登录',
  registerTab: '注册',
  emailLabel: '邮箱',
  emailPlaceholder: 'you@example.com',
  passwordLabel: '密码',
  passwordPlaceholder: '••••••••',
  loginButton: '登录并完成绑定',
  registerButton: '注册并完成绑定',
  authing: '处理中…',
  authFooterHint: '你的预留有效期为 5 分钟，请登录或注册以完成绑定。',
  fullRegisterHintPrefix: '如果需要完整注册流程请访问',
  successTitle: '绑定成功',
  errorTitle: '出现错误',
  storageUnavailableTitle: '浏览器本地存储不可用',
  storageUnavailableBody:
    '本页需要使用本地存储来记住你的绑定预留（登录/注册时不会丢）。请关闭隐私/无痕模式，并在浏览器设置中允许本站点存储，然后点击"重新检测"。',
  recheckStorage: '重新检测',
  howItWorksTitle: '工作原理',
  howItWorks1: '系统从上到下扫描你输入的列表，挑选第一个符合条件的 Key。',
  howItWorks2: '被选中的 Key 会被锁定 5 分钟，期间不会被其他人抢走。',
  howItWorks3: '若未登录，可在下方直接登录或注册完成绑定。',
  howItWorks4: '可领取条件：Key 处于激活状态、尚未被领取、剩余配额 > 50%。',
  expired: '预留已过期，请重新粘贴 Key 再试。',
  noEligible: '列表中没有可用的 Key。这些 Key 可能已被绑定，或剩余配额不足 50%。',
  emptyInput: '请至少粘贴一个 Key。',
  successBound: 'Key {key} 已成功绑定到你的账户。',
  monthlyLimitTitle: '本月已参与绑定',
  monthlyLimitBody: '每个账号每个自然月只能领取一次。下月 1 日 0 点自动恢复资格。',
  nextResetLabel: '下次重置',
  daysShort: '天',
  hoursShort: '小时',
  minutesShort: '分钟',
  featureDisabledTitle: '该功能当前未开启',
  featureDisabledBody: '管理员尚未配置 Key 池，请稍后再试。',
  eligibilityChecking: '正在检查参与资格…',
  verifyCodeLabel: '邮箱验证码',
  verifyCodePlaceholder: '6 位验证码',
  sendCodeButton: '发送验证码',
  sendingCode: '发送中…',
  resendCodeIn: '{s} 秒后可重发',
  resendCode: '重新发送',
  verifyAndRegisterButton: '验证并注册',
  codeSentHint: '6 位验证码已发送到你的邮箱，几分钟内有效。',
  codeRequired: '请输入 6 位验证码。',
  invalidCode: '验证码必须为 6 位数字。',
  turnstileRequired: '请先完成人机验证。',
}

const { locale } = useI18n()
const tr = computed<Copy>(() => (String(locale.value).startsWith('zh') ? zh : en))

const fullRegisterUrl = computed(() => `${window.location.origin}/register`)

// ----- Storage availability detection -----
const STORAGE_KEY = 'bindkey_pending'
function isStorageAvailable(): boolean {
  try {
    const probe = '__bindkey_probe__'
    window.localStorage.setItem(probe, probe)
    window.localStorage.removeItem(probe)
    return true
  } catch {
    return false
  }
}
const storageOk = ref(isStorageAvailable())
function recheckStorage(): void {
  storageOk.value = isStorageAvailable()
  if (storageOk.value) {
    pending.value = readPending()
  }
}

// ----- Auth state -----
const authStore = useAuthStore()
const isAuthenticated = computed(() => authStore.isAuthenticated)
const layoutComponent = computed(() => (isAuthenticated.value ? AppLayout : AnonShell))

// ----- Component state -----
type Pending = {
  reservation_id: string
  masked_key: string
  expires_at_unix_ms: number
}
function readPending(): Pending | null {
  if (!storageOk.value) return null
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Pending
    if (!parsed?.reservation_id || !parsed?.expires_at_unix_ms) return null
    if (parsed.expires_at_unix_ms < Date.now()) {
      window.localStorage.removeItem(STORAGE_KEY)
      return null
    }
    return parsed
  } catch {
    return null
  }
}
function writePending(p: Pending): void {
  if (!storageOk.value) return
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(p))
  } catch {
    /* ignore */
  }
}
function clearPending(): void {
  if (!storageOk.value) return
  try {
    window.localStorage.removeItem(STORAGE_KEY)
  } catch {
    /* ignore */
  }
}

const rawInput = ref('')
const reserving = ref(false)
const committing = ref(false)
const authing = ref(false)
const authMode = ref<'login' | 'register'>('register')
const authEmail = ref('')
const authPassword = ref('')
const errorMessage = ref('')
const successMessage = ref('')
const pending = ref<Pending | null>(null)

// Public settings (loaded on mount): drives whether registration requires
// email verification and/or Turnstile. Defaults are conservative (off) so
// the existing single-step flow keeps working when settings fail to load.
const emailVerifyEnabled = ref(false)
const turnstileEnabled = ref(false)
const turnstileSiteKey = ref('')

// Two-step register state. When emailVerifyEnabled is true, submitAuth()
// transitions credentials → code instead of calling register directly.
const verifyStep = ref<'credentials' | 'code'>('credentials')
const verifyCode = ref('')
const codeSending = ref(false)
const codeCountdown = ref(0)
let codeCountdownTimer: ReturnType<typeof setInterval> | null = null
const turnstileToken = ref('')
const turnstileWidgetKey = ref(0)

type Eligibility = {
  eligible: boolean
  already_participated: boolean
  next_reset_unix_ms: number
  reason?: string
}
const eligibility = ref<Eligibility | null>(null)
const loadingEligibility = ref(false)

const featureDisabled = computed(
  () => eligibility.value?.eligible === false && eligibility.value?.reason === 'feature_disabled'
)
const monthlyBlocked = computed(() => eligibility.value?.already_participated === true)

// Local fallback when the backend's next_reset_unix_ms isn't available
// (e.g. eligibility request failed). Mirrors the server's "1st of next
// natural month at 00:00 server-local" semantics closely enough for UI
// countdown — the source of truth refreshes on next page load.
function computeNextNaturalMonthMs(): number {
  const d = new Date()
  return new Date(d.getFullYear(), d.getMonth() + 1, 1, 0, 0, 0, 0).getTime()
}

const hasInput = computed(() => rawInput.value.trim().length > 0)

// ----- Countdown -----
const now = ref(Date.now())
let timer: ReturnType<typeof setInterval> | null = null
const remainingMs = computed(() => {
  if (!pending.value) return 0
  return Math.max(0, pending.value.expires_at_unix_ms - now.value)
})
const remainingMmSs = computed(() => {
  const ms = remainingMs.value
  const totalSec = Math.floor(ms / 1000)
  const m = Math.floor(totalSec / 60)
  const s = totalSec % 60
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`
})
watch(remainingMs, (v) => {
  if (v <= 0 && pending.value) {
    errorMessage.value = tr.value.expired
    cancelPending()
  }
})

// ----- API calls -----
type ApiEnvelope<T> = { code: number; data: T; message?: string }
function extractError(e: any): string {
  return (
    e?.message ||
    e?.response?.data?.message ||
    e?.response?.data?.detail ||
    'unknown error'
  )
}

async function fetchEligibility(): Promise<void> {
  if (!isAuthenticated.value) {
    eligibility.value = null
    return
  }
  loadingEligibility.value = true
  try {
    const { data } = await apiClient.get<ApiEnvelope<Eligibility>>('/bind-key/eligibility')
    const result = ((data as any).data ?? data) as Eligibility
    eligibility.value = result
  } catch (e: any) {
    // Non-fatal: fall back to letting the user attempt the flow; commit will gate.
    eligibility.value = null
  } finally {
    loadingEligibility.value = false
  }
}

const resetCountdown = computed(() => {
  const ts = eligibility.value?.next_reset_unix_ms
  if (!ts) return ''
  const ms = ts - now.value
  if (ms <= 0) return ''
  const totalMin = Math.floor(ms / 60000)
  const days = Math.floor(totalMin / (60 * 24))
  const hours = Math.floor((totalMin % (60 * 24)) / 60)
  const minutes = totalMin % 60
  const parts: string[] = []
  if (days > 0) parts.push(`${days}${tr.value.daysShort}`)
  if (hours > 0 || days > 0) parts.push(`${hours}${tr.value.hoursShort}`)
  parts.push(`${minutes}${tr.value.minutesShort}`)
  return parts.join(' ')
})

async function reserveKeys(): Promise<void> {
  errorMessage.value = ''
  successMessage.value = ''
  const lines = rawInput.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  if (lines.length === 0) {
    errorMessage.value = tr.value.emptyInput
    return
  }
  reserving.value = true
  try {
    const { data } = await apiClient.post<ApiEnvelope<Pending>>('/bind-key/reserve', {
      keys: lines,
    })
    const result = (data as any).data ?? data
    pending.value = result
    writePending(result)
    rawInput.value = ''
    if (isAuthenticated.value) {
      await commitReservation()
    }
  } catch (e: any) {
    const code = e?.reason ?? e?.response?.data?.reason
    if (code === 'BIND_KEY_NO_ELIGIBLE') {
      errorMessage.value = tr.value.noEligible
    } else {
      errorMessage.value = extractError(e)
    }
  } finally {
    reserving.value = false
  }
}

async function commitReservation(): Promise<void> {
  if (!pending.value) return
  errorMessage.value = ''
  committing.value = true
  try {
    const { data } = await apiClient.post<ApiEnvelope<{ masked_key: string }>>(
      '/bind-key/commit',
      { reservation_id: pending.value.reservation_id }
    )
    const result = (data as any).data ?? data
    successMessage.value = tr.value.successBound.replace(
      '{key}',
      result?.masked_key || pending.value.masked_key
    )
    clearPending()
    pending.value = null
    rawInput.value = ''
    errorMessage.value = ''
    // Reflect the just-recorded monthly participation in the UI so the form
    // is replaced by the "本月已参与" card. Otherwise re-pasting the same key
    // would hit /reserve and surface a misleading "no eligible key" error.
    eligibility.value = {
      eligible: false,
      already_participated: true,
      next_reset_unix_ms:
        eligibility.value?.next_reset_unix_ms ?? computeNextNaturalMonthMs(),
    }
  } catch (e: any) {
    const code = e?.reason ?? e?.response?.data?.reason
    if (code === 'BIND_KEY_RESERVATION_EXPIRED') {
      errorMessage.value = tr.value.expired
      clearPending()
      pending.value = null
    } else if (code === 'BIND_KEY_ALREADY_PARTICIPATED') {
      // Server-side gate fired (e.g. user opened two tabs). Flip the UI
      // into the monthly-limit state so it's consistent with refresh.
      eligibility.value = {
        eligible: false,
        already_participated: true,
        next_reset_unix_ms:
          e?.metadata?.next_reset_unix_ms ??
          e?.response?.data?.data?.next_reset_unix_ms ??
          eligibility.value?.next_reset_unix_ms ??
          0,
      }
      clearPending()
      pending.value = null
    } else {
      errorMessage.value = extractError(e)
    }
  } finally {
    committing.value = false
  }
}

function cancelPending(): void {
  clearPending()
  pending.value = null
}

function startCodeCountdown(seconds: number): void {
  if (codeCountdownTimer) {
    clearInterval(codeCountdownTimer)
    codeCountdownTimer = null
  }
  codeCountdown.value = Math.max(0, Math.floor(seconds))
  if (codeCountdown.value <= 0) return
  codeCountdownTimer = setInterval(() => {
    if (codeCountdown.value > 0) {
      codeCountdown.value--
    } else if (codeCountdownTimer) {
      clearInterval(codeCountdownTimer)
      codeCountdownTimer = null
    }
  }, 1000)
}

async function sendRegisterCode(): Promise<void> {
  errorMessage.value = ''
  const email = authEmail.value.trim()
  if (!email) {
    errorMessage.value = tr.value.emailLabel
    return
  }
  if (turnstileEnabled.value && !turnstileToken.value) {
    errorMessage.value = tr.value.turnstileRequired
    return
  }
  codeSending.value = true
  try {
    const resp = await sendVerifyCode({
      email,
      turnstile_token: turnstileToken.value || undefined,
    })
    verifyStep.value = 'code'
    startCodeCountdown(resp.countdown || 60)
    // Token is single-use; force a re-render so the next resend asks anew.
    turnstileToken.value = ''
    turnstileWidgetKey.value++
  } catch (e: any) {
    errorMessage.value = extractError(e)
  } finally {
    codeSending.value = false
  }
}

async function submitAuth(): Promise<void> {
  errorMessage.value = ''
  authing.value = true
  try {
    if (authMode.value === 'login') {
      await authStore.login({
        email: authEmail.value.trim(),
        password: authPassword.value,
        turnstile_token: turnstileEnabled.value ? turnstileToken.value || undefined : undefined,
      })
    } else if (emailVerifyEnabled.value) {
      // Two-step: first click sends code, second click submits register with code.
      if (verifyStep.value === 'credentials') {
        await sendRegisterCode()
        return
      }
      const code = verifyCode.value.trim()
      if (!code) {
        errorMessage.value = tr.value.codeRequired
        return
      }
      if (!/^\d{6}$/.test(code)) {
        errorMessage.value = tr.value.invalidCode
        return
      }
      await authStore.register({
        email: authEmail.value.trim(),
        password: authPassword.value,
        verify_code: code,
      })
    } else {
      // Single-step register (email verify disabled).
      await authStore.register({
        email: authEmail.value.trim(),
        password: authPassword.value,
        turnstile_token: turnstileEnabled.value ? turnstileToken.value || undefined : undefined,
      })
    }
    // After successful auth, isAuthenticated should be true. Refresh
    // eligibility before committing so anonymous users who already
    // participated this month see the monthly-limit card directly,
    // instead of hitting /commit and bouncing through an error state.
    if (isAuthenticated.value) {
      await fetchEligibility()
      if (monthlyBlocked.value || featureDisabled.value) {
        clearPending()
        pending.value = null
        return
      }
      if (pending.value) {
        await commitReservation()
      }
    }
  } catch (e: any) {
    errorMessage.value = extractError(e)
  } finally {
    authing.value = false
  }
}

// ----- Lifecycle -----
onMounted(async () => {
  if (!storageOk.value) return
  pending.value = readPending()
  // Load public settings to know whether registration requires email
  // verification or Turnstile. Failures are non-fatal: we keep the
  // single-step flow and let the backend reject if needed.
  try {
    const settings = await getPublicSettings()
    emailVerifyEnabled.value = !!settings.email_verify_enabled
    turnstileEnabled.value = !!settings.turnstile_enabled
    turnstileSiteKey.value = settings.turnstile_site_key || ''
  } catch {
    /* ignore */
  }
  if (isAuthenticated.value) {
    await fetchEligibility()
  }
  // Auto-commit if we returned to the page already logged in with a live
  // pending and we still have eligibility.
  if (
    pending.value &&
    isAuthenticated.value &&
    !featureDisabled.value &&
    !monthlyBlocked.value
  ) {
    await commitReservation()
  }
  timer = setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

// Switching login/register tab resets the two-step verify state.
watch(authMode, () => {
  verifyStep.value = 'credentials'
  verifyCode.value = ''
  errorMessage.value = ''
  if (codeCountdownTimer) {
    clearInterval(codeCountdownTimer)
    codeCountdownTimer = null
  }
  codeCountdown.value = 0
})

watch(isAuthenticated, async (v) => {
  if (v) {
    await fetchEligibility()
  } else {
    eligibility.value = null
  }
})

onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  if (codeCountdownTimer) clearInterval(codeCountdownTimer)
})
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: all 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
