<template>
  <AppLayout>
    <div class="mx-auto max-w-3xl space-y-6">
      <div class="card">
        <div class="border-b border-gray-100 px-6 py-4 dark:border-dark-700">
          <div class="flex items-center gap-3">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-900/30"
            >
              <Icon name="calendar" size="md" class="text-emerald-700 dark:text-emerald-300" />
            </div>
            <div>
              <h1 class="text-lg font-semibold text-gray-900 dark:text-white">活动报名</h1>
              <p class="text-sm text-gray-500 dark:text-dark-400">选择活动并填写接收邮件地址</p>
            </div>
          </div>
        </div>

        <div class="space-y-5 p-6">
          <div v-if="loading" class="flex items-center justify-center py-10">
            <svg class="h-6 w-6 animate-spin text-emerald-600" fill="none" viewBox="0 0 24 24">
              <circle
                class="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                stroke-width="4"
              />
              <path
                class="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
          </div>

          <div v-else-if="loadError" class="empty-state py-10">
            <div
              class="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-red-100 dark:bg-red-900/30"
            >
              <Icon name="exclamationCircle" size="xl" class="text-red-500 dark:text-red-300" />
            </div>
            <p class="text-sm font-medium text-red-700 dark:text-red-300">活动列表加载失败</p>
            <p class="mt-2 max-w-md text-center text-sm text-red-600 dark:text-red-400">
              {{ loadError }}
            </p>
          </div>

          <div v-else-if="events.length === 0" class="empty-state py-10">
            <div
              class="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gray-100 dark:bg-dark-800"
            >
              <Icon name="inbox" size="xl" class="text-gray-400 dark:text-dark-500" />
            </div>
            <p class="text-sm text-gray-500 dark:text-dark-400">当前没有进行中的活动</p>
          </div>

          <form v-else class="space-y-5" @submit.prevent="handleSubmit">
            <div>
              <label for="activity" class="input-label">当前活动</label>
              <select id="activity" v-model.number="selectedEventId" class="input mt-1 h-11">
                <option v-for="event in events" :key="event.id" :value="event.id">
                  {{ event.name }}
                </option>
              </select>
            </div>

            <div
              v-if="selectedEvent"
              class="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800"
            >
              <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div class="min-w-0">
                  <h2 class="text-base font-semibold text-gray-900 dark:text-white">
                    {{ selectedEvent.name }}
                  </h2>
                  <div
                    class="activity-markdown mt-3 text-sm leading-6 text-gray-600 dark:text-dark-300"
                    v-html="renderedSelectedDescription"
                  ></div>
                </div>
                <span
                  v-if="selectedEvent.signed_up"
                  class="inline-flex flex-shrink-0 items-center rounded-md bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300"
                >
                  已报名
                </span>
              </div>
              <div class="mt-4 grid gap-2 text-xs text-gray-500 dark:text-dark-400 sm:grid-cols-2">
                <div>开始时间：{{ formatDateTime(selectedEvent.starts_at) }}</div>
                <div>结束时间：{{ selectedEvent.ends_at ? formatDateTime(selectedEvent.ends_at) : '未设置' }}</div>
              </div>
            </div>

            <div>
              <label for="receive-email" class="input-label">接收活动邮件地址</label>
              <div class="relative mt-1">
                <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4">
                  <Icon name="mail" size="md" class="text-gray-400 dark:text-dark-500" />
                </div>
                <input
                  id="receive-email"
                  v-model.trim="receiveEmail"
                  type="email"
                  required
                  :disabled="submitting"
                  class="input h-11 pl-12"
                  placeholder="name@example.com"
                />
              </div>
            </div>

            <button
              type="submit"
              class="btn btn-primary w-full py-3"
              :disabled="!selectedEvent || !receiveEmail || submitting || redirecting"
            >
              <svg
                v-if="submitting"
                class="-ml-1 mr-2 h-5 w-5 animate-spin"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  class="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  stroke-width="4"
                />
                <path
                  class="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
              </svg>
              <Icon v-else name="checkCircle" size="md" class="mr-2" />
              {{ submitting ? '提交中' : selectedEvent?.signed_up ? '更新报名' : '报名' }}
            </button>
          </form>
        </div>
      </div>

      <transition name="fade">
        <div
          v-if="successMessage"
          class="card border-emerald-200 bg-emerald-50 dark:border-emerald-800/50 dark:bg-emerald-900/20"
        >
          <div class="flex items-start gap-4 p-6">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-900/30"
            >
              <Icon name="checkCircle" size="md" class="text-emerald-600 dark:text-emerald-400" />
            </div>
            <div>
              <h3 class="text-sm font-semibold text-emerald-800 dark:text-emerald-300">报名成功</h3>
              <p class="mt-2 text-sm text-emerald-700 dark:text-emerald-400">{{ successMessage }}</p>
            </div>
          </div>
        </div>
      </transition>

      <transition name="fade">
        <div
          v-if="submitError"
          class="card border-red-200 bg-red-50 dark:border-red-800/50 dark:bg-red-900/20"
        >
          <div class="flex items-start gap-4 p-6">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900/30"
            >
              <Icon name="exclamationCircle" size="md" class="text-red-600 dark:text-red-400" />
            </div>
            <div>
              <h3 class="text-sm font-semibold text-red-800 dark:text-red-300">提交失败</h3>
              <p class="mt-2 text-sm text-red-700 dark:text-red-400">{{ submitError }}</p>
            </div>
          </div>
        </div>
      </transition>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { activityAPI, type ActivityEvent } from '@/api/activity'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'
import { formatDateTime } from '@/utils/format'

marked.setOptions({
  breaks: true,
  gfm: true,
})

const router = useRouter()

const events = ref<ActivityEvent[]>([])
const selectedEventId = ref<number | null>(null)
const receiveEmail = ref('')
const loading = ref(false)
const submitting = ref(false)
const successMessage = ref('')
const loadError = ref('')
const submitError = ref('')
// Set briefly after a successful signup that reserved a key, before we redirect
// the user to the bind-gift page. Lets the button/copy reflect the transition.
const redirecting = ref(false)

const selectedEvent = computed(() => {
  return events.value.find((event) => event.id === selectedEventId.value) ?? null
})

const renderedSelectedDescription = computed(() => {
  const markdown = selectedEvent.value?.description?.trim() || ''
  if (!markdown) {
    return ''
  }
  const html = marked.parse(markdown) as string
  return DOMPurify.sanitize(html)
})

watch(selectedEvent, (event) => {
  receiveEmail.value = event?.receive_email ?? ''
  successMessage.value = ''
  submitError.value = ''
})

async function loadEvents(): Promise<void> {
  loading.value = true
  loadError.value = ''
  try {
    events.value = await activityAPI.listActiveActivities()
    selectedEventId.value = events.value[0]?.id ?? null
  } catch (error) {
    events.value = []
    selectedEventId.value = null
    loadError.value = getErrorMessage(error, '活动列表加载失败')
  } finally {
    loading.value = false
  }
}

async function handleSubmit(): Promise<void> {
  if (!selectedEvent.value || submitting.value) {
    return
  }

  submitting.value = true
  successMessage.value = ''
  submitError.value = ''
  try {
    const signup = await activityAPI.signupActivity(selectedEvent.value.id, receiveEmail.value)
    const target = events.value.find((event) => event.id === signup.activity_id)
    if (target) {
      target.signed_up = true
      target.receive_email = signup.receive_email
    }
    receiveEmail.value = signup.receive_email

    // If the backend reserved a pool key for this activity, deep-link to the
    // bind-gift page carrying the reservation id. The user just clicks
    // "确认绑定" there to receive the gift balance (reserve was done server-side
    // so concurrent signups never race for the same key).
    if (signup.key_status === 'reserved' && signup.reservation?.reservation_id) {
      successMessage.value = '报名成功，正在跳转到赠金绑定页面…'
      redirecting.value = true
      const r = signup.reservation
      router.push({
        path: '/bind-key',
        query: {
          reservation: r.reservation_id,
          // masked_key + expiry let the bind page render the pending card
          // without re-fetching. masked_key is already masked (non-sensitive).
          mk: r.masked_key,
          exp: String(r.expires_at_unix_ms)
        }
      })
      return
    }

    // Signed up, but no key was granted. Explain why so the user isn't left
    // wondering where their gift is.
    switch (signup.key_status) {
      case 'already_claimed':
        successMessage.value = `报名成功。你已领取过本活动的赠金 Key，无需重复领取。接收活动邮件地址：${signup.receive_email}`
        break
      case 'no_key_available':
        successMessage.value = `报名成功，但本活动的赠金 Key 暂时已被领完。接收活动邮件地址：${signup.receive_email}`
        break
      case 'referral_invitee':
        successMessage.value = `报名成功。你在注册时已通过邀请获得专属权益，本活动的赠金 Key 不再重复发放。接收活动邮件地址：${signup.receive_email}`
        break
      default:
        successMessage.value = `接收活动邮件地址：${signup.receive_email}`
    }
  } catch (error) {
    submitError.value = getErrorMessage(error, '报名提交失败')
  } finally {
    submitting.value = false
  }
}

function getErrorMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'message' in error) {
    const message = String((error as { message?: unknown }).message || '').trim()
    if (message) {
      return message
    }
  }
  return fallback
}

onMounted(loadEvents)
</script>

<style scoped>
.activity-markdown {
  overflow-wrap: anywhere;
}

.activity-markdown :deep(p) {
  @apply mb-3 last:mb-0;
}

.activity-markdown :deep(h1) {
  @apply mb-3 mt-5 text-xl font-bold text-gray-900 first:mt-0 dark:text-white;
}

.activity-markdown :deep(h2) {
  @apply mb-3 mt-5 text-lg font-semibold text-gray-900 first:mt-0 dark:text-white;
}

.activity-markdown :deep(h3) {
  @apply mb-2 mt-4 text-base font-semibold text-gray-900 first:mt-0 dark:text-white;
}

.activity-markdown :deep(a) {
  @apply text-primary-600 underline underline-offset-4 hover:text-primary-700 dark:text-primary-300 dark:hover:text-primary-200;
}

.activity-markdown :deep(ul) {
  @apply mb-3 list-disc pl-5;
}

.activity-markdown :deep(ol) {
  @apply mb-3 list-decimal pl-5;
}

.activity-markdown :deep(li) {
  @apply mb-1;
}

.activity-markdown :deep(blockquote) {
  @apply my-3 border-l-4 border-gray-300 pl-4 text-gray-500 dark:border-dark-600 dark:text-dark-300;
}

.activity-markdown :deep(code) {
  @apply rounded bg-gray-200 px-1 py-0.5 font-mono text-xs text-gray-800 dark:bg-dark-700 dark:text-dark-100;
}

.activity-markdown :deep(pre) {
  @apply my-3 overflow-x-auto rounded-lg bg-gray-900 p-3 text-gray-100;
}

.activity-markdown :deep(pre code) {
  @apply bg-transparent p-0 text-gray-100;
}
</style>
