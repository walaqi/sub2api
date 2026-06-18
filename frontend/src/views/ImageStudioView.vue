<template>
  <div class="flex min-h-screen flex-col items-center justify-center gap-6 bg-gray-50 px-4 py-10 text-center dark:bg-dark-900">
    <!-- Loading: minting ticket + redirecting -->
    <template v-if="state === 'loading'">
      <div class="h-10 w-10 animate-spin rounded-full border-4 border-primary-200 border-t-primary-500" />
      <div class="flex flex-col gap-1">
        <h1 class="text-lg font-semibold text-gray-900 dark:text-white">
          {{ t('imageStudio.title') }}
        </h1>
        <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('imageStudio.redirecting') }}</p>
      </div>
    </template>

    <!-- Error: disabled or failed -->
    <template v-else>
      <div class="flex max-w-md flex-col items-center gap-3">
        <Icon name="infoCircle" size="lg" class="text-amber-500" />
        <h1 class="text-lg font-semibold text-gray-900 dark:text-white">
          {{ t('imageStudio.title') }}
        </h1>
        <p class="text-sm text-gray-500 dark:text-gray-400">{{ errorMessage }}</p>
      </div>
      <div class="flex items-center gap-3">
        <button class="btn btn-secondary" type="button" @click="goBack">
          {{ t('imageStudio.back') }}
        </button>
        <button class="btn btn-primary" type="button" @click="launch">
          {{ t('imageStudio.retry') }}
        </button>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import Icon from '@/components/icons/Icon.vue'
import { imageStudioAPI } from '@/api'

const { t } = useI18n()
const router = useRouter()

type ViewState = 'loading' | 'error'
const state = ref<ViewState>('loading')
const errorMessage = ref('')

// Same-origin mount point of the image-studio sub-app (reverse-proxied to its
// backend in production). The ticket is verified there and exchanged for the
// sub-app's own session cookie. A full-page redirect discards this SPA, so
// image-studio runs standalone with its own toolbar/UI — we never embed it.
const IMAGE_STUDIO_PATH = '/image-studio/'

async function launch() {
  state.value = 'loading'
  try {
    const { ticket } = await imageStudioAPI.getTicket()
    const url = `${IMAGE_STUDIO_PATH}?ticket=${encodeURIComponent(ticket)}`
    window.location.href = url
  } catch (err) {
    state.value = 'error'
    const e = err as { code?: number | string }
    // 404 = feature disabled on the backend (config switch off).
    errorMessage.value = e?.code === 404 ? t('imageStudio.disabled') : t('imageStudio.failed')
  }
}

function goBack() {
  if (window.history.length > 1) {
    router.back()
  } else {
    router.replace('/')
  }
}

onMounted(launch)
</script>
