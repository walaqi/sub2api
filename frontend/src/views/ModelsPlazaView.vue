<template>
  <component :is="layoutComponent">
    <div class="mx-auto w-full max-w-7xl space-y-5 p-4 md:p-6">
      <!-- Header -->
      <div class="flex flex-col gap-1">
        <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
          {{ t('modelsPlaza.title') }}
        </h1>
        <p class="text-sm text-gray-500 dark:text-gray-400">
          {{ t('modelsPlaza.description') }}
        </p>
      </div>

      <!-- Toolbar: search + platform filter + group selector + view toggle -->
      <div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div class="flex flex-1 flex-wrap items-center gap-3">
          <!-- Search -->
          <div class="relative w-full sm:w-72">
            <Icon
              name="search"
              size="md"
              class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 dark:text-gray-500"
            />
            <input
              v-model="plaza.search.value"
              type="text"
              :placeholder="t('modelsPlaza.searchPlaceholder')"
              class="input pl-10"
            />
          </div>

          <!-- Platform filter -->
          <select v-model="plaza.platformFilter.value" class="input w-auto min-w-[140px]">
            <option value="">{{ t('modelsPlaza.allPlatforms') }}</option>
            <option v-for="p in plaza.platforms.value" :key="p" :value="p">
              {{ p }}
            </option>
          </select>

          <!-- Group selector -->
          <div class="flex items-center gap-2">
            <label class="whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
              {{ t('modelsPlaza.group') }}
            </label>
            <select
              v-model="selectedGroupModel"
              class="input w-auto min-w-[160px]"
              :disabled="plaza.groups.value.length === 0"
              :title="t('modelsPlaza.groupHint')"
            >
              <option v-if="plaza.groups.value.length === 0" :value="null">
                {{ t('modelsPlaza.noGroup') }}
              </option>
              <option v-for="g in plaza.groups.value" :key="g.id" :value="g.id">
                {{ g.name }} (×{{ g.rate_multiplier }})
              </option>
            </select>
          </div>
        </div>

        <div class="flex flex-shrink-0 items-center gap-2">
          <!-- View toggle -->
          <div class="inline-flex overflow-hidden rounded-lg border border-gray-200 dark:border-dark-700">
            <button
              type="button"
              class="px-3 py-1.5 text-sm transition-colors"
              :class="
                plaza.viewMode.value === 'card'
                  ? 'bg-primary-500 text-white'
                  : 'bg-white text-gray-600 hover:bg-gray-50 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
              "
              :title="t('modelsPlaza.viewCard')"
              @click="setView('card')"
            >
              <Icon name="grid" size="sm" />
            </button>
            <button
              type="button"
              class="px-3 py-1.5 text-sm transition-colors"
              :class="
                plaza.viewMode.value === 'table'
                  ? 'bg-primary-500 text-white'
                  : 'bg-white text-gray-600 hover:bg-gray-50 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
              "
              :title="t('modelsPlaza.viewTable')"
              @click="setView('table')"
            >
              <Icon name="menu" size="sm" />
            </button>
          </div>

          <!-- Refresh -->
          <button
            class="btn btn-secondary"
            :disabled="plaza.loading.value"
            :title="t('modelsPlaza.refresh')"
            @click="reload"
          >
            <Icon name="refresh" size="md" :class="plaza.loading.value ? 'animate-spin' : ''" />
          </button>
        </div>
      </div>

      <!-- Content -->
      <ModelPlazaGrid
        v-if="plaza.viewMode.value === 'card'"
        :rows="plaza.rows.value"
        :loading="plaza.loading.value"
        :empty-title="t('modelsPlaza.empty')"
        :empty-description="t('modelsPlaza.description')"
      />
      <ModelPlazaTable
        v-else
        :rows="plaza.rows.value"
        :loading="plaza.loading.value"
        :empty-label="t('modelsPlaza.empty')"
      />
    </div>
  </component>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'
import ModelPlazaGrid from '@/components/plaza/ModelPlazaGrid.vue'
import ModelPlazaTable from '@/components/plaza/ModelPlazaTable.vue'
import { useModelsPlaza, type PlazaViewMode } from '@/composables/useModelsPlaza'
import { useAuthStore } from '@/stores/auth'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

// 未登录时用轻量匿名外壳（无侧边栏/顶栏），登录后用完整 AppLayout。
const AnonShell = defineComponent({
  name: 'ModelsPlazaAnonShell',
  setup(_, { slots }) {
    return () =>
      h('div', { class: 'relative min-h-screen bg-gray-50 dark:bg-dark-950' }, [
        h('div', {
          class:
            'pointer-events-none fixed inset-0 bg-gradient-to-br from-gray-50 via-primary-50/30 to-gray-100 dark:from-dark-950 dark:via-dark-900 dark:to-dark-950',
        }),
        h('main', { class: 'relative z-10' }, slots.default?.()),
      ])
  },
})

const isAuthenticated = computed(() => authStore.isAuthenticated)
const layoutComponent = computed(() => (isAuthenticated.value ? AppLayout : AnonShell))

// 视图模式与 URL ?view= 同步。
function normalizeView(v: unknown): PlazaViewMode {
  return v === 'table' ? 'table' : 'card'
}

const plaza = useModelsPlaza()
plaza.viewMode.value = normalizeView(route.query.view)

function setView(mode: PlazaViewMode) {
  plaza.viewMode.value = mode
}

// viewMode → URL（replace，避免污染历史栈）
watch(plaza.viewMode, (mode) => {
  if (route.query.view === mode) return
  router.replace({ query: { ...route.query, view: mode } })
})

// URL → viewMode（浏览器前进/后退时同步）
watch(
  () => route.query.view,
  (v) => {
    const next = normalizeView(v)
    if (next !== plaza.viewMode.value) plaza.viewMode.value = next
  },
)

// el-select v-model 需要可写 ref：桥接到 composable 的 selectedGroupId。
const selectedGroupModel = computed<number | null>({
  get: () => plaza.selectedGroupId.value,
  set: (v) => {
    plaza.selectedGroupId.value = v
  },
})

function reload() {
  void plaza.load()
}

onMounted(() => {
  void plaza.load()
})
</script>
