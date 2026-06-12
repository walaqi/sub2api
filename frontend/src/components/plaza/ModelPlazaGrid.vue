<template>
  <div>
    <!-- Loading skeleton -->
    <div
      v-if="loading && rows.length === 0"
      class="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4"
    >
      <div
        v-for="i in 8"
        :key="i"
        class="min-h-[320px] animate-pulse rounded-2xl border border-gray-200/80 bg-white/70 p-5 dark:border-dark-700/70 dark:bg-dark-800/60"
      >
        <div class="flex items-start gap-3">
          <div class="h-9 w-9 rounded-xl bg-gray-200 dark:bg-dark-700"></div>
          <div class="flex-1 space-y-2">
            <div class="h-4 w-2/3 rounded bg-gray-200 dark:bg-dark-700"></div>
            <div class="h-3 w-1/3 rounded bg-gray-200 dark:bg-dark-700"></div>
          </div>
        </div>
        <div class="mt-4 grid grid-cols-2 gap-3">
          <div class="h-24 rounded-xl bg-gray-100 dark:bg-dark-900/40"></div>
          <div class="h-24 rounded-xl bg-gray-100 dark:bg-dark-900/40"></div>
        </div>
      </div>
    </div>

    <EmptyState
      v-else-if="rows.length === 0"
      :title="emptyTitle"
      :description="emptyDescription"
    />

    <div
      v-else
      class="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4"
    >
      <ModelPlazaCard
        v-for="row in rows"
        :key="`${row.model.platform}-${row.model.name}`"
        :row="row"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import EmptyState from '@/components/common/EmptyState.vue'
import ModelPlazaCard from './ModelPlazaCard.vue'
import type { PlazaModelRow } from '@/composables/useModelsPlaza'

defineProps<{
  rows: PlazaModelRow[]
  loading: boolean
  emptyTitle: string
  emptyDescription: string
}>()
</script>
