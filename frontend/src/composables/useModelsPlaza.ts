/**
 * useModelsPlaza — 模型广场数据与展示态组合式函数。
 *
 * 职责：
 *  - 拉取 catalog（公开接口，1 分钟后端 TTL）
 *  - 维护分组选择、平台过滤、搜索、视图模式（card/table）
 *  - 计算每个模型的标准价 / 充值价（充值价 = 标准价 × 所选分组 rate_multiplier）
 *
 * 设计为「视图无关」：可被独立的模型广场页面或首页嵌入复用，UI 组件只消费
 * 返回的响应式状态与派生计算。
 */

import { computed, ref, watch, type Ref } from 'vue'
import {
  modelsPlazaAPI,
  type ModelCatalog,
  type CatalogModel,
  type CatalogGroup,
} from '@/api/modelsPlaza'

export type PlazaViewMode = 'card' | 'table'

/** 单个模型在「当前所选分组」下的展示行（含已算好的充值价）。 */
export interface PlazaModelRow {
  model: CatalogModel
  /** 标准价（已含余额充值倍率），按 token 计；null 表示该项未配置。 */
  standard: PlazaPriceSet
  /** 充值价 = 标准价 × 所选分组 rate_multiplier。无分组时与标准价相等。 */
  recharge: PlazaPriceSet
}

export interface PlazaPriceSet {
  input: number | null
  output: number | null
  cacheRead: number | null
  cacheWrite: number | null
  perRequest: number | null
  imageOutput: number | null
}

function scale(value: number | null, mult: number): number | null {
  if (value == null) return null
  return value * mult
}

function buildPriceSet(model: CatalogModel, mult: number): PlazaPriceSet {
  return {
    input: scale(model.standard_input_price, mult),
    output: scale(model.standard_output_price, mult),
    cacheRead: scale(model.standard_cache_read_price, mult),
    cacheWrite: scale(model.standard_cache_write_price, mult),
    perRequest: scale(model.standard_per_request_price, mult),
    imageOutput: scale(model.standard_image_output_price, mult),
  }
}

export interface UseModelsPlazaOptions {
  /** 视图模式的双向绑定源（页面用 URL query 同步，首页可传本地 ref）。 */
  viewMode?: Ref<PlazaViewMode>
}

export function useModelsPlaza(options: UseModelsPlazaOptions = {}) {
  const catalog = ref<ModelCatalog | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  const search = ref('')
  const platformFilter = ref<string>('') // '' = 全部平台
  const selectedGroupId = ref<number | null>(null)
  const viewMode = options.viewMode ?? ref<PlazaViewMode>('card')

  const groups = computed<CatalogGroup[]>(() => catalog.value?.groups ?? [])

  /** 当前所选分组对象；null 表示未选（充值价 = 标准价）。 */
  const selectedGroup = computed<CatalogGroup | null>(() => {
    if (selectedGroupId.value == null) return null
    return groups.value.find((g) => g.id === selectedGroupId.value) ?? null
  })

  /** 充值价相对标准价的倍率：所选分组的 rate_multiplier，未选则 1。 */
  const rechargeRate = computed(() => selectedGroup.value?.rate_multiplier ?? 1)

  /** 目录中出现的平台集合（用于平台过滤下拉），按字母序。 */
  const platforms = computed<string[]>(() => {
    const set = new Set<string>()
    for (const m of catalog.value?.models ?? []) set.add(m.platform)
    return Array.from(set).sort()
  })

  /** 过滤后的模型行（含标准价 + 充值价），应用搜索与平台过滤。 */
  const rows = computed<PlazaModelRow[]>(() => {
    const q = search.value.trim().toLowerCase()
    const pf = platformFilter.value
    const mult = rechargeRate.value
    const out: PlazaModelRow[] = []
    for (const model of catalog.value?.models ?? []) {
      if (pf && model.platform !== pf) continue
      if (q && !model.name.toLowerCase().includes(q) && !model.platform.toLowerCase().includes(q)) {
        continue
      }
      out.push({
        model,
        standard: buildPriceSet(model, 1),
        recharge: buildPriceSet(model, mult),
      })
    }
    return out
  })

  async function load(signal?: AbortSignal) {
    loading.value = true
    error.value = null
    try {
      const data = await modelsPlazaAPI.getCatalog({ signal })
      catalog.value = data
      // 初始化分组选择：优先后端给的 default_group_id，其次第一个公开分组。
      if (selectedGroupId.value == null) {
        if (data.default_group_id && data.groups.some((g) => g.id === data.default_group_id)) {
          selectedGroupId.value = data.default_group_id
        } else if (data.groups.length > 0) {
          selectedGroupId.value = data.groups[0].id
        }
      }
    } catch (e: unknown) {
      // 取消请求不算错误
      if (e instanceof Error && e.name === 'CanceledError') return
      error.value = e instanceof Error ? e.message : String(e)
    } finally {
      loading.value = false
    }
  }

  // 当 catalog 刷新后所选分组消失时，回退到第一个可用分组。
  watch(groups, (gs) => {
    if (selectedGroupId.value != null && !gs.some((g) => g.id === selectedGroupId.value)) {
      selectedGroupId.value = gs.length > 0 ? gs[0].id : null
    }
  })

  return {
    // 原始/状态
    catalog,
    loading,
    error,
    // 过滤态
    search,
    platformFilter,
    selectedGroupId,
    viewMode,
    // 派生
    groups,
    selectedGroup,
    rechargeRate,
    platforms,
    rows,
    // 动作
    load,
  }
}
