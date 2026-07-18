/**
 * Models Plaza API
 *
 * Public, unauthenticated endpoint backing the 模型广场 / Model Plaza page.
 * The backend gates the data behind a feature flag (models_plaza_enabled);
 * when disabled it returns an empty catalog rather than an error.
 *
 * Pricing model (see backend ModelCatalogService):
 *  - Standard prices are pre-multiplied by the balance recharge multiplier.
 *  - Recharge price is computed client-side: standard × selected group's rate_multiplier.
 */

import { apiClient } from './client'

/** A public (non-exclusive) group selectable in the plaza group picker. */
export interface CatalogGroup {
  id: number
  name: string
  platform: string
  rate_multiplier: number
}

/** A single model entry, aggregated by platform + model name. */
export interface CatalogModel {
  name: string
  platform: string
  context_length: number
  max_output_tokens: number
  capabilities: string[]
  input_modalities: string[]
  output_modalities: string[]
  billing_mode: string

  standard_input_price: number | null
  standard_output_price: number | null
  standard_cache_read_price: number | null
  standard_cache_write_price: number | null
  standard_per_request_price: number | null
  standard_image_output_price: number | null

  /** Public group IDs (same platform) that provide this model. */
  group_ids: number[]
}

/** The full plaza catalog payload. */
export interface ModelCatalog {
  models: CatalogModel[]
  groups: CatalogGroup[]
  recharge_multiplier: number
  /** Admin-configured default group (models_plaza_default_group_id) when it is public; 0 when unset/stale — frontend falls back to groups[0]. */
  default_group_id: number
}

/**
 * Fetch the model plaza catalog. Public endpoint; no auth required.
 */
export async function getCatalog(options?: { signal?: AbortSignal }): Promise<ModelCatalog> {
  const { data } = await apiClient.get<ModelCatalog>('/models-plaza/catalog', {
    signal: options?.signal,
  })
  return data
}

export const modelsPlazaAPI = {
  getCatalog,
}
