/**
 * Admin Multi-account Abuse Detection API endpoints.
 * Suspect-group listing, bulk user disable, throttle settings, and the live
 * auto-throttle list.
 */

import { apiClient } from '../client'

export type AbuseDimension = 'device' | 'fingerprint' | 'ip'

export interface SuspectGroupMember {
  user_id: number
  email: string
  username: string
  requests: number
  first_seen: string
  last_seen: string
}

export interface SuspectGroup {
  dimension: AbuseDimension
  value: string
  user_count: number
  total_requests: number
  first_seen: string
  last_seen: string
  members: SuspectGroupMember[]
}

export interface ListSuspectsParams {
  window_hours?: number
  min_users?: number
  dimensions?: string // comma-separated: "device,fingerprint,ip"
}

export interface ListSuspectsResponse {
  window_hours: number
  min_users: number
  groups: SuspectGroup[]
}

export interface BulkUpdateUsersRequest {
  user_ids: number[]
  status: 'active' | 'disabled'
}

export interface BulkUpdateUsersResult {
  success: number
  failed: number
  skipped: number
  success_ids: number[]
  failed_ids: number[]
  skipped_ids: number[]
}

export interface SuspectThrottleSettings {
  enabled: boolean
  rate_percent: number
  floor_rpm: number
  min_users: number
  window_hours: number
  interval_min: number
  ttl_minutes: number
}

export interface ThrottledEntry {
  user_id: number
  dimensions: string[]
  marked_at: string
  ttl_seconds: number
}

export interface ListThrottledResponse {
  count: number
  entries: ThrottledEntry[]
}

export interface ClearThrottledResponse {
  cleared: number
}

export async function listSuspects(params: ListSuspectsParams = {}): Promise<ListSuspectsResponse> {
  const { data } = await apiClient.get<ListSuspectsResponse>('/admin/abuse/suspects', { params })
  return data
}

export async function bulkUpdateUsers(
  payload: BulkUpdateUsersRequest
): Promise<BulkUpdateUsersResult> {
  const { data } = await apiClient.post<BulkUpdateUsersResult>('/admin/abuse/users/bulk-update', payload)
  return data
}

export async function getThrottleSettings(): Promise<SuspectThrottleSettings> {
  const { data } = await apiClient.get<SuspectThrottleSettings>('/admin/abuse/throttle-settings')
  return data
}

export async function updateThrottleSettings(
  payload: SuspectThrottleSettings
): Promise<SuspectThrottleSettings> {
  const { data } = await apiClient.put<SuspectThrottleSettings>('/admin/abuse/throttle-settings', payload)
  return data
}

export async function listThrottled(): Promise<ListThrottledResponse> {
  const { data } = await apiClient.get<ListThrottledResponse>('/admin/abuse/throttled')
  return data
}

export async function clearThrottled(): Promise<ClearThrottledResponse> {
  const { data } = await apiClient.delete<ClearThrottledResponse>('/admin/abuse/throttled')
  return data
}

export const abuseAPI = {
  listSuspects,
  bulkUpdateUsers,
  getThrottleSettings,
  updateThrottleSettings,
  listThrottled,
  clearThrottled,
}

export default abuseAPI
