import { apiClient } from './client'

export interface ActivityEvent {
  id: number
  name: string
  description: string
  status?: string
  starts_at: string
  ends_at?: string | null
  signed_up: boolean
  receive_email?: string | null
}

// Key-grant outcome codes returned with a signup (mirrors backend KeyStatus*).
export type ActivityKeyStatus =
  | 'reserved'
  | 'already_claimed'
  | 'no_key_available'
  | 'disabled'
  | 'referral_invitee'

export interface ActivityReservation {
  reservation_id: string
  masked_key: string
  expires_at_unix_ms: number
  remaining_quota: number
}

export interface ActivitySignup {
  id: number
  activity_id: number
  user_id: number
  username: string
  receive_email: string
  created_at: string
  updated_at: string
  // Key-grant outcome. When key_status === 'reserved', `reservation` is set and
  // the client should redirect to /bind-key?reservation=<id> to claim the gift.
  key_status?: ActivityKeyStatus
  reservation?: ActivityReservation | null
}

export async function listActiveActivities(): Promise<ActivityEvent[]> {
  const { data } = await apiClient.get<ActivityEvent[]>('/activity/events/active')
  return data ?? []
}

export async function signupActivity(activityId: number, receiveEmail: string): Promise<ActivitySignup> {
  const { data } = await apiClient.post<ActivitySignup>(`/activity/events/${activityId}/signups`, {
    receive_email: receiveEmail
  })
  return data
}

export const activityAPI = {
  listActiveActivities,
  signupActivity
}
