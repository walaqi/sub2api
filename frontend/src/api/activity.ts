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

export interface ActivitySignup {
  id: number
  activity_id: number
  user_id: number
  username: string
  receive_email: string
  created_at: string
  updated_at: string
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
