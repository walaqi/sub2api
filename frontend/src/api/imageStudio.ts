/**
 * Image Studio API
 *
 * Backs the 图片工作台 / Image Studio entry. The母系统 (this app) mints a
 * short-lived RS256 entry ticket; the user is then full-page redirected to the
 * same-origin image-studio sub-app at `/image-studio/?ticket=<jwt>`, which
 * verifies the ticket and exchanges it for its own session cookie.
 *
 * Gated by the `image_studio_enabled` public flag (config switch). When the
 * backend has the feature disabled, the ticket endpoint returns 404.
 */

import { apiClient } from './client'

/** Result of minting an entry ticket. */
export interface ImageStudioTicket {
  /** Signed RS256 JWT, carried to image-studio via the URL query. */
  ticket: string
  /** Unix seconds when the ticket expires (short-lived, ~60s). */
  expires_at: number
}

/**
 * Mint a one-time entry ticket for the current authenticated user.
 * @returns the ticket + its expiry
 */
export async function getTicket(): Promise<ImageStudioTicket> {
  const { data } = await apiClient.get<ImageStudioTicket>('/image-studio/ticket')
  return data
}

export const imageStudioAPI = {
  getTicket,
}

export default imageStudioAPI
