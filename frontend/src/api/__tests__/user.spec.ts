import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const { get } = vi.hoisted(() => ({ get: vi.fn() }))

vi.mock('@/api/client', () => ({
  apiClient: { get },
}))

describe('user api referral status', () => {
  beforeEach(() => {
    get.mockReset()
  })

  it('fetches the referral status endpoint and returns the unwrapped payload', async () => {
    // 拦截器已解包信封，get 直接返回 { data: <ReferralStatus> }。
    const payload = {
      enabled: true,
      eligible: false,
      eligibility_grant_mode: 'recharge' as const,
      eligibility_recharge_min_amount: 100,
      eligibility_recharge_remaining: 60,
      aff_code: 'ABC123',
      invitee_amount: 10,
      inviter_amount: 10,
      spend_threshold: 10,
      invitee_reward: null,
      inviter_reward_quota_enabled: false,
      inviter_reward_quota: 0,
      inviter_progress: [],
    }
    get.mockResolvedValue({ data: payload })

    const { getReferralStatus } = await import('@/api/user')
    const result = await getReferralStatus()

    expect(get).toHaveBeenCalledWith('/user/referral/status')
    expect(result).toEqual(payload)
  })
})

describe('user api oauth binding urls', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.stubEnv('VITE_API_BASE_URL', 'https://api.example.com/api/v1')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('builds third-party bind urls against the bind start endpoint', async () => {
    const { buildOAuthBindingStartURL } = await import('@/api/user')

    expect(buildOAuthBindingStartURL('linuxdo', { redirectTo: '/settings/profile' })).toBe(
      'https://api.example.com/api/v1/auth/oauth/linuxdo/bind/start?redirect=%2Fsettings%2Fprofile&intent=bind_current_user'
    )
    expect(
      buildOAuthBindingStartURL('wechat', {
        redirectTo: '/settings/profile',
        wechatOAuthSettings: {
          wechat_oauth_open_enabled: true,
          wechat_oauth_mp_enabled: false,
          wechat_oauth_mobile_enabled: false
        }
      })
    ).toBe(
      'https://api.example.com/api/v1/auth/oauth/wechat/bind/start?redirect=%2Fsettings%2Fprofile&intent=bind_current_user&mode=open'
    )
  })
})
