import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import ProfileInfoCard from '@/components/user/profile/ProfileInfoCard.vue'
import type { User, UserGiftItem } from '@/types'

vi.mock('vue-router', () => ({
  useRoute: () => ({
    fullPath: '/profile'
  })
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    user: null
  })
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn()
  })
}))

vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string, params?: Record<string, string>) => {
        if (key === 'profile.accountBalance') return 'Account Balance'
        if (key === 'profile.concurrencyLimit') return 'Concurrency Limit'
        if (key === 'profile.memberSince') return 'Member Since'
        if (key === 'profile.administrator') return 'Administrator'
        if (key === 'profile.user') return 'User'
        if (key === 'profile.authBindings.providers.email') return 'Email'
        if (key === 'profile.authBindings.providers.linuxdo') return 'LinuxDo'
        if (key === 'profile.authBindings.providers.wechat') return 'WeChat'
        if (key === 'profile.authBindings.providers.oidc') return params?.providerName || 'OIDC'
        if (key === 'profile.authBindings.source.avatar') {
          return `Avatar synced from ${params?.providerName || 'provider'}`
        }
        if (key === 'profile.authBindings.source.username') {
          return `Username synced from ${params?.providerName || 'provider'}`
        }
        if (key === 'profile.giftBalance') return 'Gift'
        if (key === 'profile.giftExpiringSoonShort') return 'expiring soon'
        if (key === 'profile.giftExpiringAt') return `expiring at ${params?.date || ''}`
        if (key === 'profile.giftModePriority') return 'priority'
        if (key === 'profile.giftModeRatio') return 'ratio'
        return key
      }
    })
  }
})

function createUser(overrides: Partial<User> = {}): User {
  return {
    id: 5,
    username: 'alice',
    email: 'alice@example.com',
    avatar_url: null,
    role: 'user',
    balance: 10,
    concurrency: 2,
    status: 'active',
    allowed_groups: null,
    balance_notify_enabled: true,
    balance_notify_threshold: null,
    balance_notify_extra_emails: [],
    created_at: '2026-04-20T00:00:00Z',
    updated_at: '2026-04-20T00:00:00Z',
    ...overrides
  }
}

describe('ProfileInfoCard', () => {
  it('renders basic account information inside the new overview shell', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser()
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.text()).toContain('alice@example.com')
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).toContain('User')
    expect(wrapper.get('[data-testid="profile-basics-panel"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="profile-auth-bindings-panel"]').exists()).toBe(true)
  })

  it('renders each held gift as its own line with mode, amount and expiry', () => {
    const gifts: UserGiftItem[] = [
      // priority, expiring soon
      { remaining: 49.4, deduction_mode: 'priority', expiring_soon: true },
      // ratio 1:1, expiring soon
      { remaining: 49.4, deduction_mode: 'ratio', ratio_recharge: 1, expiring_soon: true },
      // ratio 1:1, fixed expiry date (2026-07-01 local)
      {
        remaining: 49.4,
        deduction_mode: 'ratio',
        ratio_recharge: 1,
        expires_at_unix_ms: new Date(2026, 6, 1, 12, 0, 0).getTime(),
        expiring_soon: false
      },
      // priority, no expiry
      { remaining: 49.4, deduction_mode: 'priority', expiring_soon: false }
    ]
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser({ gift_balance: 197.6 }),
        gifts
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    const list = wrapper.get('[data-testid="profile-overview-gift-list"]')
    const lines = list.findAll('li').map((li) => li.text())
    expect(lines).toHaveLength(4)
    expect(lines[0]).toBe('Gift $49.40 ($49.40 expiring soon) - priority')
    expect(lines[1]).toBe('Gift $49.40 ($49.40 expiring soon) - ratio 1:1')
    expect(lines[2]).toBe('Gift $49.40 ($49.40 expiring at 07/01/2026) - ratio 1:1')
    expect(lines[3]).toBe('Gift $49.40 - priority')
  })

  it('does not render the gift list when the user holds no gifts', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser(),
        gifts: []
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.find('[data-testid="profile-overview-gift-list"]').exists()).toBe(false)
  })

  it('renders third-party source hints from profile sources', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser({
          avatar_url: 'https://cdn.example.com/linuxdo.png',
          profile_sources: {
            avatar: { provider: 'linuxdo', source: 'linuxdo' },
            username: { provider: 'linuxdo', source: 'linuxdo' }
          }
        })
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.text()).toContain('Avatar synced from LinuxDo')
    expect(wrapper.text()).toContain('Username synced from LinuxDo')
  })

  it('uses the configured OIDC provider name in source hints', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser({
          profile_sources: {
            username: { provider: 'oidc', source: 'oidc' }
          }
        }),
        oidcProviderName: 'ExampleID'
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.text()).toContain('Username synced from ExampleID')
  })

  it('does not display synthetic oauth-only emails as a real bound email', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser({
          email: 'legacy-user@oidc-connect.invalid',
          email_bound: false,
          auth_bindings: {
            email: { bound: false }
          }
        })
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.text()).not.toContain('legacy-user@oidc-connect.invalid')
  })

  it('does not display synthetic oauth-only emails when only legacy identity bindings mark email as unbound', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser({
          email: 'legacy-user@wechat-connect.invalid',
          identity_bindings: {
            email: { bound: false }
          }
        })
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.text()).not.toContain('legacy-user@wechat-connect.invalid')
  })

  it('renders the approved overview hero and two-column content shell', () => {
    const wrapper = mount(ProfileInfoCard, {
      props: {
        user: createUser()
      },
      global: {
        stubs: {
          Icon: true
        }
      }
    })

    expect(wrapper.get('[data-testid="profile-overview-hero"]').text()).toContain('alice@example.com')
    expect(wrapper.get('[data-testid="profile-overview-metric-balance"]').text()).toContain('Account Balance')
    expect(wrapper.get('[data-testid="profile-overview-metric-concurrency"]').text()).toContain('Concurrency Limit')
    expect(wrapper.get('[data-testid="profile-overview-metric-member-since"]').text()).toContain('Member Since')
    expect(wrapper.find('[data-testid="profile-info-summary-grid"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="profile-main-column"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="profile-side-column"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="profile-basics-panel"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="profile-auth-bindings-panel"]').exists()).toBe(true)
  })
})
