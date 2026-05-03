import MockAdapter from 'axios-mock-adapter'
import { createClients } from '../../createClients'
import { MemoryStorage } from '../storage'

describe('SessionManager hard-cut contract', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  it('authClient.getSession waits for initialization and returns the refreshed session', async () => {
    const storage = new MemoryStorage()
    const storageKey = 'test.auth.token'
    storage.setItem(
      storageKey,
      JSON.stringify({
        access_token: 'expired-token',
        refresh_token: 'refresh-token-1',
        expires_at: Math.floor(Date.now() / 1000) - 3600,
        user: { id: '1', email: 'test@example.com' }
      })
    )

    const { authClient } = createClients({
      auth: { url: 'http://localhost:8080/auth' },
      storage: storage as any,
      storageKey,
      persistSession: true,
      autoRefreshToken: true,
      debug: false
    })

    const mockAdapter = new MockAdapter((authClient as any).api.client)
    mockAdapter.onPost('http://localhost:8080/auth/token?grant_type=refresh_token').reply(200, {
      data: {
        session: {
          access_token: 'new-access-token',
          refresh_token: 'refresh-token-2',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })

    await expect(authClient!.getSession()).resolves.toMatchObject({
      access_token: 'new-access-token',
      refresh_token: 'refresh-token-2'
    })

    mockAdapter.restore()
  })

  it('auth and admin clients share one session truth and admin exposes no setSession API', async () => {
    const storage = new MemoryStorage()
    const { authClient, adminClient } = createClients({
      auth: { url: 'http://localhost:8080/auth' },
      admin: { url: 'http://localhost:8080/admin' },
      storage: storage as any,
      storageKey: 'test.auth.token',
      persistSession: true,
      autoRefreshToken: true,
      debug: false
    })

    const authMock = new MockAdapter((authClient as any).api.client)
    authMock.onPost('http://localhost:8080/auth/token?grant_type=password').reply(200, {
      data: {
        session: {
          access_token: 'signed-in-token',
          refresh_token: 'signed-in-refresh-token',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        },
        user: { id: '1', email: 'test@example.com' }
      }
    })

    await authClient!.signInWithPassword({
      email: 'test@example.com',
      password: 'Password123!'
    })

    expect('setSession' in ((adminClient as unknown) as Record<string, unknown>)).toBe(false)
    await expect(adminClient!.getSession()).resolves.toMatchObject({
      access_token: 'signed-in-token'
    })

    authMock.restore()
  })
})
