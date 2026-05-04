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

  it('authClient.createRequestClient shares session truth and refresh behavior across base URLs', async () => {
    const storage = new MemoryStorage()
    const { authClient, sessionManager } = createClients({
      auth: { url: 'http://localhost:8080/auth' },
      storage: storage as any,
      storageKey: 'test.auth.token',
      persistSession: true,
      autoRefreshToken: true,
      debug: false
    })

    const authMock = new MockAdapter((authClient as any).api.client)
    const hostRequest = authClient!.createRequestClient({ baseURL: 'http://localhost:7001' })
    const hostMock = new MockAdapter((hostRequest as any).client)

    await sessionManager.setSession({
      access_token: 'expired-access-token',
      refresh_token: 'refresh-token-1',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      user: { id: '1', email: 'test@example.com' }
    } as any)

    authMock.onPost('http://localhost:8080/auth/token?grant_type=refresh_token').reply(200, {
      data: {
        session: {
          access_token: 'fresh-access-token',
          refresh_token: 'refresh-token-2',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })

    hostMock.onGet('/api/v1/workspaces').replyOnce(401, {
      error: {
        message: 'Token expired',
        key: 'auth.unauthorized',
        type: 'user'
      }
    })
    hostMock.onGet('/api/v1/workspaces').reply((config) => {
      expect(config.baseURL).toBe('http://localhost:7001')
      expect(config.headers?.Authorization).toBe('Bearer fresh-access-token')
      return [200, { data: { items: [] } }]
    })

    const response = await hostRequest.get('/api/v1/workspaces')

    expect(response.status).toBe(200)
    await expect(authClient!.getSession()).resolves.toMatchObject({
      access_token: 'fresh-access-token',
      refresh_token: 'refresh-token-2'
    })

    hostMock.restore()
    authMock.restore()
  })

  it('authClient.createRequestClient reuses the same client for the same baseURL', async () => {
    const { authClient } = createClients({
      auth: { url: 'http://localhost:8080/auth' },
      persistSession: false,
      autoRefreshToken: true,
      debug: false
    })

    const clientA = authClient!.createRequestClient({ baseURL: 'http://localhost:7001' })
    const clientB = authClient!.createRequestClient({ baseURL: 'http://localhost:7001' })

    expect(clientA).toBe(clientB)
  })
})
