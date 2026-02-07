import { AuthApi } from '../../AuthApi'
import { MemoryStorage } from '../storage'
import MockAdapter from 'axios-mock-adapter'

class FakeNavigatorLocks {
  private locked = false
  private waiters: Array<() => void> = []

  async request<T>(name: string, callback: () => Promise<T>): Promise<T> {
    void name
    if (this.locked) {
      await new Promise<void>((resolve) => this.waiters.push(resolve))
    }

    this.locked = true
    try {
      return await callback()
    } finally {
      this.locked = false
      const next = this.waiters.shift()
      next?.()
    }
  }
}

describe('Cross-tab refresh coordination (navigator.locks)', () => {
  let originalNavigator: any

  beforeEach(() => {
    originalNavigator = (globalThis as any).navigator
    ;(globalThis as any).navigator = {
      ...(originalNavigator || {}),
      locks: new FakeNavigatorLocks()
    }
  })

  afterEach(() => {
    ;(globalThis as any).navigator = originalNavigator
    jest.clearAllMocks()
  })

  it('should handle high concurrency with slow refresh and reuse refreshed session', async () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

    const storage = new MemoryStorage()
    const storageKey = 'test.auth.token'
    const baseURL = 'http://localhost:8080/auth'

    const session = {
      access_token: 'access-token-1',
      refresh_token: 'refresh-token-1',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      user: { id: '1', email: 'test@example.com' }
    }
    storage.setItem(storageKey, JSON.stringify(session))

    const authClientA = new AuthApi(baseURL, {
      storage,
      storageKey,
      autoRefreshToken: true,
      persistSession: true,
      crossTabRefreshLock: true,
      debug: false
    })
    const authClientB = new AuthApi(baseURL, {
      storage,
      storageKey,
      autoRefreshToken: true,
      persistSession: true,
      crossTabRefreshLock: true,
      debug: false
    })

    await new Promise((resolve) => setTimeout(resolve, 50))

    const axiosA = (authClientA as any).api.client
    const axiosB = (authClientB as any).api.client

    const mockA = new MockAdapter(axiosA)
    const mockB = new MockAdapter(axiosB)

    let aGetCalls = 0
    let bGetCalls = 0
    mockA.onGet('/user').reply(() => {
      aGetCalls++
      if (aGetCalls <= 5) {
        return [401, { error: { message: 'Token expired', key: 'auth.unauthorized', type: 'user' } }]
      }
      return [200, { data: { user: { id: '1' } } }]
    })
    mockB.onGet('/user').reply(() => {
      bGetCalls++
      if (bGetCalls <= 5) {
        return [401, { error: { message: 'Token expired', key: 'auth.unauthorized', type: 'user' } }]
      }
      return [200, { data: { user: { id: '1' } } }]
    })

    const refreshUrl = `${baseURL}/token?grant_type=refresh_token`
    mockA.onPost(refreshUrl).reply(async () => {
      await sleep(80) // simulate slow issuance / network delay
      return [
        200,
        {
          data: {
            session: {
              access_token: 'access-token-2',
              refresh_token: 'refresh-token-2',
              expires_at: Math.floor(Date.now() / 1000) + 3600,
              user: { id: '1', email: 'test@example.com' }
            }
          }
        }
      ]
    })
    mockB.onPost(refreshUrl).reply(200, {
      data: {
        session: {
          access_token: 'access-token-3',
          refresh_token: 'refresh-token-3',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })

    const requests = [
      ...Array.from({ length: 5 }, () => (authClientA as any).api.get('/user')),
      ...Array.from({ length: 5 }, () => (authClientB as any).api.get('/user'))
    ]

    const results = await Promise.all(requests)
    for (const r of results) {
      expect(r.error).toBeNull()
    }

    const isRefreshCall = (url: string | undefined) =>
      typeof url === 'string' && url.includes('/token?grant_type=refresh_token')

    const refreshCalls = mockA.history.post.filter((r) => isRefreshCall(r.url)).length +
      mockB.history.post.filter((r) => isRefreshCall(r.url)).length

    expect(refreshCalls).toBe(1)
    expect(authClientA.getSession()?.access_token).toBe('access-token-2')
    expect(authClientB.getSession()?.access_token).toBe('access-token-2')

    mockA.restore()
    mockB.restore()
  })

  it('should only perform one refresh across two AuthApi instances', async () => {
    const storage = new MemoryStorage()
    const storageKey = 'test.auth.token'
    const baseURL = 'http://localhost:8080/auth'

    const session = {
      access_token: 'access-token-1',
      refresh_token: 'refresh-token-1',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      user: { id: '1', email: 'test@example.com' }
    }
    storage.setItem(storageKey, JSON.stringify(session))

    const authClientA = new AuthApi(baseURL, {
      storage,
      storageKey,
      autoRefreshToken: true,
      persistSession: true,
      crossTabRefreshLock: true,
      debug: false
    })
    const authClientB = new AuthApi(baseURL, {
      storage,
      storageKey,
      autoRefreshToken: true,
      persistSession: true,
      crossTabRefreshLock: true,
      debug: false
    })

    // Wait for initializeSession() to load from storage
    await new Promise((resolve) => setTimeout(resolve, 50))

    const axiosA = (authClientA as any).api.client
    const axiosB = (authClientB as any).api.client

    const mockA = new MockAdapter(axiosA)
    const mockB = new MockAdapter(axiosB)

    mockA.onGet('/user').replyOnce(401, {
      error: { message: 'Token expired', key: 'auth.unauthorized', type: 'user' }
    })
    mockA.onGet('/user').reply(200, { data: { user: { id: '1' } } })

    mockB.onGet('/user').replyOnce(401, {
      error: { message: 'Token expired', key: 'auth.unauthorized', type: 'user' }
    })
    mockB.onGet('/user').reply(200, { data: { user: { id: '1' } } })

    const refreshUrl = `${baseURL}/token?grant_type=refresh_token`
    mockA.onPost(refreshUrl).reply(200, {
      data: {
        session: {
          access_token: 'access-token-2',
          refresh_token: 'refresh-token-2',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })
    mockB.onPost(refreshUrl).reply(200, {
      data: {
        session: {
          access_token: 'access-token-3',
          refresh_token: 'refresh-token-3',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })

    const [resA, resB] = await Promise.all([
      (authClientA as any).api.get('/user'),
      (authClientB as any).api.get('/user')
    ])

    expect(resA.error).toBeNull()
    expect(resB.error).toBeNull()

    const isRefreshCall = (url: string | undefined) =>
      typeof url === 'string' && url.includes('/token?grant_type=refresh_token')

    const refreshCalls = mockA.history.post.filter((r) => isRefreshCall(r.url)).length +
      mockB.history.post.filter((r) => isRefreshCall(r.url)).length

    expect(refreshCalls).toBe(1)

    mockA.restore()
    mockB.restore()
  })
})

describe('Refresh coordination fallback (no navigator.locks)', () => {
  let originalNavigator: any

  beforeEach(() => {
    originalNavigator = (globalThis as any).navigator
    // Remove Web Locks API to force Node/Bun fallback lock
    ;(globalThis as any).navigator = {
      ...(originalNavigator || {})
    }
    delete (globalThis as any).navigator.locks
  })

  afterEach(() => {
    ;(globalThis as any).navigator = originalNavigator
    jest.clearAllMocks()
  })

  it('should still only perform one refresh across two AuthApi instances', async () => {
    const storage = new MemoryStorage()
    const storageKey = 'test.auth.token'
    const baseURL = 'http://localhost:8080/auth'

    const session = {
      access_token: 'access-token-1',
      refresh_token: 'refresh-token-1',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      user: { id: '1', email: 'test@example.com' }
    }
    storage.setItem(storageKey, JSON.stringify(session))

    const authClientA = new AuthApi(baseURL, {
      storage,
      storageKey,
      autoRefreshToken: true,
      persistSession: true,
      crossTabRefreshLock: true,
      debug: false
    })
    const authClientB = new AuthApi(baseURL, {
      storage,
      storageKey,
      autoRefreshToken: true,
      persistSession: true,
      crossTabRefreshLock: true,
      debug: false
    })

    await new Promise((resolve) => setTimeout(resolve, 50))

    const axiosA = (authClientA as any).api.client
    const axiosB = (authClientB as any).api.client

    const mockA = new MockAdapter(axiosA)
    const mockB = new MockAdapter(axiosB)

    mockA.onGet('/user').replyOnce(401, {
      error: { message: 'Token expired', key: 'auth.unauthorized', type: 'user' }
    })
    mockA.onGet('/user').reply(200, { data: { user: { id: '1' } } })

    mockB.onGet('/user').replyOnce(401, {
      error: { message: 'Token expired', key: 'auth.unauthorized', type: 'user' }
    })
    mockB.onGet('/user').reply(200, { data: { user: { id: '1' } } })

    const refreshUrl = `${baseURL}/token?grant_type=refresh_token`
    mockA.onPost(refreshUrl).reply(200, {
      data: {
        session: {
          access_token: 'access-token-2',
          refresh_token: 'refresh-token-2',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })
    mockB.onPost(refreshUrl).reply(200, {
      data: {
        session: {
          access_token: 'access-token-3',
          refresh_token: 'refresh-token-3',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })

    const [resA, resB] = await Promise.all([
      (authClientA as any).api.get('/user'),
      (authClientB as any).api.get('/user')
    ])

    expect(resA.error).toBeNull()
    expect(resB.error).toBeNull()

    const isRefreshCall = (url: string | undefined) =>
      typeof url === 'string' && url.includes('/token?grant_type=refresh_token')

    const refreshCalls = mockA.history.post.filter((r) => isRefreshCall(r.url)).length +
      mockB.history.post.filter((r) => isRefreshCall(r.url)).length

    expect(refreshCalls).toBe(1)

    mockA.restore()
    mockB.restore()
  })
})
