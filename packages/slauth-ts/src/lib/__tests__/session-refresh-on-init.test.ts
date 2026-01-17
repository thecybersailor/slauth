import { AuthApi } from '../../AuthApi'
import { MemoryStorage } from '../storage'
import MockAdapter from 'axios-mock-adapter'
import axios from 'axios'

describe('Session Auto-Refresh on Initialization', () => {
  let authClient: AuthApi
  let mockStorage: MemoryStorage
  let mockAdapter: MockAdapter
  let refreshCallCount = 0

  beforeEach(() => {
    refreshCallCount = 0
    mockStorage = new MemoryStorage()
  })

  afterEach(() => {
    if (mockAdapter) {
      mockAdapter.restore()
    }
    jest.clearAllMocks()
  })

  it('should auto-refresh expired session on initialization', async () => {
    // Create expired session
    const expiredSession = {
      access_token: 'expired-token',
      refresh_token: 'valid-refresh-token',
      expires_at: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
      user: { id: '1', email: 'test@example.com' }
    }

    // Save expired session to storage
    mockStorage.setItem('test.auth.token', JSON.stringify(expiredSession))

    // Create auth client first to get the axios instance
    authClient = new AuthApi('http://localhost:8080/auth', {
      storage: mockStorage,
      storageKey: 'test.auth.token',
      autoRefreshToken: true,
      persistSession: true,
      debug: false
    })

    // Get the axios instance from the client
    const axiosInstance = (authClient as any).api.client
    mockAdapter = new MockAdapter(axiosInstance)

    // Mock the refresh endpoint
    mockAdapter.onPost('http://localhost:8080/auth/token?grant_type=refresh_token').reply(200, {
      data: {
        session: {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: { id: '1', email: 'test@example.com' }
        }
      }
    })

    // Wait for initialization to complete
    await new Promise(resolve => setTimeout(resolve, 200))

    // Verify that refresh was called
    expect(mockAdapter.history.post.length).toBeGreaterThan(0)
    const refreshRequest = mockAdapter.history.post.find(req => 
      req.url?.includes('/token?grant_type=refresh_token')
    )
    expect(refreshRequest).toBeDefined()
    expect(JSON.parse(refreshRequest!.data)).toMatchObject({
      refresh_token: 'valid-refresh-token'
    })

    // Verify that session was updated with new token
    const currentSession = authClient.getSession()
    expect(currentSession?.access_token).toBe('new-access-token')
  })

  it('should clear session if auto-refresh is disabled', async () => {
    // Create expired session
    const expiredSession = {
      access_token: 'expired-token',
      refresh_token: 'valid-refresh-token',
      expires_at: Math.floor(Date.now() / 1000) - 3600,
      user: { id: '1', email: 'test@example.com' }
    }

    mockStorage.setItem('test.auth.token', JSON.stringify(expiredSession))

    // Create auth client with auto-refresh disabled
    authClient = new AuthApi('http://localhost:8080/auth', {
      storage: mockStorage,
      storageKey: 'test.auth.token',
      autoRefreshToken: false,
      persistSession: true,
      debug: false
    })

    // Wait for initialization
    await new Promise(resolve => setTimeout(resolve, 100))

    // Verify that session was cleared
    const currentSession = authClient.getSession()
    expect(currentSession).toBeNull()
  })

  it('should use valid session without refresh', async () => {
    // Create valid session
    const validSession = {
      access_token: 'valid-token',
      refresh_token: 'valid-refresh-token',
      expires_at: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
      user: { id: '1', email: 'test@example.com' }
    }

    mockStorage.setItem('test.auth.token', JSON.stringify(validSession))

    // Create auth client
    authClient = new AuthApi('http://localhost:8080/auth', {
      storage: mockStorage,
      storageKey: 'test.auth.token',
      autoRefreshToken: true,
      persistSession: true,
      debug: false
    })

    // Get the axios instance from the client
    const axiosInstance = (authClient as any).api.client
    mockAdapter = new MockAdapter(axiosInstance)

    // Wait for initialization
    await new Promise(resolve => setTimeout(resolve, 100))

    // Verify that refresh was NOT called
    expect(mockAdapter.history.post.length).toBe(0)

    // Verify that session is still valid
    const currentSession = authClient.getSession()
    expect(currentSession?.access_token).toBe('valid-token')
  })
})

