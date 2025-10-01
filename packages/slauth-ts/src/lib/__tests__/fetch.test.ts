import { HttpClient } from '../fetch'
import axios from 'axios'
import MockAdapter from 'axios-mock-adapter'

describe('HttpClient - Callback Mechanisms', () => {
  let client: HttpClient
  let mock: MockAdapter
  let onUnauthorizedMock: jest.Mock
  let onSessionRefreshedMock: jest.Mock
  let onAuthErrorMock: jest.Mock

  beforeEach(() => {
    onUnauthorizedMock = jest.fn()
    onSessionRefreshedMock = jest.fn()
    onAuthErrorMock = jest.fn()

    client = new HttpClient({
      baseURL: 'http://localhost:3000',
      onUnauthorized: onUnauthorizedMock,
      onSessionRefreshed: onSessionRefreshedMock,
      onAuthError: onAuthErrorMock,
      debug: false
    })

    // Create mock adapter after client initialization
    mock = new MockAdapter((client as any).client)
  })

  afterEach(() => {
    mock.restore()
    jest.clearAllMocks()
  })

  describe('onUnauthorized callback', () => {
    it('should trigger onUnauthorized when receiving 401 status code', async () => {
      mock.onGet('/test').reply(401, {
        error: {
          message: 'Unauthorized access',
          key: 'auth.unauthorized',
          type: 'user'
        }
      })

      const { data, error } = await client.get('/test')

      expect(data).toBeNull()
      expect(error).toBeTruthy()
      expect(onUnauthorizedMock).toHaveBeenCalledTimes(1)
      expect(onAuthErrorMock).toHaveBeenCalledTimes(1)
    })

    it('should trigger onUnauthorized for 401 on POST requests', async () => {
      mock.onPost('/protected').reply(401, {
        error: {
          message: 'Authorization required',
          key: 'auth.authorization_required',
          type: 'user'
        }
      })

      const { data, error } = await client.post('/protected', {})

      expect(data).toBeNull()
      expect(error).toBeTruthy()
      expect(onUnauthorizedMock).toHaveBeenCalledTimes(1)
      expect(onAuthErrorMock).toHaveBeenCalledTimes(1)
    })
  })

  describe('onUnauthorized without auto refresh', () => {
    it('should trigger onUnauthorized for any 401 error when auto refresh is disabled', async () => {
      mock.onGet('/user').reply(401, {
        error: {
          message: 'Session has expired',
          key: 'auth.session_expired',
          type: 'user'
        }
      })

      const { data, error } = await client.get('/user')

      expect(data).toBeNull()
      expect(error).toBeTruthy()
      expect(onUnauthorizedMock).toHaveBeenCalledTimes(1)
      expect(onAuthErrorMock).toHaveBeenCalledTimes(1)
    })
  })

  describe('onAuthError callback', () => {
    it('should trigger onAuthError for any auth error', async () => {
      mock.onPost('/login').reply(400, {
        error: {
          message: 'Invalid credentials',
          key: 'auth.invalid_credentials',
          type: 'user'
        }
      })

      const { data, error } = await client.post('/login', {})

      expect(data).toBeNull()
      expect(error).toBeTruthy()
      expect(onAuthErrorMock).toHaveBeenCalledTimes(1)
      expect(onAuthErrorMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid credentials',
          key: 'auth.invalid_credentials'
        })
      )
    })

    it('should trigger onAuthError but not onUnauthorized for network errors', async () => {
      mock.onGet('/test').networkError()

      const { data, error } = await client.get('/test')

      expect(data).toBeNull()
      expect(error).toBeTruthy()
      expect(onUnauthorizedMock).not.toHaveBeenCalled()
      expect(onAuthErrorMock).toHaveBeenCalledTimes(1)
    })
  })

  describe('setAuth method', () => {
    it('should set authorization header when token is provided', async () => {
      client.setAuth('test-token')

      mock.onGet('/user').reply((config) => {
        expect(config.headers?.Authorization).toBe('Bearer test-token')
        return [200, { data: { user: { id: '1' } } }]
      })

      await client.get('/user')
    })

    it('should remove authorization header when token is null', async () => {
      client.setAuth('test-token')
      client.setAuth(null)

      mock.onGet('/user').reply((config) => {
        expect(config.headers?.Authorization).toBeUndefined()
        return [200, { data: {} }]
      })

      await client.get('/user')
    })
  })
})

describe('Auto Token Refresh', () => {
  let client: HttpClient
  let mock: MockAdapter
  let refreshCallCount = 0
  let onUnauthorizedMock: jest.Mock
  let onSessionRefreshedMock: jest.Mock

  beforeEach(() => {
    refreshCallCount = 0
    onUnauthorizedMock = jest.fn()
    onSessionRefreshedMock = jest.fn()
    
    const refreshTokenFn = async (): Promise<boolean> => {
      refreshCallCount++
      // Simulate successful refresh
      client.setAuth('new-access-token')
      onSessionRefreshedMock({ access_token: 'new-access-token' })
      return true
    }

    client = new HttpClient({
      baseURL: 'http://localhost:3000',
      autoRefreshToken: true,
      refreshTokenFn,
      onUnauthorized: onUnauthorizedMock,
      onSessionRefreshed: onSessionRefreshedMock,
      debug: false
    })

    mock = new MockAdapter((client as any).client)
  })

  afterEach(() => {
    mock.restore()
    jest.clearAllMocks()
  })

  it('should auto refresh token on 401 and retry request', async () => {
    // First request fails with 401
    mock.onGet('/user').replyOnce(401, {
      error: {
        message: 'Token expired',
        key: 'auth.unauthorized',
        type: 'user'
      }
    })

    // After refresh, request should succeed
    mock.onGet('/user').reply(200, {
      data: { user: { id: '1', email: 'test@example.com' } }
    })

    const { data, error } = await client.get('/user')

    expect(refreshCallCount).toBe(1)
    expect(onSessionRefreshedMock).toHaveBeenCalledTimes(1)
    expect(onUnauthorizedMock).not.toHaveBeenCalled()
    expect(data).toHaveProperty('user')
    expect(error).toBeNull()
  })

  it('should trigger onUnauthorized if refresh fails', async () => {
    const failingRefreshFn = async (): Promise<boolean> => {
      return false
    }

    const failClient = new HttpClient({
      baseURL: 'http://localhost:3000',
      autoRefreshToken: true,
      refreshTokenFn: failingRefreshFn,
      onUnauthorized: onUnauthorizedMock,
      debug: false
    })

    const failMock = new MockAdapter((failClient as any).client)

    failMock.onGet('/user').reply(401, {
      error: {
        message: 'Token expired',
        key: 'auth.unauthorized',
        type: 'user'
      }
    })

    const { data, error } = await failClient.get('/user')

    expect(data).toBeNull()
    expect(error).toBeTruthy()
    expect(onUnauthorizedMock).toHaveBeenCalledTimes(1)

    failMock.restore()
  })
})

