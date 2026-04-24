import MockAdapter from 'axios-mock-adapter'
import { AuthApi } from '../AuthApi'
import { MemoryStorage } from '../lib/storage'

describe('AuthApi security flow contracts', () => {
  let authClient: AuthApi
  let mockAdapter: MockAdapter

  beforeEach(() => {
    authClient = new AuthApi('http://localhost:8080/auth', {
      storage: new MemoryStorage(),
      storageKey: 'test.auth.token',
      autoRefreshToken: false,
      persistSession: false,
      debug: false
    })

    ;(authClient as any).currentSession = {
      access_token: 'test-access-token',
      refresh_token: 'test-refresh-token',
      user: { id: 'user_123', email: 'test@example.com' }
    }
    ;(authClient as any).api.setAuth('test-access-token')

    mockAdapter = new MockAdapter((authClient as any).api.client)
  })

  afterEach(() => {
    mockAdapter.restore()
    jest.clearAllMocks()
  })

  it('updatePasswordWithFlow should call /password', async () => {
    mockAdapter.onPut('http://localhost:8080/auth/password').reply(200, {
      data: {
        user: { id: 'user_123', email: 'test@example.com' }
      }
    })

    await authClient.updatePasswordWithFlow({
      password: 'NewPassword123!'
    })

    expect(mockAdapter.history.put).toHaveLength(1)
    expect(mockAdapter.history.put[0]?.url).toBe('/password')
  })

  it('updateEmail should expose session_code from legacy flow', async () => {
    mockAdapter.onPut('http://localhost:8080/auth/email').reply(200, {
      data: {
        session_code: 'email-session-code'
      }
    })

    const result = await authClient.updateEmail({
      email: 'next@example.com'
    })

    expect(result.session_code).toBe('email-session-code')
  })

  it('updatePhone should expose session_code from legacy flow', async () => {
    mockAdapter.onPut('http://localhost:8080/auth/phone').reply(200, {
      data: {
        session_code: 'phone-session-code'
      }
    })

    const result = await authClient.updatePhone({
      phone: '+12345678901'
    })

    expect(result.session_code).toBe('phone-session-code')
  })

  it('secure email change methods should use new endpoints', async () => {
    mockAdapter.onPost('http://localhost:8080/auth/email/change').reply(200, {
      data: {
        flow_id: 'flow_123',
        session_code: 'email-session-code',
        stage: 'verify_new',
        channel: 'email',
        completed: false
      }
    })
    mockAdapter.onPost('http://localhost:8080/auth/email/change/verify').reply(200, {
      data: {
        flow_id: 'flow_123',
        stage: 'completed',
        channel: 'email',
        completed: true
      }
    })

    const start = await authClient.startEmailChange({
      email: 'next@example.com'
    })
    const verify = await authClient.verifyEmailChangeSecure({
      flow_id: 'flow_123',
      token: '123456',
      session_code: 'email-session-code'
    })

    expect(start.flow_id).toBe('flow_123')
    expect(start.session_code).toBe('email-session-code')
    expect(mockAdapter.history.post[0]?.url).toBe('/email/change')
    expect(JSON.parse(mockAdapter.history.post[1]?.data ?? '{}')).toMatchObject({
      flow_id: 'flow_123',
      token: '123456',
      session_code: 'email-session-code'
    })
    expect(verify.completed).toBe(true)
  })

  it('secure phone change methods should use new endpoints', async () => {
    mockAdapter.onPost('http://localhost:8080/auth/phone/change').reply(200, {
      data: {
        flow_id: 'flow_456',
        session_code: 'phone-session-code',
        stage: 'verify_new',
        channel: 'sms',
        completed: false
      }
    })
    mockAdapter.onPost('http://localhost:8080/auth/phone/change/verify').reply(200, {
      data: {
        flow_id: 'flow_456',
        stage: 'verify_current',
        channel: 'sms',
        session_code: 'second-session-code',
        completed: false
      }
    })

    const start = await authClient.startPhoneChange({
      phone: '+12345678901'
    })
    const verify = await authClient.verifyPhoneChangeSecure({
      flow_id: 'flow_456',
      token: '654321',
      session_code: 'phone-session-code'
    })

    expect(start.flow_id).toBe('flow_456')
    expect(start.session_code).toBe('phone-session-code')
    expect(mockAdapter.history.post[0]?.url).toBe('/phone/change')
    expect(JSON.parse(mockAdapter.history.post[1]?.data ?? '{}')).toMatchObject({
      flow_id: 'flow_456',
      token: '654321',
      session_code: 'phone-session-code'
    })
    expect(verify.stage).toBe('verify_current')
  })
})
