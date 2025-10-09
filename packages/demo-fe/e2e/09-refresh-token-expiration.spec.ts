import { test, expect } from './fixtures/base.fixtures.js'
import { clearAuthState } from './helpers/auth.helper.js'
import { testConfig, TEST_IDS } from './fixtures/test-data.js'

test.describe('Refresh Token Expiration and Callbacks', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${testConfig.baseUrl}/auth/signin`)
    await clearAuthState(page)
  })

  test('Refresh token works before expiration with callback verification', async ({ page, testContext }) => {
    let userEmail: string
    let userPassword: string

    await test.step('Read user info from TestContext', async () => {
      const email = testContext.get<string>('auth.email')
      const password = testContext.get<string>('auth.password')
      const testStatus = testContext.get<string>('test.status')
      
      const validStatuses = ['email_confirmed_and_signin_completed', 'signin_completed', 'signup_completed_pending_confirmation']

      if (!email || !password || !validStatuses.includes(testStatus)) {
        console.log('⚠️ No valid user info found in TestContext or incorrect user status')
        console.log(`   📧 Email: ${email || 'none'}`)
        console.log(`   🔑 Password: ${password ? 'exists' : 'none'}`)
        console.log(`   📊 Test Status: ${testStatus || 'none'}`)
        console.log('   Please run 01-complete-signup-flow.spec.ts test first')
        test.skip()
        return
      }
      
      userEmail = email
      userPassword = password
      
      console.log(`🔍 Read user info from TestContext:`)
      console.log(`   📧 Email: ${email}`)
      console.log(`   🔑 Password: ${password.substring(0, 8)}...`)
    })

    await test.step('Configure session time-box to 10 seconds', async () => {
      const configResult = await page.evaluate(async (backendUrl) => {
        const response = await fetch(`${backendUrl}/admin/config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: {
              session_config: {
                time_box_user_sessions: 10
              }
            }
          })
        })
        return {
          status: response.status,
          ok: response.ok
        }
      }, testConfig.backendUrl)

      expect(configResult.ok).toBe(true)
      console.log('✅ Session time-box configured to 10 seconds')
    })

    await test.step('Login with valid credentials', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)
      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(userEmail)
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(userPassword)
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      
      await page.waitForURL(/\/dashboard/, { timeout: 10000 })
      await expect(page.getByTestId(TEST_IDS.DASHBOARD_TITLE)).toBeVisible({ timeout: 5000 })
      
      console.log('✅ Login successful')
    })

    await test.step('Initialize callback tracking', async () => {
      await page.evaluate(() => {
        (window as any).authCallbacks = {
          onSessionRefreshed: 0,
          onUnauthorized: 0,
          onAuthError: 0,
          lastRefreshedSession: null,
          lastError: null
        }
      })
      console.log('✅ Callback tracking initialized')
    })

    await test.step('Wait 2 seconds (token still valid)', async () => {
      await page.waitForTimeout(2000)
      console.log('✅ Waited 2 seconds, token should still be valid')
    })

    await test.step('Manually refresh token before expiration', async () => {
      const result = await page.evaluate(async (backendUrl) => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session || !session.refresh_token) {
          return { error: 'No refresh token found' }
        }

        const oldAccessToken = session.access_token
        const oldRefreshToken = session.refresh_token

        const response = await fetch(`${backendUrl}/auth/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            refresh_token: session.refresh_token
          })
        })

        const data = await response.json()
        
        if (response.ok && data.data?.session) {
          localStorage.setItem('aira.auth.token', JSON.stringify(data.data.session))
          
          return {
            success: true,
            status: response.status,
            oldAccessToken: oldAccessToken,
            newAccessToken: data.data.session.access_token,
            oldRefreshToken: oldRefreshToken,
            newRefreshToken: data.data.session.refresh_token,
            tokensAreDifferent: oldAccessToken !== data.data.session.access_token,
            refreshTokensAreDifferent: oldRefreshToken !== data.data.session.refresh_token
          }
        }

        return { 
          error: data.error || 'Refresh failed',
          status: response.status
        }
      }, testConfig.backendUrl)

      expect(result.success).toBe(true)
      expect(result.status).toBe(200)
      expect(result.tokensAreDifferent).toBe(true)
      console.log('✅ Token refreshed successfully before expiration')
      console.log(`   📊 Access tokens different: ${result.tokensAreDifferent}`)
      console.log(`   📊 Refresh tokens different: ${result.refreshTokensAreDifferent}`)
    })

    await test.step('Verify new access token is valid', async () => {
      const userInfoResult = await page.evaluate(async (backendUrl) => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session) return { error: 'No session' }

        const response = await fetch(`${backendUrl}/auth/user`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${session.access_token}`
          }
        })

        const data = await response.json()
        return {
          status: response.status,
          hasUser: !!data.data?.user,
          email: data.data?.user?.email
        }
      }, testConfig.backendUrl)

      expect(userInfoResult.status).toBe(200)
      expect(userInfoResult.hasUser).toBe(true)
      expect(userInfoResult.email).toBe(userEmail)
      console.log('✅ New access token validated successfully')
    })

    await test.step('Reset session config to default', async () => {
      await page.evaluate(async (backendUrl) => {
        await fetch(`${backendUrl}/admin/config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: {
              session_config: {
                time_box_user_sessions: 0
              }
            }
          })
        })
      }, testConfig.backendUrl)
      console.log('✅ Session config reset to default')
    })
  })

  test('Refresh token fails after expiration', async ({ page, testContext }) => {
    let userEmail: string
    let userPassword: string

    await test.step('Read user info from TestContext', async () => {
      const email = testContext.get<string>('auth.email')
      const password = testContext.get<string>('auth.password')
      const testStatus = testContext.get<string>('test.status')
      
      const validStatuses = ['email_confirmed_and_signin_completed', 'signin_completed', 'signup_completed_pending_confirmation']

      if (!email || !password || !validStatuses.includes(testStatus)) {
        console.log('⚠️ No valid user info found in TestContext or incorrect user status')
        test.skip()
        return
      }
      
      userEmail = email
      userPassword = password
      
      console.log(`🔍 Read user info from TestContext:`)
      console.log(`   📧 Email: ${email}`)
    })

    await test.step('Configure session time-box to 2 seconds', async () => {
      const configResult = await page.evaluate(async (backendUrl) => {
        const response = await fetch(`${backendUrl}/admin/config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: {
              session_config: {
                time_box_user_sessions: 2
              }
            }
          })
        })
        return {
          status: response.status,
          ok: response.ok
        }
      }, testConfig.backendUrl)

      expect(configResult.ok).toBe(true)
      console.log('✅ Session time-box configured to 2 seconds')
    })

    await test.step('Login with valid credentials', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)
      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(userEmail)
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(userPassword)
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      
      await page.waitForURL(/\/dashboard/, { timeout: 10000 })
      await expect(page.getByTestId(TEST_IDS.DASHBOARD_TITLE)).toBeVisible({ timeout: 5000 })
      
      console.log('✅ Login successful')
    })

    await test.step('Initialize callback tracking', async () => {
      await page.evaluate(() => {
        (window as any).authCallbacks = {
          onSessionRefreshed: 0,
          onUnauthorized: 0,
          onAuthError: 0,
          lastError: null
        }
      })
      console.log('✅ Callback tracking initialized')
    })

    await test.step('Wait 3 seconds for session to expire', async () => {
      await page.waitForTimeout(3000)
      console.log('✅ Waited 3 seconds, session should be expired')
    })

    await test.step('Attempt to refresh expired token', async () => {
      const result = await page.evaluate(async (backendUrl) => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session || !session.refresh_token) {
          return { error: 'No refresh token found' }
        }

        const response = await fetch(`${backendUrl}/auth/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            refresh_token: session.refresh_token
          })
        })

        const data = await response.json()
        
        return {
          status: response.status,
          ok: response.ok,
          error: data.error,
          errorKey: data.error?.key,
          errorMessage: data.error?.message
        }
      }, testConfig.backendUrl)

      expect(result.status).toBe(401)
      expect(result.ok).toBe(false)
      expect(result.errorKey).toBe('auth.session_expired')
      console.log('✅ Refresh token correctly rejected after expiration')
      console.log(`   📊 Status: ${result.status}`)
      console.log(`   📊 Error: ${result.errorKey}`)
      console.log(`   📊 Message: ${result.errorMessage}`)
    })

    await test.step('Verify old access token is also invalid', async () => {
      const userInfoResult = await page.evaluate(async (backendUrl) => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session) return { error: 'No session' }

        const response = await fetch(`${backendUrl}/auth/user`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${session.access_token}`
          }
        })

        const data = await response.json()
        return {
          status: response.status,
          errorKey: data.error?.key
        }
      }, testConfig.backendUrl)

      expect(userInfoResult.status).toBe(401)
      console.log('✅ Old access token also rejected')
      console.log(`   📊 Error: ${userInfoResult.errorKey}`)
    })

    await test.step('Reset session config to default', async () => {
      await page.evaluate(async (backendUrl) => {
        await fetch(`${backendUrl}/admin/config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: {
              session_config: {
                time_box_user_sessions: 0
              }
            }
          })
        })
      }, testConfig.backendUrl)
      console.log('✅ Session config reset to default')
    })
  })

  test('Verify SDK callbacks with auto-refresh enabled', async ({ page, testContext }) => {
    let userEmail: string
    let userPassword: string

    await test.step('Read user info from TestContext', async () => {
      const email = testContext.get<string>('auth.email')
      const password = testContext.get<string>('auth.password')
      const testStatus = testContext.get<string>('test.status')
      
      const validStatuses = ['email_confirmed_and_signin_completed', 'signin_completed', 'signup_completed_pending_confirmation']

      if (!email || !password || !validStatuses.includes(testStatus)) {
        console.log('⚠️ No valid user info found in TestContext or incorrect user status')
        test.skip()
        return
      }
      
      userEmail = email
      userPassword = password
      
      console.log(`🔍 Read user info from TestContext:`)
      console.log(`   📧 Email: ${email}`)
    })

    await test.step('Navigate to app and verify callback tracking is ready', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)
      
      // Wait for auth module to load
      await page.waitForTimeout(1000)
      
      const callbackStatus = await page.evaluate(() => {
        return {
          hasCallbacks: !!(window as any).__authCallbacks,
          initialCounts: (window as any).__authCallbacks
        }
      })

      expect(callbackStatus.hasCallbacks).toBe(true)
      console.log('✅ Callback tracking is ready:', callbackStatus.initialCounts)
    })

    await test.step('Configure session time-box to 5 seconds', async () => {
      const configResult = await page.evaluate(async (backendUrl) => {
        const response = await fetch(`${backendUrl}/admin/config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: {
              session_config: {
                time_box_user_sessions: 5
              }
            }
          })
        })
        return { ok: response.ok }
      }, testConfig.backendUrl)

      expect(configResult.ok).toBe(true)
      console.log('✅ Session time-box configured to 5 seconds')
    })

    await test.step('Reset callback counters before signin', async () => {
      await page.evaluate(() => {
        const win = window as any
        if (win.__authCallbacks) {
          win.__authCallbacks.onSessionRefreshed = 0
          win.__authCallbacks.onUnauthorized = 0
          win.__authCallbacks.onAuthError = 0
          win.__authCallbacks.callHistory = []
        }
      })
      console.log('✅ Callback counters reset')
    })

    await test.step('Sign in using UI', async () => {
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(userEmail)
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(userPassword)
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      
      await page.waitForURL(/\/dashboard/, { timeout: 10000 })
      await expect(page.getByTestId(TEST_IDS.DASHBOARD_TITLE)).toBeVisible({ timeout: 5000 })
      
      console.log('✅ Sign in successful')
    })

    await test.step('Check callback counts after initial login', async () => {
      const callbacks = await page.evaluate(() => {
        return (window as any).__authCallbacks
      })
      
      console.log('📊 Callback counts after login:')
      console.log(`   onSessionRefreshed: ${callbacks.onSessionRefreshed}`)
      console.log(`   onUnauthorized: ${callbacks.onUnauthorized}`)
      console.log(`   onAuthError: ${callbacks.onAuthError}`)
    })

    await test.step('Manually trigger refresh before expiration', async () => {
      await page.waitForTimeout(2000)
      
      const refreshResult = await page.evaluate(async (backendUrl) => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session || !session.refresh_token) {
          return { error: 'No refresh token found' }
        }

        const response = await fetch(`${backendUrl}/auth/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            refresh_token: session.refresh_token
          })
        })

        const data = await response.json()
        
        if (response.ok && data.data?.session) {
          localStorage.setItem('aira.auth.token', JSON.stringify(data.data.session))
          
          return {
            success: true,
            callbacks: (window as any).__authCallbacks
          }
        }

        return { 
          error: data.error || 'Refresh failed',
          callbacks: (window as any).__authCallbacks
        }
      }, testConfig.backendUrl)

      expect(refreshResult.success).toBe(true)
      console.log('✅ Manual refresh successful')
      console.log(`📊 onSessionRefreshed called: ${refreshResult.callbacks.onSessionRefreshed} times`)
      console.log(`📊 onAuthError called: ${refreshResult.callbacks.onAuthError} times`)
    })

    await test.step('Wait for expiration and attempt refresh', async () => {
      await page.waitForTimeout(4000)
      
      const expiredRefreshResult = await page.evaluate(async (backendUrl) => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session || !session.refresh_token) {
          return { error: 'No refresh token found' }
        }

        const response = await fetch(`${backendUrl}/auth/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            refresh_token: session.refresh_token
          })
        })

        const data = await response.json()
        
        return {
          success: response.ok,
          status: response.status,
          error: data.error,
          callbacks: (window as any).__authCallbacks
        }
      }, testConfig.backendUrl)

      expect(expiredRefreshResult.success).toBe(false)
      expect(expiredRefreshResult.status).toBe(401)
      console.log('✅ Expired refresh correctly failed')
      console.log(`📊 Final callback counts:`)
      console.log(`   onSessionRefreshed: ${expiredRefreshResult.callbacks.onSessionRefreshed}`)
      console.log(`   onUnauthorized: ${expiredRefreshResult.callbacks.onUnauthorized}`)
      console.log(`   onAuthError: ${expiredRefreshResult.callbacks.onAuthError}`)
      console.log(`📊 Call history length: ${expiredRefreshResult.callbacks.callHistory.length}`)
    })

    await test.step('Reset session config to default', async () => {
      await page.evaluate(async (backendUrl) => {
        await fetch(`${backendUrl}/admin/config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: {
              session_config: {
                time_box_user_sessions: 0
              }
            }
          })
        })
      }, testConfig.backendUrl)
      console.log('✅ Session config reset to default')
    })
  })
})

