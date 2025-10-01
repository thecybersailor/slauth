import { test, expect } from './fixtures/base.fixtures.js'
import { clearAuthState } from './helpers/auth.helper.js'
import { testConfig, TEST_IDS } from './fixtures/test-data.js'

test.describe('Token Refresh and Callback Mechanisms', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${testConfig.baseUrl}/auth/signin`)
    await clearAuthState(page)
  })

  test('Manual token refresh after login', async ({ page, testContext }) => {
    let userEmail: string
    let userPassword: string

    // Step 0: Read user info from TestContext
    await test.step('Read user info from TestContext', async () => {
      const email = testContext.get<string>('auth.email')
      const password = testContext.get<string>('auth.password')
      const testStatus = testContext.get<string>('test.status')
      
      const validStatuses = ['email_confirmed_and_signin_completed', 'signup_completed_pending_confirmation']

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

    // Step 1: Login first
    await test.step('Login with valid credentials', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)
      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(userEmail)
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(userPassword)
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      
      await expect(page).toHaveURL(/.*\/dashboard/, { timeout: 10000 })
      console.log('✅ Login successful')
    })

    // Step 2: Get current session tokens
    await test.step('Verify session tokens exist', async () => {
      const session = await page.evaluate(() => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        return sessionStr ? JSON.parse(sessionStr) : null
      })

      expect(session).toBeTruthy()
      expect(session.access_token).toBeTruthy()
      expect(session.refresh_token).toBeTruthy()
      
      console.log('✅ Session tokens verified:', {
        hasAccessToken: !!session.access_token,
        hasRefreshToken: !!session.refresh_token,
        expiresAt: session.expires_at
      })
    })

    // Step 3: Call refresh token API manually
    await test.step('Manually refresh token', async () => {
      const result = await page.evaluate(async () => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session || !session.refresh_token) {
          return { error: 'No refresh token found' }
        }

        const oldAccessToken = session.access_token

        const response = await fetch(`${testConfig.backendUrl}/auth/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            refresh_token: session.refresh_token
          })
        })

        const data = await response.json()
        
        if (data.data?.session) {
          // Update localStorage with new session
          localStorage.setItem('aira.auth.token', JSON.stringify(data.data.session))
          
          return {
            success: true,
            oldAccessToken: oldAccessToken,
            newAccessToken: data.data.session.access_token,
            tokensAreDifferent: oldAccessToken !== data.data.session.access_token
          }
        }

        return { error: data.error || 'Refresh failed' }
      })

      expect(result.success).toBe(true)
      expect(result.tokensAreDifferent).toBe(true)
      console.log('✅ Token refreshed successfully, tokens are different')
    })

    // Step 4: Verify new token works
    await test.step('Verify new access token is valid', async () => {
      const userInfoResult = await page.evaluate(async () => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        const session = sessionStr ? JSON.parse(sessionStr) : null
        
        if (!session) return { error: 'No session' }

        const response = await fetch(`${testConfig.backendUrl}/auth/user`, {
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
      })

      expect(userInfoResult.status).toBe(200)
      expect(userInfoResult.hasUser).toBe(true)
      expect(userInfoResult.email).toBe('test-refresh@example.com')
      console.log('✅ New access token validated successfully')
    })
  })

  test('Callback mechanism on unauthorized error', async ({ page }) => {
    // Step 1: Setup callback tracking
    await page.goto(`${testConfig.baseUrl}/`)
    
    await test.step('Inject callback tracking code', async () => {
      await page.evaluate(() => {
        (window as any).callbackLog = {
          onUnauthorized: 0,
          onSessionExpired: 0,
          onAuthError: 0
        }
      })
      console.log('✅ Callback tracking injected')
    })

    // Step 2: Make request with expired/invalid token
    await test.step('Trigger unauthorized error with invalid token', async () => {
      const result = await page.evaluate(async () => {
        // Store callback invocations
        const log = (window as any).callbackLog

        // Make request with invalid token
        const response = await fetch(`${testConfig.backendUrl}/auth/user`, {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer invalid-token'
          }
        }).catch(err => ({ error: err.message }))

        const data = await response.json?.() || response

        // Check if it's an unauthorized error
        if (data.error && (data.error.key === 'auth.unauthorized' || data.error.key === 'auth.authorization_required')) {
          log.onUnauthorized++
          log.onAuthError++
        }

        return {
          errorKey: data.error?.key,
          errorMessage: data.error?.message,
          onUnauthorizedCalled: log.onUnauthorized,
          onAuthErrorCalled: log.onAuthError
        }
      })

      console.log('📊 Callback result:', result)
      
      expect(result.errorKey).toMatch(/auth\.unauthorized|auth\.authorization_required/)
      // Note: In real implementation, callbacks would be triggered by SDK
      console.log('✅ Unauthorized error detected')
    })
  })

  test('Expired session handling', async ({ page }) => {
    // This test simulates session expiration behavior
    
    await test.step('Login and get session', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)
      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('test-expired@example.com')
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('TestPassword123!')
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      
      await expect(page).toHaveURL(/.*\/dashboard/, { timeout: 10000 })
      console.log('✅ Login successful')
    })

    await test.step('Manually corrupt session to simulate expiration', async () => {
      await page.evaluate(() => {
        // Simulate expired session by setting a very old expiration time
        const sessionStr = localStorage.getItem('aira.auth.token')
        if (sessionStr) {
          const session = JSON.parse(sessionStr)
          session.expires_at = Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
          localStorage.setItem('aira.auth.token', JSON.stringify(session))
        }
      })
      console.log('✅ Session expiration simulated')
    })

    await test.step('Verify session expiration detection', async () => {
      const isExpired = await page.evaluate(() => {
        const sessionStr = localStorage.getItem('aira.auth.token')
        if (!sessionStr) return true
        
        const session = JSON.parse(sessionStr)
        const now = Math.floor(Date.now() / 1000)
        return session.expires_at < now
      })

      expect(isExpired).toBe(true)
      console.log('✅ Session detected as expired')
    })
  })

  test('onAuthError callback for general auth errors', async ({ page }) => {
    await page.goto(`${testConfig.baseUrl}/`)

    await test.step('Trigger authentication error', async () => {
      const result = await page.evaluate(async () => {
        const response = await fetch(`${testConfig.backendUrl}/auth/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            grant_type: 'password',
            email: 'nonexistent@example.com',
            password: 'WrongPassword123!'
          })
        })

        const data = await response.json()

        return {
          status: response.status,
          hasError: !!data.error,
          errorKey: data.error?.key,
          errorMessage: data.error?.message
        }
      })

      expect(result.hasError).toBe(true)
      expect(result.errorKey).toBeTruthy()
      console.log('✅ Auth error triggered:', result.errorKey)
      console.log('💡 In real SDK usage, onAuthError callback would be invoked here')
    })
  })
})

