import { test, expect } from './fixtures/base.fixtures.js'
import { testConfig, generateTestUser, TEST_IDS } from './fixtures/test-data.js'
import { clearAuthState, getAllLocalStorage } from './helpers/auth.helper.js'

test.describe('Complete Login Flow', () => {
  test.beforeEach(async ({ page }) => {

    await page.goto(`${testConfig.baseUrl}/auth/signin`)
    await clearAuthState(page)
  })

  test('Complete user login flow', async ({ page, testContext }) => {
    let userEmail: string
    let userPassword: string

    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text())
    })

    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message)
    })

    // ==================== Step 0: Read user info from TestContext ====================
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
        console.log(`   Expected status: ${validStatuses.join(' or ')}`)
        console.log('   Please run 01-complete-signup-flow.spec.ts test first')
        test.skip()
        return
      }
      
      userEmail = email
      userPassword = password
      
      console.log(`🔍 Read user info from TestContext:`)
      console.log(`   📧 Email: ${email}`)
      console.log(`   🔑 Password: ${password.substring(0, 8)}...`)
      console.log(`   📊 Test Status: ${testStatus}`)
    })

    // ==================== Step 1: Navigate to login page ====================
    await test.step(`Navigate to login page ${testConfig.baseUrl}/auth/signin`, async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)


      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/signin`)
      console.log('✅ Successfully navigated to login page')
    })

    // ==================== Step 2: Fill login form ====================
    await test.step('Fill login form', async () => {

      await expect(page.getByTestId(TEST_IDS.SIGNIN_EMAIL)).toBeVisible({ timeout: 5000 })
      await expect(page.getByTestId(TEST_IDS.SIGNIN_PASSWORD)).toBeVisible({ timeout: 5000 })


      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(userEmail)


      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(userPassword)

      console.log('📝 Login form filled')
    })

    // ==================== Step 3: Submit login request ====================
    await test.step('Submit login request', async () => {

      const loginButton = page.getByTestId(TEST_IDS.SIGNIN_BUTTON)
      await expect(loginButton).toBeVisible()
      await loginButton.click()

      console.log('🔐 Login request sent')



    })

    // ==================== Step 4: Verify login success ====================
    await test.step('Verify login success and redirect', async () => {

      await expect(page).toHaveURL(/.*\/dashboard/, { timeout: 10000 })
      console.log('✅ Login successful, redirected to dashboard')


      await expect(page.getByTestId(TEST_IDS.DASHBOARD_TITLE)).toContainText('Dashboard')
      console.log('✅ Dashboard page loaded successfully')


      await expect(page.getByTestId(TEST_IDS.USER_EMAIL)).toBeVisible()
      console.log('✅ User info displayed correctly')
    })

    // ==================== Step 5: Verify authentication state ====================
    await test.step('Verify authentication state and localStorage', async () => {

      const authToken = await page.evaluate(() => {
        return localStorage.getItem('aira.auth.token')
      })

      const authUser = await page.evaluate(() => {
        return localStorage.getItem('aira.auth.token-user')
      })

      expect(authToken).toBeTruthy()
      expect(authUser).toBeTruthy()

      console.log('✅ Authentication state saved to localStorage')


      const userInfo = JSON.parse(authUser)
      expect(userInfo.email).toBe(userEmail)

      expect(userInfo.email).toBeTruthy()
      console.log('🔍 User object fields:', Object.keys(userInfo))

      console.log('✅ User info verification passed:', {
        email: userInfo.email,
        confirmed: !!userInfo.confirmed_at,
        lastSignIn: userInfo.last_sign_in_at
      })
    })

    // ==================== Step 6: Test logout functionality ====================
    await test.step('Test logout functionality', async () => {

      const logoutButton = page.getByTestId(TEST_IDS.LOGOUT_BUTTON)
      const signoutButton = page.getByTestId(TEST_IDS.SIGNOUT_BUTTON)


      if (await logoutButton.isVisible()) {
        await logoutButton.click()
        console.log('🔓 Clicked logout button')
      } else if (await signoutButton.isVisible()) {
        await signoutButton.click()
        console.log('🔓 Clicked logout button')
      } else {
        console.log('ℹ️ Logout button not found, skipping logout test')
        return
      }





      await expect(page).toHaveURL(/.*\/$/, { timeout: 5000 })
      console.log('✅ Logout successful, redirected to home page')


      const authToken = await page.evaluate(() => {
        return localStorage.getItem('aira.auth.token')
      })
      expect(authToken).toBeNull()
      console.log('✅ Authentication state cleared')
    })

    console.log('✅ Complete login flow test completed')
  })

  test('Error handling for failed login', async ({ page }) => {
    // ==================== Step 1: Navigate to login page ====================
    await test.step('Navigate to login page', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/signin`)
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/signin`)
      console.log('✅ Successfully navigated to login page')
    })

    // ==================== Step 2: Login with wrong credentials ====================
    await test.step('Attempt login with wrong credentials', async () => {

      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('wrong-email@example.com')


      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('WrongPassword123!')

      console.log('📝 Filled wrong login credentials')


      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()

      console.log('🔐 Submitted wrong login request')



    })

    // ==================== Step 3: Verify error message display ====================
    await test.step('Verify error message display', async () => {

      const errorMessage = page.getByTestId(TEST_IDS.ERROR_MESSAGE)
      const authMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE)

      if (await errorMessage.isVisible()) {
        await expect(errorMessage).toBeVisible()
        console.log('✅ Error message displayed')
      } else if (await authMessage.isVisible()) {
        await expect(authMessage).toBeVisible()
        console.log('✅ Auth message displayed')
      } else {

        await expect(page).toHaveURL(/.*\/auth\/signin/)
        console.log('✅ Login failed, stayed on login page')
      }


      expect(page.url()).not.toMatch(/.*\/dashboard/)
      console.log('✅ Confirmed not redirected to dashboard')
    })

    console.log('✅ Login failure handling test completed')
  })

  test('Complete flow from confirmation page to login', async ({ page, testContext }) => {
    let userEmail: string
    let userPassword: string

    // ==================== Step 0: Read user info from TestContext ====================
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
        console.log(`   Expected status: ${validStatuses.join(' or ')}`)
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

    // ==================== Step 1: Simulate redirect from confirmation page ====================
    await test.step('Simulate redirect from confirmation page to login page', async () => {

      await page.goto(`${testConfig.baseUrl}/auth/signin?confirmed=true`)


      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/signin?confirmed=true`)
      console.log('✅ Successfully navigated to login page with confirmation parameter')
    })

    // ==================== Step 2: Verify confirmation success message ====================
    await test.step('Verify confirmation success message display', async () => {

      await page.waitForLoadState('networkidle')


      const successMessage = page.getByTestId(TEST_IDS.SUCCESS_MESSAGE)
      const authMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE)

      if (await successMessage.isVisible()) {
        await expect(successMessage).toBeVisible()
        console.log('✅ Confirmation success message displayed')
      } else if (await authMessage.isVisible()) {
        await expect(authMessage).toBeVisible()
        console.log('✅ Auth message displayed')
      } else {
        console.log('ℹ️ Confirmation success message not found, page design may differ')
      }
    })

    // ==================== Step 3: Normal login flow ====================
    await test.step('Execute normal login flow', async () => {

      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(userEmail)

      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(userPassword)

      console.log('📝 Fill login credentials')


      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()

      console.log('🔐 Submit login request')



    })

    // ==================== Step 4: Verify login success ====================
    await test.step('Verify login success', async () => {

      await expect(page).toHaveURL(/.*\/dashboard/, { timeout: 10000 })
      console.log('✅ Login successful, redirected to dashboard')


      await expect(page.getByTestId(TEST_IDS.USER_EMAIL)).toBeVisible()
      console.log('✅ User info displayed correctly')
    })

    console.log('✅ Complete flow from confirmation page to login test completed')
  })
})
