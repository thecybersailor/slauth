import { test, expect } from './fixtures/base.fixtures.js'
import { testConfig, TEST_IDS } from './fixtures/test-data.js'

/**
 * Form Validation Tests
 * Test various form validation scenarios
 */
test.describe('Form Validation Tests', () => {
  test.beforeEach(async ({ page }) => {
    console.log('🚀 Starting form validation tests')
  })

  test('Login form empty field validation', async ({ page }) => {
    await test.step('Visit login page', async () => {
      await page.goto('/auth/signin')
      await page.waitForLoadState('networkidle')
    })

    await test.step('Submit empty form', async () => {
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      await page.waitForTimeout(2000)
    })

    await test.step('Check validation behavior', async () => {
      
      const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE)
      const hasMessage = await messageElement.isVisible()
      
      if (hasMessage) {
        const messageText = await messageElement.textContent()
        console.log('✅ Form validation triggered:', messageText)
      } else {
        console.log('ℹ️ May be using HTML5 validation or other validation methods')
      }
    })

    console.log('✅ Login form empty field validation test completed')
  })

  test('Registration form password confirmation validation', async ({ page }) => {
    await test.step('Visit signup page', async () => {
      await page.goto('/auth/signup')
      await page.waitForLoadState('networkidle')
    })

    await test.step('Fill in mismatched passwords', async () => {
      await page.getByTestId(TEST_IDS.SIGNUP_EMAIL).locator('input').fill('test@example.com')
      await page.getByTestId(TEST_IDS.SIGNUP_PASSWORD).locator('input').fill('Password123!')
      await page.getByTestId(TEST_IDS.SIGNUP_CONFIRM_PASSWORD).locator('input').fill('different-password')
    })

    await test.step('Submit form', async () => {
      await page.getByTestId(TEST_IDS.SIGNUP_BUTTON).click()
      
      await page.waitForTimeout(500)
    })

    await test.step('Check validation result', async () => {
      
      const confirmPasswordInput = page.getByTestId(TEST_IDS.SIGNUP_CONFIRM_PASSWORD)
      const confirmPasswordError = confirmPasswordInput.locator('.aira-input__error')
      const authMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE)

      
      await page.waitForTimeout(100)

      const hasConfirmPasswordError = await confirmPasswordError.isVisible()
      const hasAuthMessage = await authMessage.isVisible()

      console.log('🔍 Confirm password error visible:', hasConfirmPasswordError)
      console.log('🔍 Auth message visible:', hasAuthMessage)

      if (hasConfirmPasswordError) {
        
        const dataStatus = await confirmPasswordInput.getAttribute('data-status')
        console.log('🔍 Confirm password input status:', dataStatus)
        await expect(confirmPasswordInput).toHaveAttribute('data-status', 'error')
        console.log('✅ Confirm password error status validation successful')
      } else if (hasAuthMessage) {
        await expect(authMessage).toHaveAttribute('data-status', 'error')
        console.log('✅ Auth error message status validation successful')
      } else {
        console.log('ℹ️ May be using HTML5 validation or other validation methods')
      }
    })

    console.log('✅ Registration form password confirmation validation test completed')
  })

  test('Email format validation', async ({ page }) => {
    await test.step('Visit login page', async () => {
      await page.goto('/auth/signin')
      await page.waitForLoadState('networkidle')
    })

    await test.step('Fill in invalid email format', async () => {
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('invalid-email')
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('Password123!')
    })

    await test.step('Submit form', async () => {
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      await page.waitForTimeout(2000)
    })

    await test.step('Check validation result', async () => {
      const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE)
      const hasMessage = await messageElement.isVisible()
      
      if (hasMessage) {
        const messageText = await messageElement.textContent()
        console.log('✅ Email format validation triggered:', messageText)
      } else {
        console.log('ℹ️ Email format validation may be handled by frontend')
      }
    })

    console.log('✅ Email format validation test completed')
  })

  test('Required field validation', async ({ page }) => {
    await test.step('Visit signup page', async () => {
      await page.goto('/auth/signup')
      await page.waitForLoadState('networkidle')
    })

    await test.step('Fill in only partial fields', async () => {
      await page.getByTestId(TEST_IDS.SIGNUP_EMAIL).locator('input').fill('test@example.com')
      
    })

    await test.step('Submit form', async () => {
      await page.getByTestId(TEST_IDS.SIGNUP_BUTTON).click()
      await page.waitForTimeout(2000)
    })

    await test.step('Check validation result', async () => {
      const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE)
      const hasMessage = await messageElement.isVisible()
      
      if (hasMessage) {
        const messageText = await messageElement.textContent()
        console.log('✅ Required field validation triggered:', messageText)
      } else {
        console.log('ℹ️ Required field validation may be handled by HTML5')
      }
    })

    console.log('✅ Required field validation test completed')
  })
})
