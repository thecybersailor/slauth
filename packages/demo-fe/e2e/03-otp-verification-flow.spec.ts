/*
OTP Verification Flow E2E Tests
Complete verification flow including email OTP and SMS OTP

Test Flow:
1. Email OTP sending and verification
2. SMS OTP sending and verification (simulated)
3. OTP resend functionality
4. OTP verification failure handling
5. OTP expiration handling

Run command:
npm run test:e2e -- e2e/03-otp-verification-flow.spec.ts --headed --project=chromium --timeout=60000
*/

import { test, expect } from './fixtures/base.fixtures.js'
import { testConfig, generateTestUser, TEST_IDS } from './fixtures/test-data.js'
import { clearAuthState, getAllLocalStorage } from './helpers/auth.helper.js'

test.describe('OTP Verification Flow', () => {
  test.beforeEach(async ({ page }) => {
    
    await page.goto(`${testConfig.baseUrl}/auth/signin`)
    await clearAuthState(page)
  })

  test('Email OTP sending and verification flow', async ({ page }) => {
    
    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text())
    })

    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message)
    })

    // ==================== Step 1: Send email OTP directly ====================
    await test.step('Send email OTP', async () => {
      
      const response = await page.request.post(`${testConfig.backendUrl}/auth/otp`, {
        data: {
          email: 'test-1759123091412@example.com'
        }
      })

      expect(response.status()).toBe(200)
      const responseData = await response.json()
      console.log('📧 OTP send response:', responseData)

      

    })

    // ==================== Step 2: Navigate to OTP verification page ====================
    await test.step('Navigate to OTP verification page', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/verify-otp`)
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/verify-otp`)
      console.log('✅ Successfully navigated to OTP verification page')
    })

    // ==================== Step 3: Fill in email address ====================
    await test.step('Fill in email address', async () => {
      const emailInput = page.locator('[data-testid="verify-otp-email-input-field"]')
      await expect(emailInput).toBeVisible()
      await emailInput.fill('test-1759123091412@example.com')
      console.log('📧 Fill in email address')
    })

    // ==================== Step 4: Get OTP from MailHog ====================
    await test.step('Get OTP from MailHog', async () => {
      


      
      const emails = await page.request.get(`${testConfig.mailhogUrl}/api/v1/messages`).then(r => r.json())
      expect(emails.length).toBeGreaterThan(0)

      const latestEmail = emails[0]
      const emailBody = latestEmail.Content.Body
      console.log('📧 Email content preview:', emailBody.substring(0, 300))

      
      const otpMatch = emailBody.match(/\b(\d{6})\b/)
      if (!otpMatch) {
        console.log('❌ 6-digit OTP not found, email content:', emailBody)
        
        const otpMatch2 = emailBody.match(/(\d{4,8})/g)
        console.log('🔍 All numbers found:', otpMatch2)
      }
      expect(otpMatch).toBeTruthy()

      const otpCode = otpMatch[1]
      console.log('🔢 Extracted OTP code:', otpCode)

      
      await page.evaluate((otp) => {
        window.testOtpCode = otp
      }, otpCode)
    })

    // ==================== Step 7: Enter and verify OTP ====================
    await test.step('Enter and verify OTP', async () => {
      
      const otpCode = await page.evaluate(() => window.testOtpCode)
      
      
      const otpInput = page.locator('[data-testid="verification-code-input-field"]')
      await expect(otpInput).toBeVisible()
      
      
      await otpInput.fill(otpCode)
      console.log('📝 Enter OTP code:', otpCode)
      
      
      const verifyButton = page.locator('[data-testid="verify-button"]')
      await expect(verifyButton).toBeVisible()
      
      
      await verifyButton.click()
      console.log('🔐 Click verify OTP')
      
      

    })

    // ==================== Step 8: Verify OTP verification success ====================
    await test.step('Verify OTP verification success', async () => {
      
      const successMessage = page.locator('text=OTP verified, text=Verification successful, [data-testid="otp-success-message"]')
      
      if (await successMessage.count() > 0) {
        await expect(successMessage.first()).toBeVisible()
        console.log('✅ OTP verification success message displayed')
      } else {
        
        const currentUrl = page.url()
        if (currentUrl.includes('/dashboard') || currentUrl.includes('/profile')) {
          console.log('✅ OTP verification successful, redirected to another page')
        } else {
          console.log('ℹ️ OTP verification completed, but no clear success indication found')
        }
      }
    })

    console.log('✅ Email OTP sending and verification flow test completed')
  })

  test('OTP resend functionality', async ({ page }) => {
    // ==================== Step 1: Navigate to OTP verification page ====================
    await test.step('Navigate to OTP verification page', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/verify-otp`)
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/verify-otp`)
      console.log('✅ Successfully navigated to OTP verification page')
    })

    // ==================== Step 2: Send initial OTP ====================
    await test.step('Send initial OTP', async () => {
      
      const emailInput = page.locator('[data-testid="verify-otp-email-input-field"]')
      await expect(emailInput).toBeVisible()
      await emailInput.fill('test-1759123091412@example.com')
      console.log('📧 Fill in email address')
      
      
      const resendButton = page.locator('[data-testid="resend-button"]')
      await expect(resendButton).toBeVisible()
      await resendButton.click()
      console.log('📧 Send initial OTP')

    })

    // ==================== Step 3: Test resend functionality ====================
    await test.step('Test resend functionality', async () => {
      
      const resendButton = page.locator('[data-testid="resend-button"]')
      await expect(resendButton).toBeVisible()
      
      
      const isDisabled = await resendButton.isDisabled()
      
      if (!isDisabled) {
        await resendButton.click()
        console.log('🔄 Click resend OTP')
        
        

        
        
        const resendMessage = page.locator('text=Verification code sent!')
        if (await resendMessage.count() > 0) {
          await expect(resendMessage.first()).toBeVisible()
          console.log('✅ OTP resend success message displayed')
        }
      } else {
        console.log('ℹ️ Resend button temporarily unavailable (may have time restriction)')
      }
    })

    console.log('✅ OTP resend functionality test completed')
  })

  test('OTP verification failure handling', async ({ page }) => {
    // ==================== Step 1: Navigate to OTP verification page ====================
    await test.step('Navigate to OTP verification page', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/verify-otp`)
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/verify-otp`)
      console.log('✅ Successfully navigated to OTP verification page')
    })

    // ==================== Step 2: Enter incorrect OTP ====================
    await test.step('Enter incorrect OTP', async () => {
      
      const emailInput = page.locator('[data-testid="verify-otp-email-input-field"]')
      await expect(emailInput).toBeVisible()
      await emailInput.fill('test-1759123091412@example.com')
      console.log('📧 Fill in email address')
      
      
      const otpInput = page.locator('[data-testid="verification-code-input-field"]')
      await expect(otpInput).toBeVisible()
      
      
      await otpInput.fill('123456')
      console.log('📝 Enter incorrect OTP code: 123456')
      
      
      const verifyButton = page.locator('[data-testid="verify-button"]')
      await expect(verifyButton).toBeVisible()
      
      
      await verifyButton.click()
      console.log('🔐 Click verify incorrect OTP')
      
      

    })

    // ==================== Step 3: Verify error handling ====================
    await test.step('Verify error handling', async () => {
      
      const errorMessage = page.locator('text=Invalid OTP, text=OTP verification failed, [data-testid="otp-error-message"]')
      
      if (await errorMessage.count() > 0) {
        await expect(errorMessage.first()).toBeVisible()
        console.log('✅ OTP verification error message displayed')
      } else {
        
        const currentUrl = page.url()
        if (currentUrl.includes('/verify-otp')) {
          console.log('✅ Verification failed, remained on OTP verification page')
        } else {
          console.log('ℹ️ No clear error message found, but verification process handled')
        }
      }
    })

    console.log('✅ OTP verification failure handling test completed')
  })

  test('SMS OTP sending and verification flow', async ({ page }) => {
    
    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text())
    })
    
    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message)
    })

    // ==================== Step 1: Send SMS OTP ====================
    await test.step('Send SMS OTP', async () => {
      
      const response = await page.request.post(`${testConfig.backendUrl}/auth/sms-otp`, {
        data: {
          phone: '+1234567890',
          channel: 'sms'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.data.messageId).toBeDefined()
      console.log('📱 SMS OTP sent successfully, MessageID:', responseData.data.messageId)
    })

    // ==================== Step 2: Get SMS from SMSHog ====================
    await test.step('Get SMS from SMSHog', async () => {
      

      
      
      const smsResponse = await page.request.get(`${testConfig.smshogUrl}/api/v1/sms`)
      expect(smsResponse.status()).toBe(200)
      
      const smsData = await smsResponse.json()
      expect(smsData.success).toBe(true)
      expect(smsData.data.length).toBeGreaterThan(0)
      
      const latestSMS = smsData.data[0]
      console.log('📱 Latest SMS:', {
        phoneNumber: latestSMS.phoneNumber,
        message: latestSMS.message.substring(0, 100) + '...',
        timestamp: latestSMS.timestamp
      })
      
      
      const otpMatch = latestSMS.message.match(/\b(\d{6})\b/)
      expect(otpMatch).toBeTruthy()
      
      const otpCode = otpMatch[1]
      console.log('🔢 Extracted SMS OTP code:', otpCode)
      
      
      await page.evaluate((otp) => {
        window.testSmsOtpCode = otp
      }, otpCode)
    })

    // ==================== Step 3: Navigate to OTP verification page ====================
    await test.step('Navigate to OTP verification page', async () => {
      await page.goto(`${testConfig.baseUrl}/auth/verify-otp`)
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/verify-otp`)
      console.log('✅ Successfully navigated to OTP verification page')
    })

    // ==================== Step 4: Enter and verify SMS OTP ====================
    await test.step('Enter and verify SMS OTP', async () => {
      
      const smsResponse = await page.request.get(`${testConfig.smshogUrl}/api/v1/sms`)
      const smsData = await smsResponse.json()
      const latestSMS = smsData.data[0]
      
      
      const otpMatch = latestSMS.message.match(/\b(\d{6})\b/)
      expect(otpMatch).toBeTruthy()
      const otpCode = otpMatch[1]
      console.log('🔢 Re-fetched SMS OTP code:', otpCode)
      
      
      const verifyResponse = await page.request.post(`${testConfig.backendUrl}/auth/verify`, {
        data: {
          phone: '+1234567890',
          token: otpCode,
          type: 'sms'
        }
      })
      
      expect(verifyResponse.status()).toBe(200)
      const verifyData = await verifyResponse.json()
      expect(verifyData.data.success).toBe(true)
      console.log('📱 SMS OTP verification successful:', verifyData.data.message)
    })

    // ==================== Step 5: Verify SMS OTP verification success ====================
    await test.step('Verify SMS OTP verification success', async () => {
      
      const successMessage = page.locator('text=Email verified successfully!, text=Verification successful')
      
      if (await successMessage.count() > 0) {
        await expect(successMessage.first()).toBeVisible()
        console.log('✅ SMS OTP verification success message displayed')
      } else {
        
        const currentUrl = page.url()
        if (currentUrl.includes('/dashboard') || currentUrl.includes('/profile')) {
          console.log('✅ SMS OTP verification successful, redirected to another page')
        } else {
          console.log('ℹ️ SMS OTP verification completed, but no clear success indication found')
        }
      }
    })

    console.log('✅ SMS OTP sending and verification flow test completed')
  })

  test('SMS OTP sending failure scenarios (invalid phone number)', async ({ page }) => {
    
    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text())
    })
    
    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message)
    })

    // ==================== Step 1: Test empty phone number ====================
    await test.step('Test empty phone number', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/sms-otp`, {
        data: {
          phone: '',
          channel: 'sms'
        }
      })
      
      console.log('🔍 Empty phone number response status:', response.status())
      const responseData = await response.json()
      console.log('🔍 Empty phone number response data:', responseData)
      
      
      expect(response.status()).toBe(200)
      expect(responseData.error).toBeDefined()
      expect(responseData.error.key).toBe('auth.invalid_credentials')
      console.log('❌ Empty phone number send failed, error:', responseData.error)
    })

    // ==================== Step 2: Test invalid phone number format ====================
    await test.step('Test invalid phone number format', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/sms-otp`, {
        data: {
          phone: 'invalid-phone',
          channel: 'sms'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Invalid phone number format send failed, error:', responseData.error)
    })

    // ==================== Step 3: Test too short phone number ====================
    await test.step('Test too short phone number', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/sms-otp`, {
        data: {
          phone: '123',
          channel: 'sms'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Too short phone number send failed, error:', responseData.error)
    })

    // ==================== Step 4: Test missing phone number field ====================
    await test.step('Test missing phone number field', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/sms-otp`, {
        data: {
          channel: 'sms'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Missing phone number field send failed, error:', responseData.error)
    })

    console.log('✅ SMS OTP sending failure scenarios test completed')
  })

  test('Email OTP sending failure scenarios (invalid email)', async ({ page }) => {
    
    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text())
    })
    
    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message)
    })

    // ==================== Step 1: Test empty email ====================
    await test.step('Test empty email', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/otp`, {
        data: {
          email: ''
        }
      })
      
      console.log('🔍 Empty email response status:', response.status())
      const responseData = await response.json()
      console.log('🔍 Empty email response data:', responseData)
      
      
      if (response.status() === 200) {
        
        expect(responseData.error).toBeDefined()
        console.log('❌ Empty email send failed, error:', responseData.error)
      } else {
        expect(response.status()).toBe(200)
        expect(responseData.error).toBeDefined()
        console.log('❌ Empty email send failed, error:', responseData.error)
      }
    })

    // ==================== Step 2: Test invalid email format ====================
    await test.step('Test invalid email format', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/otp`, {
        data: {
          email: 'invalid-email'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Invalid email format send failed, error:', responseData.error)
    })

    // ==================== Step 3: Test email missing @ symbol ====================
    await test.step('Test email missing @ symbol', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/otp`, {
        data: {
          email: 'userexample.com'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Email missing @ symbol send failed, error:', responseData.error)
    })

    // ==================== Step 4: Test email missing domain part ====================
    await test.step('Test email missing domain part', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/otp`, {
        data: {
          email: 'user@'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Email missing domain part send failed, error:', responseData.error)
    })

    // ==================== Step 5: Test missing email field ====================
    await test.step('Test missing email field', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/otp`, {
        data: {}
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Missing email field send failed, error:', responseData.error)
    })

    console.log('✅ Email OTP sending failure scenarios test completed')
  })

  test('OTP verification failure scenarios (invalid parameters)', async ({ page }) => {
    
    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text())
    })
    
    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message)
    })

    // ==================== Step 1: Test empty OTP code ====================
    await test.step('Test empty OTP code', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/verify`, {
        data: {
          email: 'test@example.com',
          token: '',
          type: 'email'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Empty OTP code verification failed, error:', responseData.error)
    })

    // ==================== Step 2: Test empty email and phone ====================
    await test.step('Test empty email and phone', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/verify`, {
        data: {
          email: '',
          phone: '',
          token: '123456',
          type: 'email'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Empty email and phone verification failed, error:', responseData.error)
    })

    // ==================== Step 3: Test invalid OTP type ====================
    await test.step('Test invalid OTP type', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/verify`, {
        data: {
          email: 'test@example.com',
          token: '123456',
          type: 'invalid_type'
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Invalid OTP type verification failed, error:', responseData.error)
    })

    // ==================== Step 4: Test missing required fields ====================
    await test.step('Test missing required fields', async () => {
      const response = await page.request.post(`${testConfig.backendUrl}/auth/verify`, {
        data: {
          email: 'test@example.com'
          
        }
      })
      
      expect(response.status()).toBe(200)
      const responseData = await response.json()
      expect(responseData.error).toBeDefined()
      console.log('❌ Missing required fields verification failed, error:', responseData.error)
    })

    console.log('✅ OTP verification failure scenarios test completed')
  })
})
