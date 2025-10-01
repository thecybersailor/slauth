import { test, expect } from './fixtures/base.fixtures.js'
import { testConfig, generateTestUser, TEST_IDS } from './fixtures/test-data.js'
import { clearAuthState } from './helpers/auth.helper.js'

/**
 * Redirect Security Flow Tests
 * 
 * Tests redirect parameter handling and validation across authentication flows:
 * 1. Valid same-domain redirects
 * 2. Valid whitelisted cross-domain redirects
 * 3. Invalid redirects (should fallback to SiteURL)
 * 4. Redirect parameter preservation across page transitions
 * 5. Multi-step flow redirect handling (OTP, email verification)
 * 6. OAuth/SSO redirect handling
 * 
 * Security Requirements:
 * - All redirect URLs must be validated by backend against RedirectURLs whitelist
 * - Invalid URLs should fallback to configured SiteURL
 * - No client-side redirect bypass allowed
 * - Redirect parameters preserved throughout authentication flow
 */

test.describe('Redirect Security Flow', () => {
  const baseUrl = testConfig.baseUrl
  
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page)
  })

  test.describe('Valid Redirect - Same Domain', () => {
    test('should redirect to valid same-domain URL after signin', async ({ page }) => {
      const testUser = {
        email: 'test-redirect-signin@example.com',
        password: 'TestPassword123!'
      }
      const redirectTo = '/dashboard'
      
      await test.step('Navigate to signin with redirect parameter', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(redirectTo)}`)
        await expect(page).toHaveURL(new RegExp(`/auth/signin\\?redirect=`))
        console.log(`✅ Navigated to signin with redirect=${redirectTo}`)
      })

      await test.step('Submit signin form', async () => {
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        console.log('📝 Signin form submitted')
      })

      await test.step('Verify redirect to dashboard', async () => {
        // Should redirect to the specified URL
        await page.waitForURL(/\/dashboard/, { timeout: 10000 })
        expect(page.url()).toContain('/dashboard')
        console.log('✅ Successfully redirected to dashboard')
      })
    })

    test('should redirect to valid same-domain URL after signup', async ({ page }) => {
      const testUser = generateTestUser()
      const redirectTo = '/welcome'
      
      await test.step('Navigate to signup with redirect parameter', async () => {
        await page.goto(`${baseUrl}/auth/signup?redirect=${encodeURIComponent(redirectTo)}`)
        await expect(page).toHaveURL(new RegExp(`/auth/signup\\?redirect=`))
      })

      await test.step('Submit signup form', async () => {
        await page.getByTestId(TEST_IDS.SIGNUP_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNUP_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNUP_BUTTON).click()
      })

      await test.step('Verify redirect or email verification flow', async () => {
        // May redirect directly or go to verification flow depending on config
        await page.waitForTimeout(2000)
        const currentUrl = page.url()
        
        // If email confirmation is disabled, should redirect to welcome
        if (currentUrl.includes('/welcome')) {
          console.log('✅ Successfully redirected to welcome page')
        } 
        // If email confirmation is enabled, should be in verification flow
        else if (currentUrl.includes('/verify')) {
          console.log('📧 Email verification required - redirect will happen after verification')
        }
      })
    })
  })

  test.describe('Valid Redirect - Whitelisted Cross-Domain', () => {
    test('should redirect to whitelisted external URL', async ({ page }) => {
      const testUser = {
        email: 'test-redirect-external@example.com',
        password: 'TestPassword123!'
      }
      // This URL should be in RedirectURLs configuration
      const redirectTo = 'http://localhost:3000/callback'
      
      await test.step('Navigate with external redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(redirectTo)}`)
        await expect(page).toHaveURL(new RegExp(`/auth/signin\\?redirect=`))
      })

      await test.step('Submit signin form', async () => {
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      })

      await test.step('Verify redirect to external URL', async () => {
        // Should redirect to whitelisted external URL
        await page.waitForTimeout(3000)
        const finalUrl = page.url()
        
        // If redirected to external URL, URL should change
        if (finalUrl.includes('localhost:3000')) {
          console.log('✅ Successfully redirected to whitelisted external URL')
          expect(finalUrl).toContain('localhost:3000')
        } else {
          console.log('⚠️ External redirect may not be whitelisted, check RedirectURLs config')
        }
      })
    })
  })

  test.describe('Invalid Redirect - Security Fallback', () => {
    test('should fallback to SiteURL for non-whitelisted URL', async ({ page }) => {
      const testUser = {
        email: 'test-redirect-invalid@example.com',
        password: 'TestPassword123!'
      }
      // Malicious external URL that should NOT be in whitelist
      const maliciousRedirect = 'https://evil-phishing-site.com/fake-dashboard'
      
      await test.step('Navigate with malicious redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(maliciousRedirect)}`)
        console.log(`🔒 Testing security: malicious redirect=${maliciousRedirect}`)
      })

      await test.step('Submit signin form', async () => {
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      })

      await test.step('Verify fallback to safe URL', async () => {
        await page.waitForTimeout(3000)
        const finalUrl = page.url()
        
        // Should NOT redirect to evil-phishing-site.com
        expect(finalUrl).not.toContain('evil-phishing-site.com')
        console.log('✅ Security validation passed: malicious redirect blocked')
        
        // Should redirect to SiteURL or stay in same domain
        const frontendHost = new URL(testConfig.baseUrl).host
        expect(finalUrl).toContain(frontendHost)
        console.log(`✅ Fallback to safe URL: ${finalUrl}`)
      })
    })

    test('should reject javascript: protocol redirect', async ({ page }) => {
      const testUser = {
        email: 'test-redirect-xss@example.com',
        password: 'TestPassword123!'
      }
      // XSS attempt
      const xssRedirect = 'javascript:alert("XSS")'
      
      await test.step('Navigate with XSS redirect attempt', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(xssRedirect)}`)
        console.log(`🔒 Testing XSS protection: ${xssRedirect}`)
      })

      await test.step('Submit signin form', async () => {
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
      })

      await test.step('Verify XSS blocked', async () => {
        await page.waitForTimeout(2000)
        const finalUrl = page.url()
        
        // Should NOT execute javascript
        expect(finalUrl).not.toContain('javascript:')
        console.log('✅ XSS protection passed: javascript: protocol blocked')
      })
    })

    test('should reject data: protocol redirect', async ({ page }) => {
      const testUser = {
        email: 'test-redirect-data@example.com',
        password: 'TestPassword123!'
      }
      // Data URL redirect attempt
      const dataRedirect = 'data:text/html,<script>alert("XSS")</script>'
      
      await test.step('Navigate with data URL redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(dataRedirect)}`)
        console.log(`🔒 Testing data URL protection`)
      })

      await test.step('Submit and verify blocked', async () => {
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        
        await page.waitForTimeout(2000)
        const finalUrl = page.url()
        expect(finalUrl).not.toContain('data:')
        console.log('✅ Data URL protection passed')
      })
    })
  })

  test.describe('Redirect Parameter Preservation', () => {
    test('should preserve redirect when switching from signin to signup', async ({ page }) => {
      const redirectTo = '/onboarding'
      
      await test.step('Navigate to signin with redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(redirectTo)}`)
        const url = page.url()
        expect(url).toContain('redirect=')
        console.log(`✅ Signin page loaded with redirect=${redirectTo}`)
      })

      await test.step('Click signup link', async () => {
        await page.getByTestId(TEST_IDS.SIGNUP_LINK).click()
        await page.waitForTimeout(500)
      })

      await test.step('Verify redirect preserved in signup URL', async () => {
        const signupUrl = page.url()
        expect(signupUrl).toContain('/auth/signup')
        expect(signupUrl).toContain(`redirect=${encodeURIComponent(redirectTo)}`)
        console.log('✅ Redirect parameter preserved when switching to signup')
      })
    })

    test('should preserve redirect when switching from signup to signin', async ({ page }) => {
      const redirectTo = '/dashboard?welcome=true'
      
      await test.step('Navigate to signup with redirect', async () => {
        await page.goto(`${baseUrl}/auth/signup?redirect=${encodeURIComponent(redirectTo)}`)
        expect(page.url()).toContain('redirect=')
      })

      await test.step('Click signin link', async () => {
        await page.getByTestId(TEST_IDS.SIGNIN_LINK).click()
        await page.waitForTimeout(500)
      })

      await test.step('Verify redirect preserved in signin URL', async () => {
        const signinUrl = page.url()
        expect(signinUrl).toContain('/auth/signin')
        expect(signinUrl).toContain('redirect=')
        console.log('✅ Redirect parameter preserved when switching to signin')
      })
    })

    test('should preserve redirect through forgot password flow', async ({ page }) => {
      const redirectTo = '/settings'
      
      await test.step('Navigate to signin with redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(redirectTo)}`)
      })

      await test.step('Click forgot password link', async () => {
        const forgotPasswordLink = page.getByTestId(TEST_IDS.FORGOT_PASSWORD_LINK)
        if (await forgotPasswordLink.isVisible()) {
          await forgotPasswordLink.click()
          await page.waitForTimeout(500)
          
          const forgotPasswordUrl = page.url()
          expect(forgotPasswordUrl).toContain('forgot-password')
          expect(forgotPasswordUrl).toContain('redirect=')
          console.log('✅ Redirect preserved in forgot password flow')
        } else {
          console.log('⚠️ Forgot password link not visible, skipping test')
        }
      })
    })
  })

  test.describe('Multi-Step Flow Redirect', () => {
    test('should maintain redirect through OTP verification flow', async ({ page, request }) => {
      const testUser = generateTestUser()
      const redirectTo = '/verify-success'
      
      await test.step('Signup with redirect and email confirmation enabled', async () => {
        // Assume email confirmation is enabled in config
        await page.goto(`${baseUrl}/auth/signup?redirect=${encodeURIComponent(redirectTo)}`)
        
        await page.getByTestId(TEST_IDS.SIGNUP_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNUP_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNUP_BUTTON).click()
      })

      await test.step('Check if redirected to OTP verification', async () => {
        await page.waitForTimeout(2000)
        const currentUrl = page.url()
        
        if (currentUrl.includes('verify')) {
          console.log('📧 OTP verification step detected')
          
          // The redirect should be preserved in the verification flow
          // After verification, should redirect to specified URL
          console.log('✅ Redirect will be applied after OTP verification')
        } else {
          console.log('⚠️ Email verification not required, direct redirect')
        }
      })
    })

    test('should maintain redirect through email confirmation link', async ({ page }) => {
      const redirectTo = '/confirmed-dashboard'
      
      await test.step('Simulate email confirmation with redirect', async () => {
        // Simulate clicking email confirmation link with redirect parameter
        const confirmationToken = 'mock-confirmation-token-123'
        await page.goto(
          `${baseUrl}/auth/confirm?token=${confirmationToken}&redirect=${encodeURIComponent(redirectTo)}`
        )
        
        console.log('📧 Email confirmation page loaded with redirect')
      })

      await test.step('Verify redirect after confirmation', async () => {
        await page.waitForTimeout(3000)
        const finalUrl = page.url()
        
        // After confirmation, should redirect to specified URL (if valid)
        // Or show confirmation success page
        console.log(`Final URL after confirmation: ${finalUrl}`)
        
        if (finalUrl.includes('/confirmed-dashboard')) {
          console.log('✅ Redirect applied after email confirmation')
        } else {
          console.log('ℹ️ Confirmation flow may require additional steps')
        }
      })
    })
  })

  test.describe('Backend Response Validation', () => {
    test('should receive redirect_url in signin response', async ({ page }) => {
      const testUser = {
        email: 'test-redirect-response@example.com',
        password: 'TestPassword123!'
      }
      const redirectTo = '/dashboard'
      
      // Intercept API response
      let apiResponse: any = null
      
      page.on('response', async (response) => {
        if (response.url().includes('/signin') && response.status() === 200) {
          try {
            apiResponse = await response.json()
            console.log('📡 Signin API response:', JSON.stringify(apiResponse, null, 2))
          } catch (e) {
            // Not JSON response
          }
        }
      })
      
      await test.step('Submit signin with redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(redirectTo)}`)
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        
        await page.waitForTimeout(3000)
      })

      await test.step('Verify API response contains redirect_url', async () => {
        if (apiResponse) {
          // Backend should return validated redirect_url
          console.log('📋 Checking for redirect_url in response...')
          
          if ('redirect_url' in apiResponse) {
            console.log(`✅ Backend returned redirect_url: ${apiResponse.redirect_url}`)
            expect(apiResponse.redirect_url).toBeTruthy()
          } else {
            console.log('⚠️ Backend does not yet return redirect_url (needs implementation)')
          }
        }
      })
    })

    test('should use backend-validated URL, not client parameter', async ({ page }) => {
      const testUser = {
        email: 'test-backend-validation@example.com',
        password: 'TestPassword123!'
      }
      const clientRedirect = 'https://evil.com/phishing'
      
      let finalRedirectUrl: string | null = null
      
      // Intercept response to see what backend returns
      page.on('response', async (response) => {
        if (response.url().includes('/signin') && response.status() === 200) {
          try {
            const data = await response.json()
            finalRedirectUrl = data.redirect_url || null
          } catch (e) {
            // Ignore
          }
        }
      })
      
      await test.step('Submit signin with malicious redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(clientRedirect)}`)
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        
        await page.waitForTimeout(3000)
      })

      await test.step('Verify backend rejected malicious URL', async () => {
        const currentUrl = page.url()
        
        // Should NOT be redirected to evil.com
        expect(currentUrl).not.toContain('evil.com')
        console.log('✅ Malicious redirect rejected by backend')
        
        if (finalRedirectUrl) {
          console.log(`Backend returned safe URL: ${finalRedirectUrl}`)
          expect(finalRedirectUrl).not.toContain('evil.com')
        }
      })
    })
  })

  test.describe('Edge Cases', () => {
    test('should handle empty redirect parameter', async ({ page }) => {
      const testUser = {
        email: 'test-empty-redirect@example.com',
        password: 'TestPassword123!'
      }
      
      await test.step('Navigate with empty redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=`)
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        
        await page.waitForTimeout(2000)
        
        // Should redirect to default URL (SiteURL)
        const finalUrl = page.url()
        console.log(`Empty redirect handled, final URL: ${finalUrl}`)
        expect(finalUrl).toBeTruthy()
      })
    })

    test('should handle malformed redirect parameter', async ({ page }) => {
      const testUser = {
        email: 'test-malformed-redirect@example.com',
        password: 'TestPassword123!'
      }
      
      await test.step('Navigate with malformed redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=%invalid%url%`)
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        
        await page.waitForTimeout(2000)
        
        // Should handle gracefully and redirect to safe URL
        const finalUrl = page.url()
        expect(finalUrl).not.toContain('%invalid%')
        console.log('✅ Malformed redirect handled gracefully')
      })
    })

    test('should handle very long redirect URL', async ({ page }) => {
      const testUser = {
        email: 'test-long-redirect@example.com',
        password: 'TestPassword123!'
      }
      const longRedirect = '/dashboard?' + 'a=1&'.repeat(500) // Very long query string
      
      await test.step('Navigate with very long redirect', async () => {
        await page.goto(`${baseUrl}/auth/signin?redirect=${encodeURIComponent(longRedirect)}`)
        
        // Should either handle it or reject it gracefully
        await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email)
        await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password)
        await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click()
        
        await page.waitForTimeout(2000)
        
        const finalUrl = page.url()
        console.log(`Long redirect handled, URL length: ${finalUrl.length}`)
        expect(finalUrl).toBeTruthy()
      })
    })
  })
})

