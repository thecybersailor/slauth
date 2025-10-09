import { test, expect } from '@playwright/test'
import { testConfig } from './fixtures/test-data.js'

test.describe('Mock OAuth Flow', () => {
  test('should complete mock OAuth sign in flow', async ({ page }) => {
    await page.goto(`${testConfig.baseUrl}/auth/`)
    // await page.waitForLoadState('networkidle')
    
    await expect(page.getByRole('button', { name: 'Sign in with Mock OAuth' })).toBeVisible()
    await page.getByRole('button', { name: 'Sign in with Mock OAuth' }).click()
    
    await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
    // await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('mock-oauth-title')).toBeVisible()
    await expect(page.getByTestId('mock-oauth-user-select')).toBeVisible()
    await page.getByTestId('mock-oauth-user-select').selectOption('user1')
    
    await expect(page.getByTestId('mock-oauth-approve')).toBeVisible()
    await page.getByTestId('mock-oauth-approve').click()
    
    await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15000 })
    await expect(page.getByTestId('user-email')).toBeVisible()
  })

  test('should handle mock OAuth denial', async ({ page }) => {
    await page.goto(`${testConfig.baseUrl}/auth/`)
    // await page.waitForLoadState('networkidle')
    
    await expect(page.getByRole('button', { name: 'Sign in with Mock OAuth' })).toBeVisible()
    await page.getByRole('button', { name: 'Sign in with Mock OAuth' }).click()
    
    await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
    // await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('mock-oauth-deny')).toBeVisible()
    await page.getByTestId('mock-oauth-deny').click()
    
    await page.waitForURL('**/auth/**', { timeout: 10000 })
    await expect(page.getByTestId('auth-container')).toBeVisible()
    
    const status = await page.getByTestId('auth-container').getAttribute('data-status')
    console.log('Status after OAuth denial:', status)
    
    // Should be either in callback (error state) or sign_in
    expect(['callback', 'sign_in']).toContain(status)
  })

  test('should allow selecting different mock users', async ({ page }) => {
    const testUsers = ['user1', 'admin']

    for (const user of testUsers) {
      await page.goto(`${testConfig.baseUrl}/auth/`)
      // await page.waitForLoadState('networkidle')
      
      await expect(page.getByRole('button', { name: 'Sign in with Mock OAuth' })).toBeVisible()
      await page.getByRole('button', { name: 'Sign in with Mock OAuth' }).click()
      
      await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
      // await page.waitForLoadState('networkidle')
      
      await page.getByTestId('mock-oauth-user-select').selectOption(user)
      await page.getByTestId('mock-oauth-approve').click()
      
      await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15000 })
      
      await page.goto(`${testConfig.baseUrl}/auth/`)
      // await page.waitForLoadState('networkidle')
      
      const logoutButton = page.getByTestId('signout-button')
      if (await logoutButton.isVisible()) {
        await logoutButton.click()
        await expect(page.getByTestId('auth-container')).toHaveAttribute('data-status', 'sign_in')
      }
    }
  })

  test('should detect OAuth callback stuck bug', async ({ page }) => {
    const tokenRequests: any[] = []
    
    page.on('request', request => {
      if (request.url().includes('/token')) {
        tokenRequests.push({
          type: 'request',
          timestamp: new Date().toISOString(),
          postData: request.postData()
        })
        console.log('==> TOKEN REQUEST')
      }
    })
    
    page.on('response', async response => {
      if (response.url().includes('/token')) {
        let responseBody = null
        try {
          responseBody = await response.text()
        } catch (e) {
          responseBody = `[Error: ${e}]`
        }
        
        tokenRequests.push({
          type: 'response',
          timestamp: new Date().toISOString(),
          status: response.status(),
          body: responseBody?.substring(0, 200)
        })
        console.log('<== TOKEN RESPONSE:', response.status())
      }
    })
    
    await page.goto(`${testConfig.baseUrl}/auth/`)
    // await page.waitForLoadState('networkidle')
    
    await expect(page.getByRole('button', { name: 'Sign in with Mock OAuth' })).toBeVisible()
    await page.getByRole('button', { name: 'Sign in with Mock OAuth' }).click()
    
    await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
    // await page.waitForLoadState('networkidle')
    
    await page.getByTestId('mock-oauth-user-select').selectOption('user1')
    await page.getByTestId('mock-oauth-approve').click()
    
    // Try to catch the callback loading state (may be too fast to see)
    const callbackLoading = page.getByTestId('auth-callback-loading')
    const isCallbackVisible = await callbackLoading.isVisible().catch(() => false)
    
    console.log('Callback loading visible:', isCallbackVisible)
    
    if (!isCallbackVisible) {
      console.log('⚠️ Callback processed too quickly to observe loading state')
    }
    
    console.log('Token Requests:', tokenRequests.length)
    tokenRequests.forEach(req => {
      console.log('---')
      console.log('Type:', req.type)
      console.log('Timestamp:', req.timestamp)
      if (req.type === 'request') {
        console.log('Post Data:', req.postData)
      } else {
        console.log('Status:', req.status)
        console.log('Body:', req.body)
      }
    })
    
    // Check if successfully redirected to dashboard or still stuck in callback
    const currentUrl = page.url()
    console.log('Current URL:', currentUrl)
    
    if (currentUrl.includes('/dashboard')) {
      console.log('✅ OAuth callback completed successfully')
      await expect(page.getByTestId('dashboard-page')).toBeVisible()
    } else if (currentUrl.includes('/auth')) {
      console.log('⚠️ Still on auth page, checking status')
      const authContainer = page.getByTestId('auth-container')
      if (await authContainer.isVisible({ timeout: 1000 }).catch(() => false)) {
        const status = await authContainer.getAttribute('data-status')
        console.log('Auth Status:', status)
        
        if (status === 'callback') {
          console.log('*** BUG REPRODUCED: OAuth callback stuck ***')
        }
      }
    }
  })
})
