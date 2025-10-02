import { test, expect } from '@playwright/test'

test.describe('Mock OAuth Flow', () => {
  test('should complete mock OAuth sign in flow', async ({ page }) => {
    await page.goto('http://localhost:5180/auth/')
    await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('oauth-button-mock')).toBeVisible()
    await page.getByTestId('oauth-button-mock').click()
    
    await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
    await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('mock-oauth-title')).toBeVisible()
    await expect(page.getByTestId('mock-oauth-user-select')).toBeVisible()
    await page.getByTestId('mock-oauth-user-select').selectOption('user1')
    
    await expect(page.getByTestId('mock-oauth-approve')).toBeVisible()
    await page.getByTestId('mock-oauth-approve').click()
    
    await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15000 })
    await expect(page.getByTestId('auth-container')).toHaveAttribute('data-status', 'authenticated')
    await expect(page.getByTestId('user-email')).toBeVisible()
  })

  test('should handle mock OAuth denial', async ({ page }) => {
    await page.goto('http://localhost:5180/auth/')
    await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('oauth-button-mock')).toBeVisible()
    await page.getByTestId('oauth-button-mock').click()
    
    await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
    await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('mock-oauth-deny')).toBeVisible()
    await page.getByTestId('mock-oauth-deny').click()
    
    await expect(page.getByTestId('signin-form')).toBeVisible()
    await expect(page.getByTestId('auth-container')).toHaveAttribute('data-status', 'sign_in')
  })

  test('should allow selecting different mock users', async ({ page }) => {
    const testUsers = ['user1', 'admin']

    for (const user of testUsers) {
      await page.goto('http://localhost:5180/auth/')
      await page.waitForLoadState('networkidle')
      
      await expect(page.getByTestId('oauth-button-mock')).toBeVisible()
      await page.getByTestId('oauth-button-mock').click()
      
      await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
      await page.waitForLoadState('networkidle')
      
      await page.getByTestId('mock-oauth-user-select').selectOption(user)
      await page.getByTestId('mock-oauth-approve').click()
      
      await expect(page.getByTestId('dashboard-page')).toBeVisible({ timeout: 15000 })
      await expect(page.getByTestId('auth-container')).toHaveAttribute('data-status', 'authenticated')
      
      await page.goto('http://localhost:5180/auth/')
      await page.waitForLoadState('networkidle')
      
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
    
    await page.goto('http://localhost:5180/auth/')
    await page.waitForLoadState('networkidle')
    
    await expect(page.getByTestId('oauth-button-mock')).toBeVisible()
    await page.getByTestId('oauth-button-mock').click()
    
    await page.waitForURL('**/mock-oauth/authorize*', { timeout: 10000 })
    await page.waitForLoadState('networkidle')
    
    await page.getByTestId('mock-oauth-user-select').selectOption('user1')
    await page.getByTestId('mock-oauth-approve').click()
    
    await expect(page.getByTestId('auth-callback-loading')).toBeVisible({ timeout: 5000 })
    
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
    
    const authContainer = page.getByTestId('auth-container')
    const status = await authContainer.getAttribute('data-status')
    
    console.log('Auth Status:', status)
    
    if (status === 'callback') {
      console.log('*** BUG REPRODUCED: OAuth callback stuck ***')
    }
    
    expect(authContainer).toHaveAttribute('data-status', 'callback')
  })
})
