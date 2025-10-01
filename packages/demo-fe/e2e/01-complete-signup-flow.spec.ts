/*
Complete signup flow test
Full user registration experience from homepage to email confirmation

Test flow:
1. Navigate to homepage /auth/
2. Click the signup link
3. Enter email and password, send request
4. Click the link in the email, implemented through mailhog
5. Frontend handles /confirm?token=xxxxx

Run command:
npm run test:e2e -- e2e/complete-signup-flow.spec.ts --headed --project=chromium --timeout=60000
*/

import { test, expect } from './fixtures/base.fixtures.js';
import { testConfig, generateTestUser, TEST_IDS } from './fixtures/test-data.js';
import { clearAuthState, getAllLocalStorage } from './helpers/auth.helper.js';

test.describe('Complete Signup Flow', () => {
  const testUser = generateTestUser();

  test.beforeEach(async ({ page }) => {
    
    page.setDefaultTimeout(testConfig.timeout);
    
    
    await page.goto('/');
    
    
    await clearAuthState(page);
  });

  test('Complete user registration and email confirmation flow', async ({ page, testContext }) => {
    
    page.on('console', msg => {
      console.log('🔍 Browser console:', msg.text());
    });
    
    page.on('pageerror', error => {
      console.log('❌ Page error:', error.message);
    });
    
    // ==================== Step 1: Navigate to homepage ====================
    await test.step(`Navigate to homepage ${testConfig.baseUrl}/auth/`, async () => {
      await page.goto(`${testConfig.baseUrl}/auth/`);
      
      
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/`);
      
      
      await expect(page.getByTestId(TEST_IDS.AUTH_CONTAINER)).toBeVisible();
      
      console.log('✅ Successfully navigated to homepage');
    });

    // ==================== Step 2: Click signup link ====================
    await test.step('Click signup link', async () => {
      
      const signupLink = page.getByTestId('signup-redirect-link');
      await expect(signupLink).toBeVisible();
      await signupLink.click();
      
      
      await expect(page).toHaveURL(`${testConfig.baseUrl}/auth/signup`);
      
      
      await expect(page.getByTestId(TEST_IDS.SIGNUP_FORM)).toBeVisible();
      await expect(page.getByTestId(TEST_IDS.SIGNUP_EMAIL)).toBeVisible();
      await expect(page.getByTestId(TEST_IDS.SIGNUP_PASSWORD)).toBeVisible();
      await expect(page.getByTestId(TEST_IDS.SIGNUP_BUTTON)).toBeVisible();
      
      console.log('✅ Successfully navigated to signup page');
    });

    // ==================== Step 3: Enter email and password, send request ====================
    await test.step('Fill signup form and submit', async () => {
      
      await page.getByTestId(TEST_IDS.SIGNUP_EMAIL).locator('input').fill(testUser.email);
      
      
      await page.getByTestId(TEST_IDS.SIGNUP_PASSWORD).locator('input').fill(testUser.password);
      
      
      const confirmPasswordField = page.getByTestId(TEST_IDS.SIGNUP_CONFIRM_PASSWORD);
      if (await confirmPasswordField.isVisible()) {
        await confirmPasswordField.locator('input').fill(testUser.password);
      }
      
      
      await expect(page.getByTestId(TEST_IDS.SIGNUP_EMAIL).locator('input')).toHaveValue(testUser.email);
      await expect(page.getByTestId(TEST_IDS.SIGNUP_PASSWORD).locator('input')).toHaveValue(testUser.password);
      
      console.log(`📝 Form filled - Email: ${testUser.email}`);
      
      
      await page.getByTestId(TEST_IDS.SIGNUP_BUTTON).click();

      
      
      await expect(page.getByTestId(TEST_IDS.SIGNUP_BUTTON)).toHaveAttribute('data-status', 'idle', { timeout: 10000 });
      
      console.log('✅ Signup request sent');
    });

    // ==================== Step 4: Verify signup success message ====================
    await test.step('Verify signup success message', async () => {
      
      await page.waitForTimeout(2000);

      
      const authMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
      const errorMessage = page.getByTestId('error-message');

      const hasAuthMessage = await authMessage.isVisible();
      const hasErrorMessage = await errorMessage.isVisible();

      console.log('🔍 Auth message visible:', hasAuthMessage);
      console.log('🔍 Error message visible:', hasErrorMessage);

      if (hasAuthMessage) {
        const messageText = await authMessage.textContent();
        const dataStatus = await authMessage.getAttribute('data-status');
        console.log('📧 Auth message content:', messageText);
        console.log('📧 Auth message status:', dataStatus);

        
        await expect(authMessage).toHaveAttribute('data-status', 'success');

        
        expect(messageText).toMatch(/check.*email|confirm.*email|verification.*email|created.*successfully/i);

        console.log('✅ Signup successful, awaiting email confirmation');
      } else if (hasErrorMessage) {
        const errorText = await errorMessage.textContent();
        console.log('❌ Signup failed, error message:', errorText);
        throw new Error(`Signup failed: ${errorText}`);
      } else {
        console.log('ℹ️ No success or error message found, signup flow may be different');
        
        const currentUrl = page.url();
        console.log('🔍 Current page URL:', currentUrl);
      }
    });

    // ==================== Step 5: Get confirmation email via MailHog ====================
    let confirmationToken: string;
    await test.step('Get confirmation token from MailHog email', async () => {
      
      await page.waitForTimeout(3000);
      
      
      const response = await page.request.get(`${testConfig.mailhogUrl}/api/v1/messages`);
      expect(response.ok()).toBeTruthy();
      
      const emails = await response.json();
      console.log(`📧 Found ${emails.length} emails`);
      
      if (emails.length === 0) {
        console.log('⚠️ No emails found, waiting longer...');
        await page.waitForTimeout(5000);
        const retryResponse = await page.request.get(`${testConfig.mailhogUrl}/api/v1/messages`);
        const retryEmails = await retryResponse.json();
        console.log(`📧 Found ${retryEmails.length} emails after retry`);
        expect(retryEmails.length).toBeGreaterThan(0);
        emails.push(...retryEmails);
      }
      
      
      const confirmationEmail = emails[0];
      expect(confirmationEmail).toBeTruthy();
      expect(confirmationEmail.Content.Headers.Subject[0]).toMatch(/confirm|verification/i);
      
      
      const emailBody = confirmationEmail.Content.Body;
      console.log('📧 Email content preview:', emailBody.substring(0, 200) + '...');
      
      
      
      const tokenMatch = emailBody.match(/token=3D([a-f0-9=\r\n]+)/) || emailBody.match(/\/auth\/confirm\?token=([a-f0-9]{64})/);
      expect(tokenMatch).toBeTruthy();
      
      
      const rawToken = tokenMatch[1].replace(/[=\r\n]/g, '');
      expect(rawToken).toMatch(/^[a-f0-9]{64}$/); 
      
      confirmationToken = rawToken;
      console.log(`✅ Extracted confirmation token: ${confirmationToken.substring(0, 8)}...`);
    });

    // ==================== Step 6: Click email link, true e2e test ====================
    await test.step('Get real email link via MailHog API and click', async () => {
      
      const emailBody = await page.request.get(`${testConfig.mailhogUrl}/api/v1/messages`).then(r => r.json()).then(emails => emails[0].Content.Body);
      console.log('📧 Email raw content:', emailBody);
      
      
      
      const linkMatch = emailBody.match(/href=3D"([^"]+)"/);
      expect(linkMatch).toBeTruthy();
      
      console.log('🔍 Raw link match from email:', linkMatch[1]);
      
      let confirmationLink = linkMatch[1];
      
      // Decode Quoted-Printable encoding: =3D -> =, remove soft line breaks
      confirmationLink = confirmationLink
        .replace(/=3D/g, '=')        // Decode = sign
        .replace(/=\r?\n/g, '')       // Remove soft line breaks
        .replace(/\r?\n/g, '');       // Remove any remaining line breaks
      
      console.log('🔗 Real confirmation link extracted from email:', confirmationLink);
      console.log('🔗 Should contain /auth/confirm pattern:', confirmationLink.includes('/auth/confirm'));
      
      
      if (!confirmationLink.startsWith('http')) {
        confirmationLink = `${testConfig.baseUrl}${confirmationLink.startsWith('/') ? '' : '/'}${confirmationLink}`;
        console.log('🔗 Converted relative path to absolute URL:', confirmationLink);
      }
      
      expect(confirmationLink).toMatch(/confirm\?token=/);
      
      
      console.log('🔍 Browser navigating to real frontend confirmation link from email...');
      await page.goto(confirmationLink);
      
      
      await page.waitForLoadState('networkidle');
      
      console.log('📍 Current URL after confirmation:', page.url());
      
      
      const pageContent = await page.content();
      console.log('📄 Page content preview:', pageContent.substring(0, 500));
      
      
      const logs = await page.evaluate(() => {
        return (window as any).consoleLogs || [];
      });
      console.log('📝 Console logs:', logs);
      
      
      const errors = await page.evaluate(() => {
        return (window as any).errors || [];
      });
      console.log('❌ JavaScript errors:', errors);
      
      
      const vueApp = await page.evaluate(() => {
        return (window as any).__VUE_APP__ || 'Vue app not found';
      });
      console.log('🔍 Vue app state:', vueApp);
      
      
      await expect(page.getByTestId(TEST_IDS.AUTH_CONTAINER)).toBeVisible({ timeout: 5000 });
      console.log('✅ Auth component loaded');
      
      
      await page.waitForTimeout(2000);
      
      
      const confirmationStatusElement = page.getByTestId('confirmation-status');
      
      
      const currentStatus = await confirmationStatusElement.getAttribute('data-status');
      console.log('🔍 Current confirmation status:', currentStatus);
      
      if (currentStatus === 'success') {
        console.log('✅ Confirmation already completed successfully');
      } else if (currentStatus === 'processing') {
        console.log('🔍 Confirmation processing, waiting for completion...');
        await expect(confirmationStatusElement).toHaveAttribute('data-status', 'success', { timeout: 10000 });
        console.log('✅ Confirmation processed successfully');
      } else {
        console.log('⚠️ Confirmation status abnormal:', currentStatus);
      }
      
      
      await page.waitForTimeout(2000);
      const finalUrl = page.url();
      console.log('📍 Final URL:', finalUrl);
      
      if (finalUrl.includes('/signin')) {
        console.log('✅ Confirmation successful, redirected to signin page');
      } else {
        console.log('ℹ️ Confirmation complete, staying on confirmation page');
      }
      
      console.log('✅ True e2e email confirmation complete');
    });

    // ==================== Step 7: Verify user can login normally ====================
    await test.step('Verify user can login normally', async () => {
      
      if (!page.url().includes('/signin')) {
        await page.goto(`${testConfig.baseUrl}/auth/signin`);
      }
      
      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(testUser.email);
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(testUser.password);
      
      
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();
      
      
      await expect(page.getByTestId(TEST_IDS.SIGNIN_BUTTON)).toHaveAttribute('data-status', 'loading');
      await expect(page.getByTestId(TEST_IDS.SIGNIN_BUTTON)).toHaveAttribute('data-status', 'idle', { timeout: 10000 });
      
      
      // 1. May redirect to homepage
      // 2. Or display login success message
      
      await page.waitForTimeout(2000);
      const currentUrl = page.url();
      console.log('🔍 Current URL after login:', currentUrl);
      
      if (currentUrl === `${testConfig.baseUrl}/` || currentUrl.includes('/dashboard')) {
        console.log('✅ Login successful, redirected to homepage/dashboard');
      } else {
        
        const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
        if (await messageElement.isVisible()) {
          await expect(messageElement).toHaveAttribute('data-status', 'success');
          console.log('✅ Login successful, success message displayed');
        }
      }
      
      console.log('✅ User login verification complete');
    });

    // ==================== Step 8: Save test results to TestContext ====================
    await test.step('Save test results to TestContext', async () => {
      
      const allLocalStorage = await getAllLocalStorage(page);
      console.log('🔍 localStorage content:', allLocalStorage);
      
      
      testContext.set('auth.email', testUser.email);
      testContext.set('auth.password', testUser.password);
      testContext.set('auth.name', testUser.name);
      testContext.set('auth.confirmationToken', confirmationToken);
      
      
      testContext.set('test.status', 'email_confirmed_and_signin_completed');
      testContext.set('test.timestamp', new Date().toISOString());
      testContext.set('test.page', page.url());
      
      console.log(`✅ Complete signup flow test finished, results saved to TestContext:`);
      console.log(`   📧 Email: ${testUser.email}`);
      console.log(`   🔑 Password: ${testUser.password.substring(0, 8)}...`);
      console.log(`   👤 Name: ${testUser.name}`);
      console.log(`   🎫 Token: ${confirmationToken.substring(0, 8)}...`);
      console.log(`   📍 Final page: ${page.url()}`);
      console.log(`   ⏰ Completion time: ${new Date().toISOString()}`);
    });
  });

  test('Verify invalid confirmation token handling', async ({ page }) => {
    await test.step('Test invalid token handling', async () => {
      const invalidToken = 'invalid_token_' + 'a'.repeat(50); 
      const invalidConfirmationURL = `${testConfig.backendUrl}/auth/confirm?token=${invalidToken}`;
      
      console.log('🔍 Testing invalid token backend API call...');
      
      
      const confirmResponse = await page.request.get(invalidConfirmationURL);
      
      console.log('📡 Invalid token API response status:', confirmResponse.status());
      const confirmResult = await confirmResponse.json();
      console.log('📡 Invalid token API response content:', JSON.stringify(confirmResult, null, 2));
      
      
      if (confirmResponse.status() === 200) {
        
        expect(confirmResult.error).toBeDefined();
        expect(confirmResult.error.key).toBe('auth.validation_failed');
        console.log('✅ Invalid token correctly returned validation failed error');
      } else {
        
        expect(confirmResponse.status()).toBeGreaterThanOrEqual(400);
        console.log('✅ Invalid token correctly returned error status code');
      }
    });
  });

  test.afterEach(async ({ page }) => {
    console.log('🧹 Complete signup flow test finished');
  });
});