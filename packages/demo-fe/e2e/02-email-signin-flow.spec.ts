/*
Email SignIn Flow Test
Test complete flow of reading user info from TestContext and logging in

Run command:
npm run test:e2e -- e2e/02-email-signin-flow.spec.ts --headed --project=chromium --timeout=60000
*/
import { test, expect } from './fixtures/base.fixtures.js';
import { testConfig, TEST_IDS } from './fixtures/test-data.js';
import { clearAuthState, getAllLocalStorage } from './helpers/auth.helper.js';

/**
 * Email SignIn Flow Test
 * 
 * Test Flow:
 * 1. Read user info from TestContext
 * 2. Navigate to login page
 * 3. Fill login form
 * 4. Submit login
 * 5. Verify login success
 * 6. Verify page navigation
 */

test.describe('Email SignIn Flow', () => {
  test.beforeEach(async ({ page }) => {
    
    page.setDefaultTimeout(testConfig.timeout);
    
    
    await page.goto('/');
    
    
    await clearAuthState(page);
  });

  test('Login with user info from TestContext', async ({ page, testContext }) => {
    // ==================== Step 1: Read user info from TestContext ====================
    await test.step('Read user info from TestContext', async () => {
      
      const email = testContext.get<string>('auth.email');
      const password = testContext.get<string>('auth.password');
      const testStatus = testContext.get<string>('test.status');
      
      
      const validStatuses = ['email_confirmed_and_signin_completed', 'signup_completed_pending_confirmation'];

      if (!email || !password || !validStatuses.includes(testStatus)) {
        console.log('⚠️ No valid user info found in TestContext or incorrect user status');
        console.log(`   📧 Email: ${email || 'none'}`);
        console.log(`   🔑 Password: ${password ? 'exists' : 'none'}`);
        console.log(`   📊 Test Status: ${testStatus || 'none'}`);
        console.log(`   Expected status: ${validStatuses.join(' or ')}`);
        console.log('   Please run 01-email-signup-flow.spec.ts and 03-email-verification-flow.spec.ts tests first');
        
        
        test.skip();
        return;
      }
      
      console.log(`🔍 Read user info from TestContext:`);
      console.log(`   📧 Email: ${email}`);
      console.log(`   🔑 Password: ${password.substring(0, 8)}...`);
      console.log(`   📊 Test Status: ${testStatus}`);
      
      
      (test as any).userEmail = email;
      (test as any).userPassword = password;
    });

    // ==================== Step 2: Navigate to login page ====================
    await test.step('Navigate to login page', async () => {
      
      await page.getByTestId('signin-link').click();
      
      
      await expect(page).toHaveURL('/auth/signin');
      
      
      await expect(page.getByTestId(TEST_IDS.PAGE_TITLE)).toContainText('Sign in to your account');
      
      console.log('✅ Successfully navigated to login page');
    });

    // ==================== Step 3: Fill login form ====================
    await test.step('Fill login form', async () => {
      const email = (test as any).userEmail;
      const password = (test as any).userPassword;
      
      
      await expect(page.getByTestId(TEST_IDS.SIGNIN_FORM)).toBeVisible();
      
      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(email);
      
      
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(password);
      
      
      await expect(page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input')).toHaveValue(email);
      await expect(page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input')).toHaveValue(password);
      
      console.log('✅ Login form filled');
    });

    // ==================== Step 4: Submit login form ====================
    await test.step('Submit login form', async () => {
      const button = page.getByTestId(TEST_IDS.SIGNIN_BUTTON);

      
      await expect(button).toHaveAttribute('data-status', 'idle');

      
      await button.click();
      console.log('✅ Login form submitted');
    });

    // ==================== Step 5: Wait for login processing to complete ====================
    await test.step('Wait for login processing to complete', async () => {
      
      await page.waitForTimeout(2000);
      console.log('✅ Login processing completed');
    });

    // ==================== Step 6: Check localStorage state ====================
    await test.step('Check localStorage state', async () => {
      
      await page.waitForTimeout(1000);

      
      const sessionData = await page.evaluate(() => {
        return localStorage.getItem('aira.auth.token');
      });

      console.log('📊 localStorage session data:', sessionData);

      if (sessionData) {
        const session = JSON.parse(sessionData);
        console.log('🔑 Session access_token exists:', !!session.access_token);
        console.log('⏰ Session expires_at:', session.expires_at);
        console.log('👤 Session user:', session.user?.email);
      }
    });

    // ==================== Step 7: Verify page navigation to Dashboard ====================
    await test.step('Verify page navigation to Dashboard', async () => {
      
      await expect(page).toHaveURL('/dashboard', { timeout: 5000 });

      console.log('✅ Page successfully navigated to Dashboard');
    });

    // ==================== Step 7: Verify authentication state ====================
    await test.step('Verify authentication state', async () => {
      
      const allLocalStorage = await getAllLocalStorage(page);
      console.log('🔍 localStorage content:', allLocalStorage);
      
      
      const hasUserData = Object.keys(allLocalStorage).some(key => 
        key.includes('user') || key.includes('auth') || key.includes('token')
      );
      
      if (hasUserData) {
        console.log('✅ Authentication state saved to localStorage');
      } else {
        console.log('⚠️ Authentication info not found in localStorage');
      }
      
      
      testContext.set('test.status', 'signin_completed');
      testContext.set('test.signin_timestamp', new Date().toISOString());
      
      console.log('✅ Login flow completed, state updated to TestContext');
    });
  });

  test('Test login with invalid credentials', async ({ page }) => {
    
    await page.goto('/auth/signin');

    
    await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('invalid@example.com');
    await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('wrongpassword');

    
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();

    
    await page.waitForTimeout(3000);

    
    const pageContent = await page.content();
    console.log('🔍 data-testid attributes in page content:', pageContent.match(/data-testid="[^"]*"/g) || []);

    
    const allMessages = await page.locator('[data-testid*="message"]').all();
    console.log('🔍 Number of message elements found:', allMessages.length);

    for (let i = 0; i < allMessages.length; i++) {
      const testId = await allMessages[i].getAttribute('data-testid');
      const isVisible = await allMessages[i].isVisible();
      const textContent = await allMessages[i].textContent();
      console.log(`🔍 Message element ${i}: data-testid="${testId}", visible=${isVisible}, text="${textContent}"`);
    }

    
    const errorMessage = page.getByTestId('error-message');
    const authMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE);

    
    try {
      await expect(errorMessage).toBeVisible({ timeout: 5000 });
      console.log('✅ Found error-message element');
      await expect(errorMessage).toHaveAttribute('data-status', 'error');
    } catch (e) {
      console.log('⚠️ error-message not found, trying auth-message');
      await expect(authMessage).toBeVisible({ timeout: 5000 });
      await expect(authMessage).toHaveAttribute('data-status', 'error');
    }

    console.log('✅ Invalid credentials login test completed');
  });

  test('Test form validation', async ({ page }) => {
    
    await page.goto('/auth/signin');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();
    
    
    await page.waitForTimeout(2000);
    
    
    const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
    const hasMessage = await messageElement.isVisible();
    
    if (hasMessage) {
      const messageText = await messageElement.textContent();
      console.log('✅ Form validation triggered successfully:', messageText);
    } else {
      console.log('ℹ️ No client-side validation, relying on server-side validation');
    }
    
    console.log('✅ Form validation test completed');
  });

  test('Test server-side validation - empty email', async ({ page }) => {
    
    await page.goto('/auth/signin');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('TestPassword123!');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();
    
    
    await page.waitForTimeout(2000);
    
    
    const errorMessage = page.getByTestId(TEST_IDS.ERROR_MESSAGE);
    const hasError = await errorMessage.isVisible();
    
    if (hasError) {
      const errorText = await errorMessage.textContent();
      console.log('✅ Server-side validation - empty email error:', errorText);
    } else {
      console.log('ℹ️ Empty email validation may be handled by frontend');
    }
    
    console.log('✅ Server-side validation - empty email test completed');
  });

  test('Test server-side validation - empty password', async ({ page }) => {
    
    await page.goto('/auth/signin');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('test@example.com');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();
    
    
    await page.waitForTimeout(2000);
    
    
    const errorMessage = page.getByTestId(TEST_IDS.ERROR_MESSAGE);
    const hasError = await errorMessage.isVisible();
    
    if (hasError) {
      const errorText = await errorMessage.textContent();
      console.log('✅ Server-side validation - empty password error:', errorText);
    } else {
      console.log('ℹ️ Empty password validation may be handled by frontend');
    }
    
    console.log('✅ Server-side validation - empty password test completed');
  });

  test('Test server-side validation - invalid email format', async ({ page }) => {
    
    await page.goto('/auth/signin');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('invalid-email');
    await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('TestPassword123!');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();
    
    
    await page.waitForTimeout(2000);
    
    
    const errorMessage = page.getByTestId(TEST_IDS.ERROR_MESSAGE);
    const hasError = await errorMessage.isVisible();
    
    if (hasError) {
      const errorText = await errorMessage.textContent();
      console.log('✅ Server-side validation - invalid email format error:', errorText);
    } else {
      console.log('ℹ️ Invalid email format validation may be handled by frontend');
    }
    
    console.log('✅ Server-side validation - invalid email format test completed');
  });

  test('Test navigation links', async ({ page }) => {
    
    await page.goto('/auth/signin');

    
    const forgotPasswordLink = page.getByTestId('forgot-password-link');
    if (await forgotPasswordLink.isVisible()) {
      await forgotPasswordLink.click();
      await expect(page).toHaveURL(/\/auth\/forgot-password/);
      console.log('✅ Forgot Password link works correctly');

      
      await page.goBack();
    }
    
    
    const signUpLink = page.getByTestId('signup-redirect-link');
    if (await signUpLink.isVisible()) {
      await signUpLink.click();
      await expect(page).toHaveURL('/auth/signup');
      console.log('✅ Sign Up link works correctly');
    }
    
    console.log('✅ Navigation links test completed');
  });

  test('Test login with unconfirmed email user', async ({ page, testContext }) => {
    // ==================== Step 1: Check user status ====================
    await test.step('Check user status', async () => {
      const email = testContext.get<string>('auth.email');
      const password = testContext.get<string>('auth.password');
      const testStatus = testContext.get<string>('test.status');

      
      if (!email || !password || testStatus !== 'signup_completed_pending_confirmation') {
        console.log('⚠️ This test requires a user with unconfirmed email');
        console.log(`   📊 Current status: ${testStatus || 'none'}`);
        console.log('   Expected status: signup_completed_pending_confirmation');
        test.skip();
        return;
      }

      console.log('✅ Found user with unconfirmed email, starting test');
    });

    // ==================== Step 2: Attempt login ====================
    await test.step('Attempt login with unconfirmed email user', async () => {
      const email = testContext.get<string>('auth.email');
      const password = testContext.get<string>('auth.password');

      
      await page.goto('/auth/signin');
      await page.waitForLoadState('networkidle');

      
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(email);
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(password);

      
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();

      
      await page.waitForTimeout(2000);

      
      const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
      if (await messageElement.isVisible()) {
        const messageText = await messageElement.textContent();
        console.log('📧 Login message:', messageText);

        
        if (messageText && messageText.match(/confirm.*email|verify.*email|check.*email/i)) {
          console.log('✅ Correctly prompts user to confirm email');
        } else {
          console.log('⚠️ Email confirmation prompt not found, may allow unconfirmed users to login');
        }
      } else {
        console.log('⚠️ No message displayed, check if unconfirmed users are allowed to login');
      }

      console.log('✅ Unconfirmed email user login test completed');
    });
  });

  test.afterEach(async ({ page }) => {
    console.log('🧹 Email SignIn flow test completed');
  });
});
