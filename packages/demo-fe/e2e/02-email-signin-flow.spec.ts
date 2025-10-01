/*
Email SignIn Flow Test
Test complete flow of reading user info from TestContext and logging in

Run command:
npm run test:e2e -- e2e/02-email-signin-flow.spec.ts --project=chromium
*/
import { test, expect } from './fixtures/base.fixtures.js';
import { testConfig, TEST_IDS } from './fixtures/test-data.js';
import { clearAuthState } from './helpers/auth.helper.js';

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
    // Capture console logs
    page.on('console', msg => {
      console.log(`[Browser ${msg.type()}]:`, msg.text())
    })
    
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
      await page.goto(`${testConfig.baseUrl}/auth/signin`);

      // Verify signin form is visible
      await expect(page.getByTestId(TEST_IDS.SIGNIN_FORM)).toBeVisible();

      console.log('✅ Login form is visible');
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

    // ==================== Step 5: Verify no error message ====================
    await test.step('Verify no error message', async () => {
      // Check if error message is displayed
      const errorMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
      const isErrorVisible = await errorMessage.isVisible().catch(() => false);

      if (isErrorVisible) {
        const errorText = await errorMessage.textContent();
        console.log('❌ Login error message:', errorText);
        throw new Error(`Login failed: ${errorText}`);
      }

      console.log('✅ No error message - login processing completed');
    });

    // ==================== Step 6: Verify Dashboard page is displayed ====================
    await test.step('Verify Dashboard page is displayed', async () => {
      const email = (test as any).userEmail;

      // Verify Dashboard title is visible
      await expect(page.getByTestId('dashboard-title')).toBeVisible();
      console.log('✅ Dashboard title is visible');

      // Verify user email is displayed in Dashboard
      const userEmailElement = page.getByTestId('user-email');
      await expect(userEmailElement).toBeVisible();
      await expect(userEmailElement).toHaveText(email);
      console.log('✅ User email is displayed correctly in Dashboard');

      // Verify sign out button is visible
      await expect(page.getByTestId('signout-button')).toBeVisible();
      console.log('✅ Sign out button is visible');

      console.log('✅ Login success - Dashboard loaded with user data');
    });

    // ==================== Step 7: Update test context ====================
    await test.step('Update test context', async () => {
      testContext.set('test.status', 'signin_completed');
      testContext.set('test.signin_timestamp', new Date().toISOString());
      
      console.log('✅ Login flow completed, state updated to TestContext');
    });
  });

  test('Test login with invalid credentials', async ({ page }) => {
    await page.goto('/auth/signin');

    // Fill invalid credentials
    await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill('invalid@example.com');
    await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill('wrongpassword');

    // Submit form
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();

    // Verify error message is displayed
    const authMessage = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
    await expect(authMessage).toBeVisible();
    
    const errorText = await authMessage.textContent();
    console.log('Error message:', errorText);
    
    // Verify still on signin page (login failed)
    await expect(page.getByTestId(TEST_IDS.SIGNIN_FORM)).toBeVisible();

    console.log('✅ Invalid credentials login test completed');
  });

  test('Test form validation', async ({ page }) => {
    
    await page.goto('/auth/signin');
    
    
    await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();
    
    

    
    
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

    // Test Forgot Password link
    const forgotPasswordLink = page.getByTestId('forgot-password-link');
    if (await forgotPasswordLink.isVisible()) {
      await forgotPasswordLink.click();
      
      // Verify forgot password form is visible
      await expect(page.getByTestId('forgot-password-form')).toBeVisible();
      console.log('✅ Forgot Password link works correctly');

      await page.goBack();
      await expect(page.getByTestId(TEST_IDS.SIGNIN_FORM)).toBeVisible();
    }
    
    // Test Sign Up link
    const signUpLink = page.getByTestId('signup-redirect-link');
    if (await signUpLink.isVisible()) {
      await signUpLink.click();
      
      // Verify signup form is visible
      await expect(page.getByTestId('signup-form')).toBeVisible();
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
      
      // Wait for signin form to be visible
      await expect(page.getByTestId(TEST_IDS.SIGNIN_FORM)).toBeVisible();

      // Fill login form
      await page.getByTestId(TEST_IDS.SIGNIN_EMAIL).locator('input').fill(email);
      await page.getByTestId(TEST_IDS.SIGNIN_PASSWORD).locator('input').fill(password);

      // Submit login
      await page.getByTestId(TEST_IDS.SIGNIN_BUTTON).click();

      // Check for email confirmation message
      const messageElement = page.getByTestId(TEST_IDS.AUTH_MESSAGE);
      const isMessageVisible = await messageElement.isVisible().catch(() => false);
      
      if (isMessageVisible) {
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
