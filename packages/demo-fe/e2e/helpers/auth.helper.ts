import { Page } from '@playwright/test';
import { AuthState } from '../fixtures/test-data';

/**
 * Authentication helper functions for e2e tests
 */

/**
 * Set authentication state in localStorage
 */
export async function setAuthState(page: Page, authState: AuthState): Promise<void> {
  await page.evaluate(({ token, tenantId }) => {
    const userData = {
      token,
      tenant: {
        ID: tenantId
      }
    };
    localStorage.setItem('user', JSON.stringify(userData));
  }, authState);
}

/**
 * Clear authentication state from localStorage
 */
export async function clearAuthState(page: Page): Promise<void> {
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
}

/**
 * Get authentication state from localStorage
 */
export async function getAuthState(page: Page): Promise<AuthState | null> {
  return await page.evaluate(() => {
    try {
      const userStr = localStorage.getItem('user');
      if (userStr) {
        const userData = JSON.parse(userStr);
        return {
          token: userData.token,
          tenantId: userData.tenant?.ID
        };
      }
    } catch (e) {
      console.log('Failed to parse user data:', e);
    }
    return null;
  });
}

/**
 * Check if user is authenticated
 */
export async function isAuthenticated(page: Page): Promise<boolean> {
  const authState = await getAuthState(page);
  return authState !== null && !!authState.token;
}

/**
 * Wait for authentication state to be set
 */
export async function waitForAuthState(page: Page, timeout: number = 10000): Promise<AuthState> {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    const authState = await getAuthState(page);
    if (authState && authState.token) {
      return authState;
    }
    await page.waitForTimeout(100);
  }
  
  throw new Error(`Authentication state not found within ${timeout}ms`);
}

/**
 * Extract app ID from current URL
 */
export function extractAppIdFromUrl(url: string): string | null {
  const match = url.match(/\/app\/([a-zA-Z0-9]+)\//);
  return match ? match[1] : null;
}

/**
 * Extract tenant ID from localStorage
 */
export async function extractTenantId(page: Page): Promise<string | number | null> {
  const authState = await getAuthState(page);
  return authState?.tenantId || null;
}

/**
 * Get all localStorage content for debugging
 */
export async function getAllLocalStorage(page: Page): Promise<Record<string, string | null>> {
  return await page.evaluate(() => {
    const items: Record<string, string | null> = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) {
        items[key] = localStorage.getItem(key);
      }
    }
    return items;
  });
}
