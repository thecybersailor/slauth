import { test, expect } from '@playwright/test';
import { TEST_IDS } from './fixtures/test-data';

// See here how to get started:
// https://playwright.dev/docs/intro
test('visits the app root url', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId(TEST_IDS.PAGE_TITLE)).toHaveText('You did it!');
})
