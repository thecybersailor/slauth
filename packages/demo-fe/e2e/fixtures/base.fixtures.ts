import { test as base } from '@playwright/test';
import { createPlaywrightTestWithContext } from '@carthooks/test-context';

// Create test context with configuration
const { testContext, extend } = createPlaywrightTestWithContext({
  contextPath: '.test-context/context.json',
  autoSave: true
});

// Extend Playwright test with testContext fixture
export const test = extend(base);
export { expect } from '@playwright/test';
