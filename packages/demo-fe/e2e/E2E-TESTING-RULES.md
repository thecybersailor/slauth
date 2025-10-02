# E2E Testing Rules

## Core Principles

### 1. No waitForTimeout
**Never use `page.waitForTimeout()` or `waitForTimeout()` in tests.**

**Why:** Arbitrary timeouts make tests flaky and slow. Tests should wait for explicit conditions.

**Instead:**
- Use `page.waitForSelector()` with timeout
- Use `expect().toBeVisible()` which waits automatically
- Use state attributes like `data-status`

**Bad:**
```typescript
await page.waitForTimeout(5000) // ❌
```

**Good:**
```typescript
await expect(page.getByTestId('submit-button')).toBeVisible() // ✅
await expect(page.getByTestId('status-indicator')).toHaveAttribute('data-status', 'success') // ✅
```

---

### 2. Explicit Success Required
**If success is not explicitly verified, the test must fail.**

Tests must have clear assertions that verify the expected outcome. Implicit success (like "no error occurred") is not acceptable.

**Bad:**
```typescript
await page.click('[data-testid="submit"]')
// ❌ No verification of what happened
```

**Good:**
```typescript
await page.getByTestId('submit').click()
await expect(page.getByTestId('success-message')).toBeVisible() // ✅
await expect(page.getByTestId('user-email')).toContainText('test@example.com') // ✅
```

---

### 3. Use data-testid for All Locators
**Only use `page.getByTestId()` for element selection.**

**Why:** 
- More stable than CSS selectors or text content
- Makes tests resilient to UI changes
- Clear contract between tests and components

**Component Requirements:**
- Add `data-testid` to all interactive elements
- Add `data-status` for state-dependent elements

**Bad:**
```typescript
page.locator('button.submit-button') // ❌
page.locator('text=Sign In') // ❌
page.locator('[type="email"]') // ❌
```

**Good:**
```typescript
page.getByTestId('submit-button') // ✅
page.getByTestId('signin-form') // ✅
page.getByTestId('email-input') // ✅
```

---

### 4. No Direct State Inspection
**Do not inspect localStorage, sessionStorage, cookies, or URL directly.**

**Why:** Tests should verify user-visible behavior, not implementation details.

**Bad:**
```typescript
const localStorage = await page.evaluate(() => localStorage.getItem('session')) // ❌
expect(page.url()).toContain('/dashboard') // ❌
```

**Good:**
```typescript
await expect(page.getByTestId('user-dashboard')).toBeVisible() // ✅
await expect(page.getByTestId('page-title')).toContainText('Dashboard') // ✅
await expect(page.getByTestId('app-state')).toHaveAttribute('data-status', 'authenticated') // ✅
```

---

### 5. Use data-status for State Verification
**Components should expose their state via `data-status` attribute.**

**Example:**
```vue
<template>
  <div :data-status="authState" data-testid="auth-container">
    <div v-if="authState === 'loading'">Loading...</div>
    <div v-if="authState === 'authenticated'">Welcome!</div>
    <div v-if="authState === 'error'">Error occurred</div>
  </div>
</template>
```

**Test:**
```typescript
await expect(page.getByTestId('auth-container')).toHaveAttribute('data-status', 'loading')
await expect(page.getByTestId('auth-container')).toHaveAttribute('data-status', 'authenticated')
```

---

## Complete Example

### Bad Test
```typescript
test('login', async ({ page }) => {
  await page.goto('http://localhost:5180/auth/')
  await page.waitForTimeout(1000) // ❌ Rule 1
  
  await page.locator('input[type="email"]').fill('test@example.com') // ❌ Rule 3
  await page.locator('input[type="password"]').fill('password') // ❌ Rule 3
  await page.locator('button:has-text("Sign In")').click() // ❌ Rule 3
  
  await page.waitForTimeout(2000) // ❌ Rule 1
  
  const url = page.url() // ❌ Rule 4
  expect(url).toContain('/dashboard') // ❌ Rule 4
  // ❌ Rule 2: No explicit success verification
})
```

### Good Test
```typescript
test('login', async ({ page }) => {
  await page.goto('http://localhost:5180/auth/')
  
  await expect(page.getByTestId('signin-form')).toBeVisible() // ✅
  
  await page.getByTestId('email-input').fill('test@example.com') // ✅ Rule 3
  await page.getByTestId('password-input').fill('password') // ✅ Rule 3
  await page.getByTestId('signin-button').click() // ✅ Rule 3
  
  // ✅ Rule 2: Explicit success verification
  await expect(page.getByTestId('dashboard-page')).toBeVisible() // ✅
  await expect(page.getByTestId('user-email')).toContainText('test@example.com') // ✅
  await expect(page.getByTestId('app-state')).toHaveAttribute('data-status', 'authenticated') // ✅
})
```

---

## Migration Checklist

When updating existing tests:

- [ ] Replace all `waitForTimeout()` with explicit waits
- [ ] Add explicit success assertions
- [ ] Replace all selectors with `getByTestId()`
- [ ] Remove localStorage/URL checks
- [ ] Add `data-testid` to components
- [ ] Add `data-status` for state verification
- [ ] Verify tests fail when they should

