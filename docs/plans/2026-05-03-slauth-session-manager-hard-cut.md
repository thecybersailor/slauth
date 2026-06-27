# Slauth SessionManager Hard-Cut Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在 `slauth-ts` 中引入唯一 `SessionManager` 真相层，移除旧的同步/共享引用 session 路径，并从当前 `0.10.7` 基线发布 breaking 版本。

**Architecture:** 这次改造采用硬切，不保留兼容 API，不提供 fallback。`StorageManager` 只负责持久化，`SessionManager` 统一负责初始化、refresh、401 恢复、状态清理与广播；`AuthApi` 和 `AdminApi` 只消费 `SessionManager`。公共类库的代码和文档不提及任何下游项目名；下游应用升级在各自仓库单独执行。

**Tech Stack:** TypeScript, Jest, Axios, Zod, npm, Vue 3, Vue Router, Vitest

---

### Task 1: 锁定硬切契约

**Files:**
- Create: `packages/slauth-ts/src/lib/__tests__/session-manager.contract.test.ts`
- Modify: `packages/slauth-ts/src/__tests__/auth-api-security.test.ts`
- Modify: `packages/slauth-ts/src/lib/__tests__/session-refresh-on-init.test.ts`
- Modify: `packages/slauth-ts/src/lib/__tests__/cross-tab-refresh-lock.test.ts`

**Step 1: 写第一批失败测试，定义唯一成功路径**

```ts
it('authClient.getSession returns Promise<Session | null> and waits for initialization', async () => {
  const { authClient } = createClients({
    auth: { url: 'http://auth.local' },
    persistSession: true,
    autoRefreshToken: true,
    storage: fakeStorageWithExpiredSession(),
  })

  await expect(authClient!.getSession()).resolves.toMatchObject({
    access_token: 'refreshed-token',
  })
})

it('adminClient has no setSession API and reads the shared SessionManager state', async () => {
  const { authClient, adminClient } = createClients({
    auth: { url: 'http://auth.local' },
    admin: { url: 'http://admin.local' },
    persistSession: true,
  })

  expect('setSession' in (adminClient as Record<string, unknown>)).toBe(false)
  await authClient!.signInWithPassword({ email: 'u@example.com', password: 'secret' })
  await expect(adminClient!.getSession()).resolves.toMatchObject({
    access_token: expect.any(String),
  })
})
```

**Step 2: 运行 contract tests，确认以 API 不存在或返回类型不符的方式失败**

Run: `npm test -- --runInBand src/lib/__tests__/session-manager.contract.test.ts src/lib/__tests__/session-refresh-on-init.test.ts`

Expected: FAIL，包含 `getSession is not async`、`adminClient.setSession still exists`、或初始化未等待的断言失败。

**Step 3: 补第二批失败测试，禁止旧的共享引用模型**

```ts
it('does not require shared mutable session references between auth and admin clients', async () => {
  const { authClient, adminClient } = createClients({
    auth: { url: 'http://auth.local' },
    admin: { url: 'http://admin.local' },
  })

  await authClient!.refreshSession()
  const adminSession = await adminClient!.getSession()
  expect(adminSession?.access_token).toBe('new-access-token')
})
```

**Step 4: 运行 cross-tab 与 auth security tests，确认旧实现继续失败**

Run: `npm test -- --runInBand src/lib/__tests__/cross-tab-refresh-lock.test.ts src/__tests__/auth-api-security.test.ts`

Expected: FAIL，失败点聚焦在旧的 `currentSession` / `setSession` / 同步 session 语义。

**Step 5: Commit**

```bash
git add packages/slauth-ts/src/lib/__tests__/session-manager.contract.test.ts \
  packages/slauth-ts/src/lib/__tests__/session-refresh-on-init.test.ts \
  packages/slauth-ts/src/lib/__tests__/cross-tab-refresh-lock.test.ts \
  packages/slauth-ts/src/__tests__/auth-api-security.test.ts
git commit -m "test: lock hard-cut session manager contract"
```

### Task 2: 实现 SessionManager 核心

**Files:**
- Create: `packages/slauth-ts/src/lib/session-manager.ts`
- Modify: `packages/slauth-ts/src/lib/storage.ts`
- Modify: `packages/slauth-ts/src/lib/types.ts`
- Test: `packages/slauth-ts/src/lib/__tests__/session-manager.contract.test.ts`

**Step 1: 写 `SessionManager` 最小实现代码，不碰 `AuthApi` / `AdminApi`**

```ts
export class SessionManager {
  async initialize(): Promise<void> {}
  async getSession(): Promise<Session | null> {}
  async refreshSession(): Promise<Session | null> {}
  async setSession(session: Session | null): Promise<void> {}
  async clearSession(): Promise<void> {}
  async getAccessToken(): Promise<string | null> {}
}
```

**Step 2: 让 `StorageManager` 只保留持久化职责**

```ts
async loadSession(): Promise<Session | null> {}
async saveSession(session: Session): Promise<void> {}
async removeSession(): Promise<void> {}
```

明确删除 `checkExpiry` 这种认证语义参数，过期判断只允许出现在 `SessionManager`。

**Step 3: 运行 contract tests，验证 `SessionManager` 自身行为通过**

Run: `npm test -- --runInBand src/lib/__tests__/session-manager.contract.test.ts`

Expected: PASS

**Step 4: 运行初始化 refresh tests，验证启动阶段由 `SessionManager` 负责刷新**

Run: `npm test -- --runInBand src/lib/__tests__/session-refresh-on-init.test.ts`

Expected: PASS

**Step 5: Commit**

```bash
git add packages/slauth-ts/src/lib/session-manager.ts \
  packages/slauth-ts/src/lib/storage.ts \
  packages/slauth-ts/src/lib/types.ts \
  packages/slauth-ts/src/lib/__tests__/session-manager.contract.test.ts \
  packages/slauth-ts/src/lib/__tests__/session-refresh-on-init.test.ts
git commit -m "feat: add hard-cut session manager core"
```

### Task 3: 重写 AuthApi，删除本地 session 真相

**Files:**
- Modify: `packages/slauth-ts/src/AuthApi.ts`
- Modify: `packages/slauth-ts/src/lib/fetch.ts`
- Modify: `packages/slauth-ts/src/lib/validated-client.ts`
- Test: `packages/slauth-ts/src/__tests__/auth-api-security.test.ts`
- Test: `packages/slauth-ts/src/lib/__tests__/fetch.test.ts`

**Step 1: 删除 `AuthApi.currentSession/currentUser/initializeSession/setSession/clearSession` 内部真相**

```ts
export class AuthApi {
  constructor(baseURL: string, config: AuthApiConfig, sessionManager: SessionManager) {}

  async getSession(): Promise<Types.Session | null> {
    return this.sessionManager.getSession()
  }

  async isAuthenticated(): Promise<boolean> {
    return (await this.getSession()) !== null
  }
}
```

**Step 2: 把 sign-in / sign-out / refresh / user update 全部委托给 `SessionManager`**

```ts
if (data.session) {
  await this.sessionManager.setSession(data.session)
}
```

`signOut()` 只能清空 `SessionManager`，不能自己再碰 storage。

**Step 3: 让 `authClient.request` 的 401 恢复只认 `SessionManager.refreshSession()`**

```ts
const refreshSuccess = await this.config.refreshTokenFn!()
if (!refreshSuccess) {
  this.config.onUnauthorized?.()
  return Promise.reject(authError)
}
```

不再从 `HttpClient` 内部推断 session 真相，不再从 `AuthApi.currentSession` 取 refresh token。

**Step 4: 运行 fetch 与 auth tests，确认自动 refresh 仍然成立但路径只剩一条**

Run: `npm test -- --runInBand src/lib/__tests__/fetch.test.ts src/__tests__/auth-api-security.test.ts`

Expected: PASS

**Step 5: Commit**

```bash
git add packages/slauth-ts/src/AuthApi.ts \
  packages/slauth-ts/src/lib/fetch.ts \
  packages/slauth-ts/src/lib/validated-client.ts \
  packages/slauth-ts/src/__tests__/auth-api-security.test.ts \
  packages/slauth-ts/src/lib/__tests__/fetch.test.ts
git commit -m "refactor: route auth api through session manager"
```

### Task 4: 重写 AdminApi 与 createClients，共享同一个 SessionManager

**Files:**
- Modify: `packages/slauth-ts/src/AdminApi.ts`
- Modify: `packages/slauth-ts/src/createClients.ts`
- Modify: `packages/slauth-ts/src/index.ts`
- Test: `packages/slauth-ts/src/lib/__tests__/cross-tab-refresh-lock.test.ts`
- Test: `packages/slauth-ts/src/lib/__tests__/session-manager.contract.test.ts`

**Step 1: 删除 `AdminApi.currentSession`、`setSession()`、同步 `getSession()`**

```ts
export class AdminApi {
  constructor(baseURL: string, config: AdminApiConfig, sessionManager: SessionManager) {}

  async getSession(): Promise<Session | null> {
    return this.sessionManager.getSession()
  }
}
```

**Step 2: 在 `createClients()` 中创建唯一 `SessionManager` 并注入两个 client**

```ts
const sessionManager = new SessionManager(sharedConfig)
const authClient = config.auth ? new AuthApi(config.auth.url, sharedConfig, sessionManager) : null
const adminClient = config.admin ? new AdminApi(config.admin.url, sharedConfig, sessionManager) : null
```

**Step 3: 导出新的 public API**

```ts
export { SessionManager } from './lib/session-manager'
```

旧的 `adminClient.setSession()` 不再导出，不写 shim，不写 deprecation。

**Step 4: 运行 cross-tab 与 contract tests，确认 auth/admin 自动共享同一真相层**

Run: `npm test -- --runInBand src/lib/__tests__/cross-tab-refresh-lock.test.ts src/lib/__tests__/session-manager.contract.test.ts`

Expected: PASS

**Step 5: Commit**

```bash
git add packages/slauth-ts/src/AdminApi.ts \
  packages/slauth-ts/src/createClients.ts \
  packages/slauth-ts/src/index.ts \
  packages/slauth-ts/src/lib/__tests__/cross-tab-refresh-lock.test.ts \
  packages/slauth-ts/src/lib/__tests__/session-manager.contract.test.ts
git commit -m "refactor: share session manager across auth and admin clients"
```

### Task 5: 更新文档、示例和 breaking 版本信息

**Files:**
- Modify: `packages/slauth-ts/README.md`
- Modify: `packages/slauth-ts/docs/auth-api.md`
- Modify: `packages/slauth-ts/docs/admin-api.md`
- Modify: `packages/slauth-ts/package.json`
- Modify: `CHANGELOG.md`
- Modify: `packages/demo-fe/package.json`

**Step 1: 先写文档失败清单，逐项删除旧 API 痕迹**

Checklist:
- `getSession(): Session | null` 全部替换为 `getSession(): Promise<Session | null>`
- 删除 `adminClient.setSession(...)` 示例
- 明确写出 “no sync session API, no fallback, fast-fail”

**Step 2: 从当前 `0.10.7` 升级到下一 breaking 版本**

```json
{
  "version": "NEXT_BREAKING_VERSION"
}
```

执行时先确认目标版本号；文档中不提前写死具体 breaking 版本。

**Step 3: 更新 CHANGELOG 的 Unreleased 段**

```md
### Breaking
- replace ad-hoc session state with a single SessionManager
- remove sync getSession() and AdminApi.setSession()
```

**Step 4: 运行类型检查和构建，确认文档变更对应的 public API 可以编译**

Run: `npm run build`

Expected: PASS，生成 `dist/cjs`、`dist/esm`、`dist/types`

**Step 5: Commit**

```bash
git add packages/slauth-ts/README.md \
  packages/slauth-ts/docs/auth-api.md \
  packages/slauth-ts/docs/admin-api.md \
  packages/slauth-ts/package.json \
  packages/demo-fe/package.json \
  CHANGELOG.md
git commit -m "docs: publish hard-cut session manager api"
```

### Task 6: 完成 `slauth-ts` 发布验证与 npm 发布

**Files:**
- Modify: `packages/slauth-ts/package-lock.json`
- Modify: `packages/demo-fe/package-lock.json`

**Step 1: 运行 package 测试与构建，拿到发布前证据**

Run: `npm test -- --runInBand`

Expected: PASS

Run: `npm run build`

Expected: PASS

**Step 2: 更新 lockfile**

Run: `npm install`

Expected: PASS，`package-lock.json` 与版本号一致，无 `pnpm` 产物。

**Step 3: 发布 npm 包**

Run: `npm publish`

Workdir: `packages/slauth-ts`

Expected: PASS，registry 返回 `@cybersailor/slauth-ts@NEXT_BREAKING_VERSION`

**Step 4: 打 tag 并推送**

Run: `git tag vNEXT_BREAKING_VERSION`

Expected: PASS

Run: `git push origin HEAD --tags`

Expected: PASS

**Step 5: Commit**

```bash
git add packages/slauth-ts/package-lock.json packages/demo-fe/package-lock.json
git commit -m "chore: prepare slauth-ts breaking release"
```

### Task 7: 在下游应用仓库执行升级验证

**Files:**
- Modify: `consumer-app/package.json`
- Modify: `consumer-app/package-lock.json`
- Modify: `consumer-app/src/auth-entry.ts`
- Modify: `consumer-app/src/session-guard.ts`
- Modify: `consumer-app/src/request-clients.ts`
- Test: `consumer-app/src/__tests__/session-guard.test.ts`

**Step 1: 在下游应用仓库安装新版本**

Run: `npm install @cybersailor/slauth-ts@^NEXT_BREAKING_VERSION`

Workdir: `consumer-app`

Expected: PASS

**Step 2: 写失败测试，禁止下游应用再自行按 JWT exp 判死**

```ts
it('awaits authClient.getSession in router guard instead of clearing storage on expired access token', async () => {
  vi.mocked(authClient.getSession).mockResolvedValue({
    access_token: 'refreshed-token',
    refresh_token: 'refresh-token',
    user: { id: 'u1' },
  })

  await router.push('/team/select')
  expect(router.currentRoute.value.path).toBe('/team/select')
})
```

**Step 3: 删掉本地 session 真相**

要求：
- `session.ts` 不再提供 `hasValidSession()`
- 路由守卫改为 `await authClient.getSession()`
- 直连 `fetch` 通路统一接入单一 refresh helper
- refresh 失败后立即 `handleUnauthorized()`，不再靠本地 fallback 判活

**Step 4: 跑下游应用测试**

Run: `npm test -- src/router/__tests__/auth-guard.spec.ts`

Workdir: `consumer-app`

Expected: PASS

**Step 5: 再跑下游应用构建**

Run: `npm run build`

Workdir: `consumer-app`

Expected: PASS

**Step 6: Commit**

```bash
git add consumer-app/package.json \
  consumer-app/package-lock.json \
  consumer-app/src/auth-entry.ts \
  consumer-app/src/session-guard.ts \
  consumer-app/src/request-clients.ts \
  consumer-app/src/__tests__/session-guard.test.ts
git commit -m "refactor: migrate consumer app to session manager api"
```

### Task 8: 验收 review 与最终核对

**Files:**
- Modify: `none`

**Step 1: 跑端到端验收命令**

Run: `npm test -- --runInBand && npm run build`

Workdir: `packages/slauth-ts`

Expected: PASS

Run: `npm test -- src/__tests__/session-guard.test.ts && npm run build`

Workdir: `consumer-app`

Expected: PASS

**Step 2: 手工 review checklist**

Checklist:
- 只有一个 session 真相层：`SessionManager`
- `StorageManager` 不再判断过期，不再决定认证状态
- `AuthApi.getSession()` 是异步权威接口
- `AdminApi.setSession()` 已删除
- 下游应用不再自己解析 JWT `exp` 来决定登出
- 401 恢复路径只有一条：`refreshSession()`
- refresh 失败后立即 fast-fail，触发 `onUnauthorized`
- README / docs / demo / CHANGELOG / version 全部与新 API 一致
- npm 包已发布，tag 已推送

**Step 3: 在最后一次 commit 前，重新核对本计划清单**

Checklist:
- 有没有遗漏未执行任务
- 有没有与硬切原则冲突的兼容代码
- 有没有多余的 fallback / sync API / deprecation shim
- 有没有未更新的测试、文档、版本号、lockfile

**Step 4: 如核对过程中发现偏差，回到对应任务修复；如全部通过，结束执行。**

注意：
- 这个方案文件只用于执行，不提交到仓库。
- 公共类库源码、README、API 文档、CHANGELOG 中不提及任何具体下游项目名。
