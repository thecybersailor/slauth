const assert = require('assert')

const knownActions = [
  'signup',
  'signin',
  'forgot-password',
  'reset-password',
  'magic-link',
  'verify-otp',
  'callback',
  'confirm',
  'confirmed',
]

function normalizeConfiguredBasePath(authBaseUrl, origin = 'http://localhost') {
  if (!authBaseUrl) {
    return ''
  }

  return new URL(authBaseUrl, origin).pathname.replace(/\/$/, '')
}

function detectAuthBasePathForPath(currentPath, configuredBasePath = '') {
  const normalizedPath = currentPath.replace(/\/$/, '')

  if (configuredBasePath && normalizedPath === configuredBasePath) {
    return { basePath: configuredBasePath, action: 'signin' }
  }

  for (const action of knownActions) {
    if (normalizedPath.endsWith(`/${action}`)) {
      const basePath = normalizedPath.slice(0, -(action.length + 1))
      return { basePath, action }
    }
  }

  const segments = normalizedPath.split('/').filter(Boolean)
  if (segments.length >= 2) {
    const lastSegment = segments[segments.length - 1]
    const basePath = `/${segments.slice(0, -1).join('/')}`
    return { basePath, action: lastSegment }
  }

  if (segments.length === 1) {
    return { basePath: '', action: segments[0] }
  }

  return { basePath: '', action: 'signin' }
}

assert.deepStrictEqual(detectAuthBasePathForPath('/auth/', '/auth'), { basePath: '/auth', action: 'signin' })
assert.deepStrictEqual(detectAuthBasePathForPath('/auth', '/auth'), { basePath: '/auth', action: 'signin' })
assert.deepStrictEqual(detectAuthBasePathForPath('/auth/signup'), { basePath: '/auth', action: 'signup' })
assert.deepStrictEqual(detectAuthBasePathForPath('/account/auth/signin'), { basePath: '/account/auth', action: 'signin' })
assert.deepStrictEqual(detectAuthBasePathForPath('/auth/custom-action'), { basePath: '/auth', action: 'custom-action' })
assert.deepStrictEqual(detectAuthBasePathForPath('/'), { basePath: '', action: 'signin' })
assert.deepStrictEqual(detectAuthBasePathForPath('/signin'), { basePath: '', action: 'signin' })
assert.deepStrictEqual(detectAuthBasePathForPath('/signup'), { basePath: '', action: 'signup' })
assert.deepStrictEqual(detectAuthBasePathForPath('/custom-action'), { basePath: '', action: 'custom-action' })
assert.strictEqual(normalizeConfiguredBasePath('http://localhost/auth/'), '/auth')
assert.strictEqual(normalizeConfiguredBasePath('/nested/auth'), '/nested/auth')

console.log('auth path detection tests passed')
