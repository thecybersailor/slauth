import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      redirect: '/auth'
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: () => import('../views/DashboardView.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/test/:pathMatch(.*)*',
      name: 'test-path',
      component: () => import('../views/TestPathView.vue')
    },
    {
      path: '/admin/:pathMatch(.*)*',
      name: 'admin',
      component: () => import('../views/AdminView.vue')
    },
    {
      
      path: '/auth/:pathMatch(.*)*',
      name: 'auth',
      component: () => import('../views/AuthView.vue')
    }
  ],
})

// Navigation guard for authentication
router.beforeEach((to, from, next) => {
  console.log('[router] beforeEach', {
    to: to.path,
    from: from.path,
    requiresAuth: to.matched.some(record => record.meta.requiresAuth)
  })
  
  // Check if route requires authentication
  if (to.matched.some(record => record.meta.requiresAuth)) {
    // Check if user is authenticated
    const isAuthenticated = checkAuthStatus()
    console.log('[router] Auth check result', { 
      isAuthenticated,
      toPath: to.path 
    })

    if (!isAuthenticated) {
      console.log('[router] Not authenticated, redirecting to auth')
      next({ name: 'auth', query: { redirect: to.fullPath } })
      return
    }
  }

  console.log('[router] Navigation allowed')
  next()
})

// Helper function to check authentication status
function checkAuthStatus(): boolean {
  // Check if there's a valid session in localStorage
  const sessionData = localStorage.getItem('aira.auth.token')
  console.log('[router:checkAuthStatus] Checking localStorage', {
    hasData: !!sessionData,
    dataLength: sessionData?.length,
    allKeys: Object.keys(localStorage)
  })
  
  if (!sessionData) return false

  const session = JSON.parse(sessionData)
  console.log('[router:checkAuthStatus] Session parsed', {
    hasAccessToken: !!session.access_token,
    hasExpiresAt: !!session.expires_at,
    expiresAt: session.expires_at,
    now: Date.now() / 1000
  })
  
  if (!session.access_token) return false

  // Check if token is expired (basic check)
  if (session.expires_at && session.expires_at < Date.now() / 1000) {
    console.log('[router:checkAuthStatus] Token expired')
    return false
  }

  return true
}


export default router
