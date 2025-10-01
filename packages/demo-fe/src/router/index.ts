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
  
  // Check if route requires authentication
  if (to.matched.some(record => record.meta.requiresAuth)) {
    // Check if user is authenticated
    const isAuthenticated = checkAuthStatus()

    if (!isAuthenticated) {
      next({ name: 'auth', query: { redirect: to.fullPath } })
      return
    }
  }

  next()
})

// Helper function to check authentication status
function checkAuthStatus(): boolean {
  // Check if there's a valid session in localStorage
  try {
    const sessionData = localStorage.getItem('aira.auth.token')
    if (!sessionData) return false

    const session = JSON.parse(sessionData)
    if (!session.access_token) return false

    // Check if token is expired (basic check)
    if (session.expires_at && session.expires_at < Date.now() / 1000) {
      return false
    }

    return true
  } catch {
    return false
  }
}


export default router
