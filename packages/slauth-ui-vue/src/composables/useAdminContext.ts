import { inject, type ComputedRef } from 'vue'
import type { AdminApi } from '@cybersailor/slauth-ts'
import type { Localization } from '../types'

export interface AdminContext {
  adminClient: AdminApi
  localization?: Localization
  darkMode?: boolean
}

export function useAdminContext(): ComputedRef<AdminContext> {
  const context = inject<ComputedRef<AdminContext>>('admin-context')
  
  if (!context) {
    throw new Error('useAdminContext must be used within an AdminLayout component')
  }
  
  return context
}
