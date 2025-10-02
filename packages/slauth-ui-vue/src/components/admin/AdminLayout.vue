<template>
  <div 
    :class="[
      'aira-admin',
      { 'aira-admin--dark': darkMode }
    ]"
  >
    <!-- Admin panel container -->
    <div class="aira-admin__container">
      <!-- Top navigation -->
      <nav class="aira-admin__top-nav">
        <ul class="aira-admin__nav-list">
          <li 
            v-for="item in navigationItems" 
            :key="item.key"
            class="aira-admin__nav-item"
          >
            <a
              :href="item.path"
              :class="[
                'aira-admin__nav-link',
                { 'aira-admin__nav-link--active': isActiveRoute(item.path) }
              ]"
            >
              <span class="aira-admin__nav-icon">
                <AdminIcons :type="item.icon as any" />
              </span>
              <span class="aira-admin__nav-text">{{ item.label }}</span>
            </a>
          </li>
        </ul>
      </nav>

      <!-- Main content area -->
      <main class="aira-admin__main">
        <!-- Page content -->
        <div class="aira-admin__content">
          <component
            v-if="currentComponent"
            :is="currentComponent">
            <template v-for="slotName in slotNames" :key="slotName" #[slotName]="slotProps">
              <slot :name="slotName" v-bind="slotProps" />
            </template>
          </component>
        </div>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, provide, onMounted, watch, useSlots, type Slots } from 'vue'
import { mergeLocalization } from '../../localization'
import type { Localization } from '../../types'
import type { AdminContext } from '../../composables/useAdminContext'
import AdminIcons from '../ui/icons/AdminIcons.vue'
import StatsView from './system-stats/Index.vue'
import UsersView from './user-management/Index.vue'
import SettingsView from './settings-management/Index.vue'

const slots: Slots = useSlots()
const slotNames = computed<string[]>(() => Object.keys(slots) as string[])

interface Props {
  adminClient: any
  localization?: Localization
  darkMode?: boolean
  tabs?: string[]
  userDetailSections?: string[]
}

interface NavigationItem {
  key: string
  label: string
  path: string
  icon: string
}

const props = withDefaults(defineProps<Props>(), {
  localization: undefined,
  darkMode: false,
  tabs: () => ['stats', 'users', 'settings'],
  userDetailSections: undefined
})

// Merge internationalization configuration
const mergedLocalization = computed(() => {
  return mergeLocalization(props.localization)
})

// Create Admin Context and provide to child components
const adminContext = computed<AdminContext>(() => ({
  adminClient: props.adminClient,
  localization: mergedLocalization.value,
  darkMode: props.darkMode,
  userDetailSections: props.userDetailSections
}))

provide('admin-context', adminContext)
provide('darkMode', computed(() => props.darkMode))

// Reactive current path
const currentPath = ref(window.location.pathname)

// Auto-detect adminBasePath and currentAction
const pathInfo = computed(() => {
  const path = currentPath.value
  const segments = path.split('/').filter(Boolean)
  
  if (segments.length === 0) {
    return { basePath: '/', currentAction: null }
  }
  
  const lastSegment = segments[segments.length - 1]
  
  // Check if the last part is a known action (from tabs prop)
  if (props.tabs.includes(lastSegment)) {
    // Last part is action
    const basePath = '/' + segments.slice(0, -1).join('/')
    return {
      basePath: basePath === '/' ? '' : basePath,
      currentAction: lastSegment
    }
  } else {
    // Entire thing is basePath
    const basePath = '/' + segments.join('/')
    return {
      basePath,
      currentAction: null
    }
  }
})

// Navigation menu item mapping
const tabConfig = {
  stats: {
    label: 'Stats',
    icon: 'stats'
  },
  users: {
    label: 'Users',
    icon: 'users'
  },
  settings: {
    label: 'Settings',
    icon: 'settings'
  }
}

// Navigation menu items
const navigationItems = computed<NavigationItem[]>(() => {
  const basePath = pathInfo.value.basePath
  return props.tabs.map(tab => {
    const config = tabConfig[tab as keyof typeof tabConfig]
    // Priority: localization label, then default config, finally tab key
    const label = mergedLocalization.value?.admin?.[tab as keyof typeof mergedLocalization.value.admin] 
      || config?.label 
      || tab
    return {
      key: tab,
      label: typeof label === 'string' ? label : config?.label || tab,
      path: `${basePath}/${tab}`,
      icon: config?.icon || tab
    }
  })
})



const isActiveRoute = (path: string): boolean => {
  
  return currentPath.value === path || currentPath.value.startsWith(path + '/')
}


const componentMap: Record<string, any> = {
  stats: StatsView,
  users: UsersView,
  settings: SettingsView
}


const currentComponent = computed(() => {
  const action = pathInfo.value.currentAction
  if (action && componentMap[action]) {
    return componentMap[action]
  }
  return null
})


onMounted(() => {
  if (!pathInfo.value.currentAction && props.tabs.length > 0) {
    const firstTab = props.tabs[0]
    const targetPath = `${pathInfo.value.basePath}/${firstTab}`
    window.location.href = targetPath
  }
})


watch(currentPath, (newPath) => {
  if (!pathInfo.value.currentAction && props.tabs.length > 0) {
    const firstTab = props.tabs[0]
    const targetPath = `${pathInfo.value.basePath}/${firstTab}`
    if (newPath !== targetPath) {
      window.location.href = targetPath
    }
  }
})

</script>

<style scoped>
.aira-admin {
  --admin-text: var(--auth-ui-colors-default-button-text, #374151);
  --admin-border: var(--auth-ui-colors-default-button-border, #e5e7eb);
  --admin-brand: var(--auth-ui-colors-brand, #3b82f6);
  --admin-brand-accent: var(--auth-ui-colors-brand-accent, #2563eb);
  --admin-space: var(--auth-ui-space-space-large, 16px);
  --admin-radius: var(--auth-ui-radii-border-radius-button, 6px);
  --admin-font: var(--auth-ui-fonts-body-font-family, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif);
  --admin-bg: white;
  --admin-input-bg: white;
  --admin-card-bg: white;
  --admin-section-bg: #f9fafb;
  
  color: var(--admin-text);
  font-family: var(--admin-font);
}

.aira-admin--dark {
  --admin-text: #f9fafb;
  --admin-border: #374151;
  --admin-bg: #1f2937;
  --admin-input-bg: #1f2937;
  --admin-card-bg: #374151;
  --admin-section-bg: #374151;
}

.aira-admin__top-nav {
  border-bottom: 1px solid var(--admin-border);
  padding: var(--admin-space);
}

.aira-admin__nav-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  gap: 8px;
}

.aira-admin__nav-item {
  margin: 0;
}

.aira-admin__nav-link {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  text-decoration: none;
  color: var(--admin-text);
  border-radius: var(--admin-radius);
  transition: all 0.2s ease;
  font-size: 14px;
  border: none;
  background: none;
  cursor: pointer;
}

.aira-admin__nav-link:hover {
  background-color: var(--admin-border);
}

.aira-admin__nav-link--active {
  background-color: var(--admin-brand);
  color: white;
}

.aira-admin__nav-icon {
  margin-right: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
}

.aira-admin__nav-icon svg {
  width: 100%;
  height: 100%;
  stroke: currentColor;
}

.aira-admin__nav-text {
  font-weight: 500;
  font-size: 14px;
}
</style>
