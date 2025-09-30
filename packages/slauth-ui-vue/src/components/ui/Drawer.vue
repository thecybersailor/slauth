<template>
  <teleport to="body">
    <div v-if="modelValue" class="drawer-overlay" @click="handleOverlayClick">
      <div 
        :class="[
          'drawer',
          `drawer--${direction}`,
          { 'drawer--dark': darkMode }
        ]"
        :style="drawerStyle"
        :data-dark-mode="darkMode"
        @click.stop
      >
        <div class="drawer__header">
          <slot name="header">
            <h3 v-if="title" class="drawer__title">{{ title }}</h3>
          </slot>
          <button 
            class="drawer__close" 
            @click="handleClose"
            aria-label="Close"
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor">
              <path d="M15 5L5 15M5 5l10 10" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
        
        <div class="drawer__content">
          <slot />
        </div>
        
        <div v-if="$slots.footer" class="drawer__footer">
          <slot name="footer" />
        </div>
      </div>
    </div>
  </teleport>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAdminContext } from '../../composables/useAdminContext'

interface Props {
  modelValue: boolean
  direction?: 'ltr' | 'rtl' | 'ttb' | 'btt'
  size?: string | number
  title?: string
  closeOnOverlay?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  direction: 'rtl',
  size: '400px',
  closeOnOverlay: true
})

const adminContext = useAdminContext()
const darkMode = computed(() => adminContext.value.darkMode ?? false)

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'close'): void
}>()

const drawerStyle = computed(() => {
  const size = typeof props.size === 'number' ? `${props.size}px` : props.size
  
  if (props.direction === 'ltr' || props.direction === 'rtl') {
    return { width: size }
  } else {
    return { height: size }
  }
})

const handleClose = () => {
  emit('update:modelValue', false)
  emit('close')
}

const handleOverlayClick = () => {
  if (props.closeOnOverlay) {
    handleClose()
  }
}
</script>

<style scoped>
.drawer-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  z-index: 1000;
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.drawer {
  background: white;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  
  /* Define CSS variables for child components (light mode) */
  --admin-text: #374151;
  --admin-border: #e5e7eb;
  --admin-bg: white;
  --admin-input-bg: white;
  --admin-card-bg: white;
  
  /* Auth UI variables for Input and Button components */
  --auth-ui-border: #e5e7eb;
  --auth-ui-input-background: white;
  --auth-ui-background: white;
  --auth-ui-text: #374151;
  --auth-ui-primary: #3b82f6;
  --auth-ui-primary-hover: #2563eb;
  --auth-ui-error: #ef4444;
  --auth-ui-border-radius: 6px;
}

.drawer--dark {
  background: #1f2937;
  color: #f9fafb;
  
  /* Define CSS variables for child components */
  --admin-text: #f9fafb;
  --admin-border: #374151;
  --admin-bg: #1f2937;
  --admin-input-bg: #374151;
  --admin-card-bg: #374151;
  
  /* Auth UI variables for Input and Button components */
  --auth-ui-border: #4b5563;
  --auth-ui-input-background: #374151;
  --auth-ui-background: #374151;
  --auth-ui-text: #f9fafb;
  --auth-ui-primary: #3b82f6;
  --auth-ui-primary-hover: #2563eb;
  --auth-ui-error: #ef4444;
  --auth-ui-border-radius: 6px;
}

/* RTL: Right to Left */
.drawer--rtl {
  margin-left: auto;
  animation: slideInRight 0.3s ease;
}

@keyframes slideInRight {
  from { transform: translateX(100%); }
  to { transform: translateX(0); }
}

/* LTR: Left to Right */
.drawer--ltr {
  margin-right: auto;
  animation: slideInLeft 0.3s ease;
}

@keyframes slideInLeft {
  from { transform: translateX(-100%); }
  to { transform: translateX(0); }
}

/* TTB: Top to Bottom */
.drawer--ttb {
  width: 100%;
  margin-bottom: auto;
  animation: slideInTop 0.3s ease;
}

@keyframes slideInTop {
  from { transform: translateY(-100%); }
  to { transform: translateY(0); }
}

/* BTT: Bottom to Top */
.drawer--btt {
  width: 100%;
  margin-top: auto;
  animation: slideInBottom 0.3s ease;
}

@keyframes slideInBottom {
  from { transform: translateY(100%); }
  to { transform: translateY(0); }
}

.drawer__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px 24px;
  border-bottom: 1px solid #e5e7eb;
}

.drawer--dark .drawer__header {
  border-bottom-color: #374151;
}

.drawer__title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.drawer__close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #6b7280;
  transition: color 0.2s;
}

.drawer__close:hover {
  color: #374151;
}

.drawer--dark .drawer__close {
  color: #9ca3af;
}

.drawer--dark .drawer__close:hover {
  color: #f9fafb;
}

.drawer__content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
}

.drawer__footer {
  padding: 16px 24px;
  border-top: 1px solid #e5e7eb;
}

.drawer--dark .drawer__footer {
  border-top-color: #374151;
}
</style>
