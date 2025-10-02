<template>
  <teleport to="body">
    <div v-if="modelValue" class="dialog-overlay" @click="handleOverlayClick">
      <div 
        :class="[
          'dialog',
          { 'dialog--dark': darkMode }
        ]"
        :style="dialogStyle"
        :data-dark-mode="darkMode"
        @click.stop
      >
        <div class="dialog__header">
          <slot name="header">
            <h3 v-if="title" class="dialog__title">{{ title }}</h3>
          </slot>
          <button 
            v-if="showClose"
            class="dialog__close" 
            @click="handleClose"
            aria-label="Close"
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor">
              <path d="M15 5L5 15M5 5l10 10" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
        
        <div class="dialog__content">
          <slot />
        </div>
        
        <div v-if="$slots.footer" class="dialog__footer">
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
  width?: string | number
  title?: string
  closeOnOverlay?: boolean
  showClose?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  width: '500px',
  closeOnOverlay: true,
  showClose: true
})

const adminContext = useAdminContext()
const darkMode = computed(() => adminContext.value.darkMode ?? false)

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'close'): void
}>()

const dialogStyle = computed(() => {
  const width = typeof props.width === 'number' ? `${props.width}px` : props.width
  return { width, maxWidth: '90vw' }
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
.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.dialog {
  background: white;
  border-radius: 8px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  display: flex;
  flex-direction: column;
  max-height: 90vh;
  overflow: hidden;
  animation: scaleIn 0.3s ease;
  
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

@keyframes scaleIn {
  from { 
    opacity: 0;
    transform: scale(0.95);
  }
  to { 
    opacity: 1;
    transform: scale(1);
  }
}

.dialog--dark {
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

.dialog__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px 24px;
  border-bottom: 1px solid #e5e7eb;
}

.dialog--dark .dialog__header {
  border-bottom-color: #374151;
}

.dialog__title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.dialog__close {
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

.dialog__close:hover {
  color: #374151;
}

.dialog--dark .dialog__close {
  color: #9ca3af;
}

.dialog--dark .dialog__close:hover {
  color: #f9fafb;
}

.dialog__content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
}

.dialog__footer {
  padding: 16px 24px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

.dialog--dark .dialog__footer {
  border-top-color: #374151;
}
</style>

