<template>
  <div class="oauth-button-wrapper">
    <button 
      :style="buttonStyle"
      :class="buttonClass"
      v-bind="$attrs"
    >
      <slot name="icon"></slot>
      <slot></slot>
    </button>
    <div v-if="error" class="oauth-button-error">
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Theme } from '../../types'
import { useOAuthButtonStyles } from '../../composables/useOAuthButtonStyles'
import { useAuthContext } from '../../composables/useAuthContext'

const props = defineProps<{
  loading?: boolean
  error?: string
}>()

const { authConfig } = useAuthContext()

const variables = computed(() => {
  const appearance = authConfig?.appearance
  if (typeof appearance === 'object' && appearance?.variables) {
    return appearance.variables.default || {}
  }
  return {}
})

const theme = computed<Theme>(() => {
  const appearance = authConfig?.appearance
  if (typeof appearance === 'object' && appearance?.theme) {
    return appearance.theme
  }
  return 'light'
})

const {
  baseButtonStyle,
  hoverStyle,
  activeStyle,
  disabledStyle
} = useOAuthButtonStyles(variables, theme.value as Theme)

const buttonStyle = computed(() => baseButtonStyle.value)

const buttonClass = computed(() => {
  const classes = ['oauth-button']
  
  if (props.loading) {
    classes.push('oauth-button--loading')
  }
  
  return classes.join(' ')
})

const brandColor = computed(() => variables.value?.colors?.brand || '#3b82f6')
</script>

<style scoped>
.oauth-button {
  position: relative;
  overflow: hidden;
}

.oauth-button :deep(svg) {
  width: 20px;
  height: 20px;
  margin-right: 8px;
}

.oauth-button:hover:not(:disabled) {
  background-color: v-bind('hoverStyle.backgroundColor') !important;
  border-color: v-bind('hoverStyle.borderColor') !important;
  box-shadow: v-bind('hoverStyle.boxShadow') !important;
}

.oauth-button:active:not(:disabled) {
  background-color: v-bind('activeStyle.backgroundColor') !important;
  border-color: v-bind('activeStyle.borderColor') !important;
  box-shadow: v-bind('activeStyle.boxShadow') !important;
}

.oauth-button:disabled {
  opacity: v-bind('disabledStyle.opacity') !important;
  cursor: v-bind('disabledStyle.cursor') !important;
  box-shadow: v-bind('disabledStyle.boxShadow') !important;
}

.oauth-button--loading {
  pointer-events: none;
  opacity: 0.7;
}

.oauth-button--loading::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 2px;
  background: linear-gradient(90deg, transparent 0%, transparent 30%, v-bind(brandColor) 50%, transparent 70%, transparent 100%);
  background-size: 200% 100%;
  background-position: -100% 0;
  animation: loading-slide 1.5s ease-in-out infinite;
  z-index: 1;
}

@keyframes loading-slide {
  0% {
    background-position: 100% 0;
  }
  100% {
    background-position: -100% 0;
  }
}

.oauth-button-wrapper {
  width: 100%;
}

.oauth-button-error {
  margin-top: 0.5rem;
  font-size: 0.875rem;
  color: #ef4444;
  text-align: left;
}
</style>

