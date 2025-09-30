<template>
  <button
    :type="type"
    :disabled="disabled || loading"
    :data-testid="$attrs['data-testid']"
    :data-status="getButtonStatus()"
    :class="[
      'aira-button',
      `aira-button--${variant}`,
      `aira-button--${size}`,
      {
        'aira-button--full-width': fullWidth,
        'aira-button--loading': loading
      },
      className
    ]"
    @click="handleClick"
  >
    <span
      v-if="loading"
      class="aira-button__spinner"
    />
    <span :class="{ 'aira-button__text--loading': loading }">
      <slot />
    </span>
  </button>
</template>

<script setup lang="ts">
import type { ButtonProps } from '../../types'

// Props
const props = withDefaults(defineProps<ButtonProps>(), {
  variant: 'primary',
  size: 'md',
  loading: false,
  disabled: false,
  fullWidth: false,
  type: 'button'
})

// Emits
const emit = defineEmits<{
  click: [event: MouseEvent]
}>()

// Methods
const handleClick = (event: MouseEvent) => {
  if (!props.disabled && !props.loading) {
    emit('click', event)
  }
}

const getButtonStatus = () => {
  if (props.loading) return 'loading'
  if (props.disabled) return 'disabled'
  return 'idle'
}
</script>

<style scoped>
.aira-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  font-weight: 500;
  border-radius: var(--auth-ui-border-radius);
  transition: all 0.2s;
  cursor: pointer;
  border: 1px solid transparent;
  text-decoration: none;
  position: relative;
}

.aira-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Variants */
.aira-button--primary {
  background-color: var(--auth-ui-primary);
  color: white;
  border-color: var(--auth-ui-primary);
}

.aira-button--primary:hover:not(:disabled) {
  background-color: var(--auth-ui-primary-hover);
  border-color: var(--auth-ui-primary-hover);
}

.aira-button--secondary {
  background-color: var(--auth-ui-background);
  color: var(--auth-ui-text);
  border-color: var(--auth-ui-border);
}

.aira-button--secondary:hover:not(:disabled) {
  background-color: var(--auth-ui-border);
}

.aira-button--outline {
  background-color: transparent;
  color: var(--auth-ui-primary);
  border-color: var(--auth-ui-primary);
}

.aira-button--outline:hover:not(:disabled) {
  background-color: var(--auth-ui-primary);
  color: white;
}

.aira-button--ghost {
  background-color: transparent;
  color: var(--auth-ui-text);
  border-color: transparent;
}

.aira-button--ghost:hover:not(:disabled) {
  background-color: var(--auth-ui-border);
}

.aira-button--link {
  background-color: transparent;
  color: var(--auth-ui-primary);
  border-color: transparent;
  text-decoration: underline;
}

.aira-button--link:hover:not(:disabled) {
  color: var(--auth-ui-primary-hover);
}

/* Sizes */
.aira-button--sm {
  padding: 0.2rem 0.75rem;
  font-size: 0.75rem;
}

.aira-button--md {
  padding: 0.75rem 1rem;
  font-size: 0.875rem;
}

.aira-button--lg {
  padding: 1rem 1.5rem;
  font-size: 1rem;
}

/* Full width */
.aira-button--full-width {
  width: 100%;
}

/* Loading state */
.aira-button__spinner {
  width: 1rem;
  height: 1rem;
  border: 2px solid transparent;
  border-top: 2px solid currentColor;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

.aira-button__text--loading {
  opacity: 0.7;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
