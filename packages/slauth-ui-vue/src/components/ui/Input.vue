<template>
  <div
    class="aira-input"
    :data-testid="$attrs['data-testid']"
    :data-status="getInputStatus()"
  >
    <Label
      v-if="label"
      :text="label"
      :html-for="inputId"
      :required="required"
      class="aira-input__label"
    />
    <input
      :id="inputId"
      :type="type"
      :value="modelValue"
      :placeholder="placeholder"
      :required="required"
      :disabled="disabled"
      :autocomplete="autoComplete"
      :autofocus="autoFocus"
      :data-testid="$attrs['data-testid'] ? $attrs['data-testid'] + '-field' : undefined"
      :data-status="getInputStatus()"
      :class="[
        'aira-input__field',
        { 'aira-input__field--error': error },
        className
      ]"
      @input="handleInput"
      @blur="handleBlur"
      @focus="handleFocus"
    />
    <div
      v-if="error"
      class="aira-input__error"
      :data-testid="$attrs['data-testid'] ? String($attrs['data-testid']).replace('-input', '-error') : undefined"
    >
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { InputProps } from '../../types'
import Label from './Label.vue'

// Props
const props = withDefaults(defineProps<InputProps>(), {
  type: 'text',
  modelValue: '',
  required: false,
  disabled: false,
  autoFocus: false
})

// Emits
const emit = defineEmits<{
  'update:modelValue': [value: string]
  blur: [event: FocusEvent]
  focus: [event: FocusEvent]
}>()

// Computed
const inputId = computed(() => `aira-input-${Math.random().toString(36).substr(2, 9)}`)

// Methods
const handleInput = (event: Event) => {
  const target = event.target as HTMLInputElement
  emit('update:modelValue', target.value)
}

const handleBlur = (event: FocusEvent) => {
  emit('blur', event)
}

const handleFocus = (event: FocusEvent) => {
  emit('focus', event)
}

const getInputStatus = () => {
  if (props.disabled) return 'disabled'
  if (props.error) return 'error'
  return 'idle'
}
</script>

<style scoped>
.aira-input {
  margin-bottom: 1rem;
}

.aira-input__label {
  display: block;
  margin-bottom: 0.5rem;
}

.aira-input__field {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: var(--auth-ui-border-radius);
  background-color: var(--auth-ui-input-background);
  color: var(--auth-ui-text);
  font-size: 0.875rem;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.aira-input__field:focus {
  outline: none;
  border-color: var(--auth-ui-primary);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.aira-input__field:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.aira-input__field--error {
  border-color: var(--auth-ui-error);
}

.aira-input__field--error:focus {
  border-color: var(--auth-ui-error);
  box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
}

.aira-input__error {
  margin-top: 0.25rem;
  font-size: 0.75rem;
  color: var(--auth-ui-error);
}
</style>
