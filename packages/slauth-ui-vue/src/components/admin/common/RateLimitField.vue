<template>
  <div :class="['rate-limit-group', { 'rate-limit-group--dark': darkMode }]">
    <div class="rate-limit-header">
      <strong>{{ title }}</strong>
      <span class="description">{{ description }}</span>
    </div>
    <div class="rate-limit-inputs">
      <div class="input-group">
        <label>Max Requests</label>
        <input 
          type="number" 
          :value="modelValue.max_requests"
          @input="updateValue('max_requests', parseInt(($event.target as HTMLInputElement).value))"
          min="1"
        />
      </div>
      <div class="input-group">
        <label>Window (seconds)</label>
        <input 
          type="number" 
          :value="windowSeconds"
          @input="updateWindowDuration(parseInt(($event.target as HTMLInputElement).value))"
          min="1"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'

const adminContext = useAdminContext()
const darkMode = computed(() => adminContext.value.darkMode ?? false)

const props = defineProps<{
  title: string
  description: string
  modelValue: {
    max_requests: number
    window_duration: number
    description: string
  }
}>()

const emit = defineEmits<{
  'update:modelValue': [value: typeof props.modelValue]
}>()

const windowSeconds = computed(() => {
  return Math.floor(props.modelValue.window_duration / 1e9)
})

function updateValue(key: string, value: number) {
  emit('update:modelValue', {
    ...props.modelValue,
    [key]: value,
  })
}

function updateWindowDuration(seconds: number) {
  emit('update:modelValue', {
    ...props.modelValue,
    window_duration: seconds * 1e9,
  })
}
</script>

<style scoped>
.rate-limit-group {
  background: var(--rate-bg, #fff);
  border: 1px solid var(--rate-border, #e5e7eb);
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 12px;
}

.rate-limit-group--dark {
  --rate-bg: #1f2937;
  --rate-border: #4b5563;
  --rate-text: #f9fafb;
  --rate-text-secondary: #d1d5db;
  --rate-input-bg: #374151;
  --rate-input-border: #4b5563;
}

.rate-limit-header {
  margin-bottom: 12px;
}

.rate-limit-header strong {
  display: block;
  color: var(--rate-text, #374151);
  font-size: 14px;
  margin-bottom: 4px;
}

.rate-limit-header .description {
  display: block;
  color: var(--rate-text-secondary, #6b7280);
  font-size: 13px;
  line-height: 1.4;
}

.rate-limit-inputs {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.input-group label {
  display: block;
  margin-bottom: 6px;
  font-size: 13px;
  color: var(--rate-text-secondary, #6b7280);
  font-weight: 500;
}

.input-group input {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--rate-input-border, #d1d5db);
  border-radius: 4px;
  font-size: 14px;
  background: var(--rate-input-bg, white);
  color: var(--rate-text, #374151);
}

.input-group input:focus {
  outline: none;
  border-color: #3b82f6;
}
</style>
