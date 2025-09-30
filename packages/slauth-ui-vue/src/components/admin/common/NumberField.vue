<template>
  <div :class="['form-group', { 'form-group--dark': darkMode }]">
    <label>
      {{ label }}
      <span v-if="hint" class="hint-text">{{ hint }}</span>
    </label>
    <input 
      type="number" 
      :value="modelValue"
      :min="min"
      :max="max"
      :step="step"
      @input="$emit('update:modelValue', parseFloat(($event.target as HTMLInputElement).value))"
    />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'

defineProps<{
  label: string
  hint?: string
  modelValue: number
  min?: number
  max?: number
  step?: number
}>()

defineEmits<{
  'update:modelValue': [value: number]
}>()

const adminContext = useAdminContext()
const darkMode = computed(() => adminContext.value.darkMode ?? false)
</script>

<style scoped>
.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: var(--field-text, #374151);
  font-size: 14px;
}

.form-group--dark {
  --field-text: #f9fafb;
  --field-hint: #d1d5db;
  --field-bg: #1f2937;
  --field-border: #4b5563;
}

.hint-text {
  display: block;
  color: var(--field-hint, #6b7280);
  font-size: 13px;
  font-weight: normal;
  margin-top: 4px;
}

.form-group input[type="number"] {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--field-border, #d1d5db);
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.2s;
  background: var(--field-bg, white);
  color: var(--field-text, #374151);
}

.form-group input:focus {
  outline: none;
  border-color: #3b82f6;
}
</style>
