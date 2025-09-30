<template>
  <div :class="['form-group', 'checkbox', { 'form-group--dark': darkMode }]">
    <label>
      <input 
        type="checkbox" 
        :checked="modelValue" 
        @change="$emit('update:modelValue', ($event.target as HTMLInputElement).checked)"
      />
      <span class="checkbox-label">
        {{ label }}
        <span v-if="hint" class="hint-text">{{ hint }}</span>
      </span>
    </label>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'

defineProps<{
  label: string
  hint?: string
  modelValue: boolean
}>()

defineEmits<{
  'update:modelValue': [value: boolean]
}>()

const adminContext = useAdminContext()
const darkMode = computed(() => adminContext.value.darkMode ?? false)
</script>

<style scoped>
.form-group {
  margin-bottom: 16px;
}

.form-group.checkbox label {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  cursor: pointer;
  font-size: 14px;
}

.form-group.checkbox input[type="checkbox"] {
  width: auto;
  margin-top: 2px;
  cursor: pointer;
  flex-shrink: 0;
}

.checkbox-label {
  flex: 1;
  color: var(--field-text, #374151);
  line-height: 1.5;
}

.form-group--dark {
  --field-text: #f9fafb;
  --field-hint: #d1d5db;
}

.hint-text {
  display: block;
  color: var(--field-hint, #6b7280);
  font-size: 13px;
  margin-top: 4px;
  font-weight: normal;
}
</style>
