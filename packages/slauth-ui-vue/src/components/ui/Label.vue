<template>
  <label
    :for="htmlFor"
    :class="['aira-label', className]"
  >
    {{ text }}
    <span
      v-if="required"
      class="aira-label__required"
    >
      *
    </span>
  </label>
</template>

<script setup lang="ts">
import type { LabelProps } from '../../types'

// Props
defineProps<LabelProps>()
</script>

<style scoped>
.aira-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--auth-ui-text);
  cursor: pointer;
}

.aira-label__required {
  color: var(--auth-ui-error);
  margin-left: 0.25rem;
}
</style>
