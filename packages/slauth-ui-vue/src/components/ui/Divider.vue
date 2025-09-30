<template>
  <div :class="['aira-divider', className]">
    <div class="aira-divider__line" />
    <span
      v-if="text"
      class="aira-divider__text"
    >
      {{ text }}
    </span>
    <div class="aira-divider__line" />
  </div>
</template>

<script setup lang="ts">
import type { DividerProps } from '../../types'

// Props
defineProps<DividerProps>()
</script>

<style scoped>
.aira-divider {
  display: flex;
  align-items: center;
  margin: 1.5rem 0;
}

.aira-divider__line {
  flex: 1;
  height: 1px;
  background-color: var(--auth-ui-border);
}

.aira-divider__text {
  padding: 0 1rem;
  font-size: 0.75rem;
  color: var(--auth-ui-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
</style>
