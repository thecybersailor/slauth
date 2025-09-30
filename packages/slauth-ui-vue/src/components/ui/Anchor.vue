<template>
  <a
    :href="href"
    :class="['aira-anchor', className]"
    :data-testid="dataTestid"
  >
    {{ text }}
  </a>
</template>

<script setup lang="ts">
import type { AnchorProps } from '../../types'

const props = defineProps<AnchorProps>()
</script>

<style scoped>
.aira-anchor {
  color: var(--auth-ui-primary);
  text-decoration: none;
  font-size: 0.875rem;
  cursor: pointer;
  transition: color 0.2s;
}

.aira-anchor:hover {
  color: var(--auth-ui-primary-hover);
  text-decoration: underline;
}
</style>