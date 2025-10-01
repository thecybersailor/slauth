<template>
  <a
    :href="computedHref"
    :class="['aira-anchor', className]"
    :data-testid="dataTestid"
  >
    {{ text }}
  </a>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { AnchorProps } from '../../types'
import { buildUrlWithPreservedParams } from '../../lib/redirectManager'

const props = defineProps<AnchorProps>()

// Automatically preserve URL parameters (redirect, state, etc.)
const computedHref = computed(() => {
  const href = props.href
  
  // If href already has query parameters or is external, use as is
  if (href.includes('?') || href.startsWith('http://') || href.startsWith('https://')) {
    return href
  }
  
  // Otherwise, build URL with preserved parameters
  return buildUrlWithPreservedParams(href)
})
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