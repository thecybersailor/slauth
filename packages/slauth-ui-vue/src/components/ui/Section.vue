<template>
  <div class="aira-section">
    <div v-if="title || $slots.title || $slots['header-actions']" class="aira-section__header">
      <slot name="title">
        <h4 v-if="title" class="aira-section__title">{{ title }}</h4>
      </slot>
      <slot name="header-actions" />
    </div>
    <div class="aira-section__body">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
interface SectionProps {
  title?: string
}

defineProps<SectionProps>()
</script>

<style scoped>
.aira-section {
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 8px;
  background: var(--admin-card-bg, white);
  overflow: hidden;
}

.aira-section__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--admin-border, #e5e7eb);
  background: var(--admin-bg, #f9fafb);
}

.aira-section__title {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--admin-text, #374151);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.aira-section__body {
  padding: 16px;
}
</style>

