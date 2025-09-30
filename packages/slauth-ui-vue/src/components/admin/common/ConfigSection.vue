<template>
  <section :class="['config-section', { 'config-section--dark': darkMode, 'config-section--collapsed': !isOpen }]">
    <div class="section-header" @click="toggle">
      <div class="section-header__content">
        <h3>{{ title }}</h3>
        <p v-if="description" class="section-description">{{ description }}</p>
      </div>
      <button class="section-toggle" type="button">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M5 7.5L10 12.5L15 7.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
    </div>
    <div v-show="isOpen" class="section-content">
      <slot />
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'

const props = defineProps<{
  title: string
  description?: string
  defaultOpen?: boolean
}>()

const adminContext = useAdminContext()
const darkMode = computed(() => adminContext.value.darkMode ?? false)

const isOpen = ref(props.defaultOpen ?? true)

const toggle = () => {
  isOpen.value = !isOpen.value
}
</script>

<style scoped>
.config-section {
  background: var(--section-bg, #f9fafb);
  margin-bottom: 16px;
  border-radius: 8px;
  border: 1px solid var(--section-border, #e5e7eb);
  overflow: hidden;
}

.config-section--dark {
  --section-bg: #374151;
  --section-border: #4b5563;
  --section-text: #f9fafb;
  --section-text-secondary: #d1d5db;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 24px;
  cursor: pointer;
  user-select: none;
  transition: background-color 0.2s;
}

.section-header:hover {
  background: var(--section-hover, rgba(0, 0, 0, 0.02));
}

.config-section--dark .section-header:hover {
  background: var(--section-hover, rgba(255, 255, 255, 0.05));
}

.section-header__content {
  flex: 1;
}

.section-header h3 {
  margin: 0 0 4px 0;
  color: var(--section-text, #374151);
  font-size: 18px;
  font-weight: 600;
}

.section-description {
  margin: 0;
  color: var(--section-text-secondary, #6b7280);
  font-size: 14px;
  line-height: 1.5;
}

.section-toggle {
  flex-shrink: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  color: var(--section-text, #374151);
  cursor: pointer;
  transition: transform 0.2s;
  margin-left: 16px;
}

.config-section--collapsed .section-toggle {
  transform: rotate(-90deg);
}

.section-content {
  padding: 24px 24px 24px 24px;
}
</style>
