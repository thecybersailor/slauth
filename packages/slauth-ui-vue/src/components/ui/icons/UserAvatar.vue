<template>
  <div class="user-avatar">
    <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="8" r="4" stroke="currentColor" stroke-width="2"/>
      <path d="M6 21c0-3.314 2.686-6 6-6s6 2.686 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    </svg>
  </div>
</template>

<script setup lang="ts">
interface Props {
  size?: number
}

withDefaults(defineProps<Props>(), {
  size: 48
})
</script>

<style scoped>
.user-avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: var(--admin-border, #e5e7eb);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  color: var(--admin-text, #6b7280);
}

.user-avatar svg {
  width: 28px;
  height: 28px;
}
</style>
