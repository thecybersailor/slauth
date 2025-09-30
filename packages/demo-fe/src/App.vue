<script setup lang="ts">
import { ref, onMounted } from 'vue'


const theme = ref<'light' | 'dark' | 'auto'>('auto')


const themeOptions = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'auto', label: 'Auto' }
]


const applyTheme = (newTheme: 'light' | 'dark' | 'auto') => {
  theme.value = newTheme
  
  
  let actualTheme = newTheme
  if (newTheme === 'auto') {
    
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    actualTheme = prefersDark ? 'dark' : 'light'
  }
  
  
  document.documentElement.setAttribute('data-theme', actualTheme)
  
  
  updateBodyBackground(actualTheme as 'light' | 'dark')
  
  
  localStorage.setItem('theme-preference', newTheme)
}


const updateBodyBackground = (theme: 'light' | 'dark') => {
  if (theme === 'dark') {
    document.body.style.backgroundColor = '#111827'
    document.body.style.color = '#f9fafb'
  } else {
    document.body.style.backgroundColor = '#ffffff'
    document.body.style.color = '#111827'
  }
}


const handleSystemThemeChange = (e: MediaQueryListEvent) => {
  if (theme.value === 'auto') {
    const actualTheme = e.matches ? 'dark' : 'light'
    document.documentElement.setAttribute('data-theme', actualTheme)
    updateBodyBackground(actualTheme)
  }
}


onMounted(() => {
  
  const savedTheme = localStorage.getItem('theme-preference') as 'light' | 'dark' | 'auto' | null
  if (savedTheme) {
    applyTheme(savedTheme)
  } else {
    applyTheme('auto')
  }
  
  
  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  mediaQuery.addEventListener('change', handleSystemThemeChange)
  
  
  return () => {
    mediaQuery.removeEventListener('change', handleSystemThemeChange)
  }
})
</script>

<template>
  <div class="app">
    <div class="theme-selector">
      <div class="theme-selector__options">
        <label
          v-for="option in themeOptions"
          :key="option.value"
          class="theme-option"
          :class="{ 'theme-option--active': theme === option.value }"
        >
          <input
            v-model="theme"
            :value="option.value"
            type="radio"
            name="theme"
            class="theme-option__input"
            @change="applyTheme(option.value as 'light' | 'dark' | 'auto')"
          />
          <span class="theme-option__label">{{ option.label }}</span>
        </label>
      </div>
    </div>
    
    <router-view />
  </div>
</template>

<style scoped>
.app {
  min-height: 100vh;
  position: relative;
}

:global(body) {
  transition: background-color 0.3s ease, color 0.3s ease;
  margin: 0;
  padding: 0;
}

.theme-selector {
  position: fixed;
  bottom: 1rem;
  left: 1rem;
  z-index: 1000;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(0, 0, 0, 0.1);
  border-radius: 12px;
  padding: 0.75rem;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  transition: all 0.2s ease;
}

.theme-selector:hover {
  box-shadow: 0 8px 15px -3px rgba(0, 0, 0, 0.15);
}

.theme-selector__label {
  font-size: 0.75rem;
  font-weight: 600;
  color: #6b7280;
  margin-bottom: 0.5rem;
  text-align: center;
}

.theme-selector__options {
  display: flex;
  gap: 0.25rem;
}

.theme-option {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0.5rem 0.75rem;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  min-width: 3rem;
}

.theme-option:hover {
  background: rgba(0, 0, 0, 0.05);
}

.theme-option--active {
  background: #3b82f6;
  color: white;
}

.theme-option--active:hover {
  background: #2563eb;
}

.theme-option__input {
  display: none;
}

.theme-option__label {
  font-size: 0.75rem;
  font-weight: 500;
}

[data-theme="dark"] .theme-selector {
  background: rgba(31, 41, 55, 0.95);
  border-color: rgba(255, 255, 255, 0.1);
  color: #f9fafb;
}

[data-theme="dark"] .theme-selector__label {
  color: #9ca3af;
}

[data-theme="dark"] .theme-option:hover {
  background: rgba(255, 255, 255, 0.1);
}

[data-theme="dark"] .theme-option--active {
  background: #3b82f6;
  color: white;
}

@media (max-width: 640px) {
  .theme-selector {
    top: 0.5rem;
    right: 0.5rem;
    padding: 0.5rem;
  }
  
  .theme-option {
    padding: 0.375rem 0.5rem;
    min-width: 2.5rem;
  }
  
  .theme-option__label {
    font-size: 0.625rem;
  }
}
</style>
