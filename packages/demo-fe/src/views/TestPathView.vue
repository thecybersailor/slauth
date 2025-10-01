<template>
  <div class="test-path-container">
    <div class="test-path-content">
      <h1 class="test-path-title">Test Path Page</h1>
      <div class="test-path-info">
        <p class="test-path-label">Current Path:</p>
        <p class="test-path-value" data-testid="current-path">{{ currentPath }}</p>
      </div>
      <div class="test-path-info">
        <p class="test-path-label">Full URL:</p>
        <p class="test-path-value" data-testid="current-url">{{ currentUrl }}</p>
      </div>
      <div class="test-path-info">
        <p class="test-path-label">Query Params:</p>
        <p class="test-path-value" data-testid="query-params">{{ queryParams }}</p>
      </div>
      <router-link to="/" class="btn btn-primary">Go Home</router-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()

const currentPath = computed(() => route.fullPath)
const currentUrl = computed(() => window.location.href)
const queryParams = computed(() => JSON.stringify(route.query, null, 2))
</script>

<style scoped>
.test-path-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #f3f4f6;
  padding: 1rem;
}

.test-path-content {
  max-width: 48rem;
  width: 100%;
  padding: 2rem;
  background-color: white;
  border-radius: 0.5rem;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
  border: 1px solid #e5e7eb;
}

.test-path-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: #111827;
  margin: 0 0 2rem 0;
  text-align: center;
}

.test-path-info {
  margin-bottom: 1.5rem;
}

.test-path-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: #6b7280;
  margin: 0 0 0.5rem 0;
}

.test-path-value {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #111827;
  background-color: #f9fafb;
  padding: 0.75rem;
  border-radius: 0.375rem;
  border: 1px solid #e5e7eb;
  margin: 0;
  word-break: break-all;
  white-space: pre-wrap;
}

.btn {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  border-radius: 0.375rem;
  font-weight: 500;
  text-decoration: none;
  text-align: center;
  transition: all 0.15s ease;
  margin-top: 1rem;
}

.btn-primary {
  background-color: #3b82f6;
  color: white;
}

.btn-primary:hover {
  background-color: #2563eb;
}
</style>

