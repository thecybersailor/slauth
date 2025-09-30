<template>
  <div class="flex min-h-svh w-full items-center justify-center p-6 md:p-10">
    <div class="w-full max-w-sm">
      <div class="flex flex-col gap-6">
        <AuthConfig
          :auth-config="authConfig"
          :auth-client="authClient"
          :localization="localizationConfig"
          :dark-mode="false"
        >
          <Auth />
        </AuthConfig>
        
        <!-- Admin Panel Link -->
        <div class="text-center mt-4">
          <router-link
            to="/admin"
            class="inline-flex items-center px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-900 transition-colors"
            data-testid="admin-link"
          >
            Admin Panel
          </router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
// @ts-ignore
import { Auth, AuthConfig } from '@cybersailor/slauth-ui-vue'
import { authClient, authConfig, localizationConfig } from '../lib/auth'
</script>