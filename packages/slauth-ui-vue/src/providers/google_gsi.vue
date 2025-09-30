<template>
    <div>
        <div id="google_login_button" :style="containerStyle"></div>
    </div>
</template>
<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, computed } from 'vue'
import { useAuthContext } from '../composables/useAuthContext'


declare global {
  interface Window {
    google: any
  }
}

// Props
const props = defineProps<{
  localization?: any 
}>()


const { authClient, authConfig } = useAuthContext()

// Emits
const emit = defineEmits<{
  credential: [data: any]
}>()

// State
const inited = ref(false)
const scriptLoaded = ref(false)


const variables = computed(() => {
  const appearance = authConfig?.appearance
  if (typeof appearance === 'object' && appearance?.variables) {
    return appearance.variables.default || {}
  }
  return {}
})


const containerStyle = computed(() => {
  const space = variables.value.space || {}
  
  return {
    width: '100%', 
    minHeight: '40px' 
  }
})

// Methods
const init = () => {
  if (scriptLoaded.value && !inited.value) {
    inited.value = true
    const clientId = authConfig?.googleClientId || import.meta.env.VITE_GOOGLE_CLIENT_ID
    
    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: handleCredentialResponse,
      auto_select: false, 
      cancel_on_tap_outside: true 
    })
    
    
    setTimeout(() => {
      const container = document.getElementById('google_login_button')
      if (container) {
        
        const containerWidth = container.offsetWidth || 300 
        
        
        const buttonConfig = {
          type: 'standard',
          size: 'large', 
          width: containerWidth, 
          text: 'signin_with',
          shape: 'rectangular',
          theme: 'outline'
        }
        
        window.google.accounts.id.renderButton(container, buttonConfig)
      }
    }, 100)
  }
}

const handleCredentialResponse = (rst: any) => {
  
  const clientId = authConfig?.googleClientId || import.meta.env.VITE_GOOGLE_CLIENT_ID
  emit('credential', {
    credential: rst.credential,
    client_id: clientId
  })
}

const loadScript = () => {
  const script = document.createElement('script')
  script.src = 'https://accounts.google.com/gsi/client'
  script.async = true
  document.body.appendChild(script)
  script.onload = () => {
    scriptLoaded.value = true
  }
}

// Watchers
watch(scriptLoaded, () => {
  init()
})

// Lifecycle
onMounted(() => {
  loadScript()
})
</script>