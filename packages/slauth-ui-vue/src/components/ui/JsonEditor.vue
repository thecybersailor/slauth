<template>
  <div class="aira-json-editor" :data-status="error ? 'error' : 'idle'">
    <Label
      v-if="label"
      :text="label"
      :required="required"
      class="aira-json-editor__label"
    />
    <div
      ref="editorRef"
      :contenteditable="!readonly"
      class="aira-json-editor__field"
      :class="{ 'aira-json-editor__field--readonly': readonly }"
      :data-placeholder="placeholder"
      @blur="handleBlur"
      @input="handleInput"
    />
    <div v-if="error" class="aira-json-editor__error">
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import Label from './Label.vue'

interface JsonEditorProps {
  modelValue: string
  label?: string
  placeholder?: string
  required?: boolean
  readonly?: boolean
}

const props = withDefaults(defineProps<JsonEditorProps>(), {
  modelValue: '',
  placeholder: '{}',
  required: false,
  readonly: false
})

const emit = defineEmits<{
  'update:modelValue': [value: string]
}>()

const editorRef = ref<HTMLDivElement | null>(null)
const error = ref('')

const highlight = (json: string): string => {
  return json
    .replace(/("([^"\\]|\\.)*")\s*:/g, '<span class="json-key">$1</span>:')
    .replace(/:\s*("([^"\\]|\\.)*")/g, ': <span class="json-string">$1</span>')
    .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="json-boolean">$1</span>')
    .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>')
}

const updateEditor = (json: string) => {
  if (!editorRef.value) return
  
  const highlighted = highlight(json)
  editorRef.value.innerHTML = highlighted || ''
}

const handleInput = () => {
  if (!editorRef.value) return
  error.value = ''
}

const handleBlur = () => {
  if (!editorRef.value) return
  
  const text = editorRef.value.innerText.trim()
  
  if (!text) {
    emit('update:modelValue', '')
    editorRef.value.innerHTML = ''
    return
  }
  
  const parsed = JSON.parse(text)
  const formatted = JSON.stringify(parsed, null, 2)
  emit('update:modelValue', formatted)
  updateEditor(formatted)
  error.value = ''
}

watch(() => props.modelValue, (newValue) => {
  if (!editorRef.value) return
  if (editorRef.value.innerText === newValue) return
  updateEditor(newValue)
}, { immediate: true })

onMounted(() => {
  if (props.modelValue) {
    updateEditor(props.modelValue)
  }
})
</script>

<style scoped>
.aira-json-editor {
  margin-bottom: 1rem;
}

.aira-json-editor__label {
  display: block;
  margin-bottom: 0.5rem;
}

.aira-json-editor__field {
  width: 100%;
  min-height: 120px;
  padding: 0.75rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: var(--auth-ui-border-radius);
  background-color: var(--auth-ui-input-background);
  color: var(--auth-ui-text);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.8125rem;
  line-height: 1.6;
  white-space: pre;
  overflow-x: auto;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.aira-json-editor__field:focus {
  outline: none;
  border-color: var(--auth-ui-primary);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.aira-json-editor__field--readonly {
  cursor: default;
  background-color: var(--admin-bg, #f9fafb);
}

.aira-json-editor__field--readonly:focus {
  border-color: var(--auth-ui-border);
  box-shadow: none;
}

.aira-json-editor__field:empty:before {
  content: attr(data-placeholder);
  color: #9ca3af;
}

.aira-json-editor[data-status="error"] .aira-json-editor__field {
  border-color: var(--auth-ui-error);
}

.aira-json-editor[data-status="error"] .aira-json-editor__field:focus {
  border-color: var(--auth-ui-error);
  box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
}

.aira-json-editor__error {
  margin-top: 0.25rem;
  font-size: 0.75rem;
  color: var(--auth-ui-error);
}

.aira-json-editor__field :deep(.json-key) {
  color: #0ea5e9;
  font-weight: 500;
}

.aira-json-editor__field :deep(.json-string) {
  color: #10b981;
}

.aira-json-editor__field :deep(.json-number) {
  color: #f59e0b;
}

.aira-json-editor__field :deep(.json-boolean) {
  color: #8b5cf6;
}

.aira-json-editor__field :deep(.json-null) {
  color: #ef4444;
}
</style>
