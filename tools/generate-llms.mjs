#!/usr/bin/env node

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const projectRoot = path.resolve(__dirname, '..')

// Configuration
const GITHUB_BASE = 'https://github.com/thecybersailor/slauth/blob/main'
const DOCS_CONFIG = {
  'slauth-ts': {
    docsBase: `${GITHUB_BASE}/packages/slauth-ts/docs`,
    repoUrl: 'https://github.com/thecybersailor/slauth',
    npmUrl: 'https://www.npmjs.com/package/@cybersailor/slauth-ts',
  },
  'slauth-ui-vue': {
    docsBase: `${GITHUB_BASE}/packages/slauth-ui-vue/docs`,
    repoUrl: 'https://github.com/thecybersailor/slauth',
    npmUrl: 'https://www.npmjs.com/package/@cybersailor/slauth-ui-vue',
  },
  'pkg': {
    docsBase: `${GITHUB_BASE}/pkg/docs`,
    repoUrl: 'https://github.com/thecybersailor/slauth',
    pkgGoDevUrl: 'https://pkg.go.dev/github.com/thecybersailor/slauth',
  }
}

// Generate TypeScript SDK llms.txt and detailed docs
async function generateSlauthTS() {
  console.log('Generating packages/slauth-ts documentation...')
  
  const pkgDir = path.join(projectRoot, 'packages/slauth-ts')
  const docsDir = path.join(pkgDir, 'docs')
  const srcDir = path.join(pkgDir, 'src')
  
  // Create docs directory
  if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true })
  }
  
  const files = {
    index: path.join(srcDir, 'index.ts'),
    authApi: path.join(srcDir, 'AuthApi.ts'),
    adminApi: path.join(srcDir, 'AdminApi.ts'),
    createClients: path.join(srcDir, 'createClients.ts'),
  }

  const config = DOCS_CONFIG['slauth-ts']
  
  // Generate detailed API docs
  await generateAuthApiDocs(files.authApi, docsDir)
  await generateAdminApiDocs(files.adminApi, docsDir)
  
  // Generate llms.txt (curated overview with links)
  const content = []
  
  content.push('# @cybersailor/slauth-ts')
  content.push('')
  content.push('> Official TypeScript client library for Slauth authentication')
  content.push('')
  content.push('Key features:')
  content.push('- Multi-tenant architecture support')
  content.push('- Email/Password, OAuth, SAML, OTP authentication')
  content.push('- Auto token refresh and session management')
  content.push('- Full TypeScript support with type safety')
  content.push('')
  
  content.push('## Quick Start')
  content.push('')
  content.push(`- [Installation & Setup](${config.repoUrl}#installation): NPM installation and basic configuration`)
  content.push(`- [README](${config.repoUrl}/tree/main/packages/slauth-ts#readme): Package overview and usage examples`)
  content.push(`- [Single-tenant Example](${config.repoUrl}#single-tenant-frontend): Basic authentication setup`)
  content.push(`- [Multi-tenant Example](${config.repoUrl}#multi-tenant-frontend): Multiple isolated auth services`)
  content.push('')
  
  content.push('## API Reference')
  content.push('')
  content.push(`- [AuthApi Methods](${config.docsBase}/auth-api.md): User authentication operations (signUp, signIn, OAuth, MFA, etc)`)
  content.push(`- [AdminApi Methods](${config.docsBase}/admin-api.md): Admin user management operations (CRUD, sessions, identities)`)
  content.push(`- [Type Definitions](${config.repoUrl}/tree/main/packages/slauth-ts/src/types): TypeScript interfaces and type definitions`)
  content.push(`- [OpenAPI Specs](${config.repoUrl}/tree/main/docs/specs): Auth API and Admin API specifications`)
  content.push('')
  
  content.push('## Examples')
  content.push('')
  content.push(`- [Demo Application](${config.repoUrl}/tree/main/packages/demo-fe): Complete working example with Vue 3`)
  content.push(`- [E2E Test Suite](${config.repoUrl}/tree/main/packages/demo-fe/e2e): Real-world usage patterns`)
  content.push('')
  
  content.push('## Optional')
  content.push('')
  content.push(`- [NPM Package](${config.npmUrl}): Published package on NPM registry`)
  content.push(`- [Source Code](${config.repoUrl}/tree/main/packages/slauth-ts/src): Browse TypeScript source files`)
  content.push(`- [CHANGELOG](${config.repoUrl}/blob/main/CHANGELOG.md): Version history and release notes`)
  content.push('')

  // Write llms.txt
  const llmsTxtPath = path.join(pkgDir, 'llms.txt')
  fs.writeFileSync(llmsTxtPath, content.join('\n'))
  console.log('✓ Generated packages/slauth-ts/llms.txt')
  console.log('✓ Generated packages/slauth-ts/docs/auth-api.md')
  console.log('✓ Generated packages/slauth-ts/docs/admin-api.md')
}

// Generate Vue UI llms.txt and detailed docs
async function generateSlauthUIVue() {
  console.log('Generating packages/slauth-ui-vue documentation...')
  
  const pkgDir = path.join(projectRoot, 'packages/slauth-ui-vue')
  const docsDir = path.join(pkgDir, 'docs')
  const srcDir = path.join(pkgDir, 'src')
  
  // Create docs directory
  if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true })
  }
  
  const config = DOCS_CONFIG['slauth-ui-vue']
  
  // Generate detailed component docs
  await generateComponentsDocs(srcDir, docsDir)
  await generateComposablesDocs(srcDir, docsDir)
  
  // Generate llms.txt (curated overview with links)
  const content = []
  
  content.push('# @cybersailor/slauth-ui-vue')
  content.push('')
  content.push('> Vue 3 UI component library for Slauth authentication')
  content.push('')
  content.push('Key features:')
  content.push('- Pre-built authentication UI components')
  content.push('- Email/Password, OAuth, Magic Link, Password Recovery')
  content.push('- Dark/Light theme support with customizable styling')
  content.push('- Vue 3 Composition API with TypeScript support')
  content.push('- Responsive design and accessibility')
  content.push('')
  
  content.push('## Quick Start')
  content.push('')
  content.push(`- [Installation & Setup](${config.repoUrl}/tree/main/packages/slauth-ui-vue#installation): NPM installation and plugin configuration`)
  content.push(`- [README](${config.repoUrl}/tree/main/packages/slauth-ui-vue#readme): Package overview and basic usage`)
  content.push(`- [Demo Application](${config.repoUrl}/tree/main/packages/demo-fe): Live example with all components`)
  content.push('')
  
  content.push('## Components')
  content.push('')
  content.push(`- [Main Components](${config.docsBase}/components.md): Auth, SignIn, SignUp, VerifyOtp, ForgotPassword, UpdatePassword`)
  content.push(`- [User Management](${config.docsBase}/user-management.md): UserDashboard, UserProfile, MFA, Sessions, Security`)
  content.push(`- [Admin Components](${config.docsBase}/admin-components.md): Admin layout, user management, system stats`)
  content.push(`- [UI Components](${config.repoUrl}/tree/main/packages/slauth-ui-vue/src/components/ui): Button, Input, Dialog, Table, etc`)
  content.push('')
  
  content.push('## Composables')
  content.push('')
  content.push(`- [Composables Reference](${config.docsBase}/composables.md): useAuth, useAuthContext, useOAuthSignIn, etc`)
  content.push(`- [Source Code](${config.repoUrl}/tree/main/packages/slauth-ui-vue/src/composables): Browse composables implementation`)
  content.push('')
  
  content.push('## Styling & Theming')
  content.push('')
  content.push(`- [Theme Customization](${config.repoUrl}/tree/main/packages/slauth-ui-vue#styling): CSS variables and theme configuration`)
  content.push(`- [OAuth Button Styles](${config.repoUrl}/blob/main/packages/slauth-ui-vue/src/composables/useOAuthButtonStyles.ts): Social login button styling`)
  content.push('')
  
  content.push('## Optional')
  content.push('')
  content.push(`- [NPM Package](${config.npmUrl}): Published package on NPM registry`)
  content.push(`- [Source Code](${config.repoUrl}/tree/main/packages/slauth-ui-vue/src): Browse Vue component source files`)
  content.push(`- [Localization](${config.repoUrl}/tree/main/packages/slauth-ui-vue/src/localization): Internationalization support`)
  content.push('')

  // Write llms.txt
  const llmsTxtPath = path.join(pkgDir, 'llms.txt')
  fs.writeFileSync(llmsTxtPath, content.join('\n'))
  console.log('✓ Generated packages/slauth-ui-vue/llms.txt')
  console.log('✓ Generated packages/slauth-ui-vue/docs/*.md')
}

// Generate Go pkg llms.txt and detailed docs
async function generatePkg() {
  console.log('Generating pkg/ documentation...')
  
  const pkgDir = path.join(projectRoot, 'pkg')
  const docsDir = path.join(pkgDir, 'docs')
  
  // Create docs directory
  if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true })
  }
  
  const config = DOCS_CONFIG['pkg']
  
  // Generate detailed package docs
  await generatePackageStructureDocs(pkgDir, docsDir)
  
  // Generate llms.txt (curated overview with links)
  const content = []
  
  content.push('# pkg/')
  content.push('')
  content.push('> Slauth Go backend core library')
  content.push('')
  content.push('Key features:')
  content.push('- Multi-tenant architecture with isolated auth services')
  content.push('- Comprehensive authentication (Email, OAuth, SAML, OTP, MFA)')
  content.push('- Framework agnostic (works with Gin, Echo, Chi, net/http)')
  content.push('- Database support (PostgreSQL, MySQL, SQLite via GORM)')
  content.push('- Production-ready with extensive test coverage')
  content.push('')
  
  content.push('## Getting Started')
  content.push('')
  content.push(`- [Quick Start](${config.repoUrl}#quick-start): Basic setup with single-tenant`)
  content.push(`- [Multi-Tenant Guide](${config.repoUrl}#multi-tenant-architecture): Multiple isolated auth services`)
  content.push(`- [API Documentation](${config.pkgGoDevUrl}): Go package documentation`)
  content.push(`- [README](${config.repoUrl}#readme): Comprehensive project overview`)
  content.push('')
  
  content.push('## Architecture')
  content.push('')
  content.push(`- [Package Structure](${config.docsBase}/structure.md): Directory layout and responsibilities`)
  content.push(`- [Core Services](${config.docsBase}/services.md): AuthService, UserService, SessionService, etc`)
  content.push(`- [Models](${config.docsBase}/models.md): Database models and relationships`)
  content.push(`- [Controllers](${config.docsBase}/controllers.md): HTTP handlers and routing`)
  content.push('')
  
  content.push('## Key Concepts')
  content.push('')
  content.push(`- [Multi-Tenant Design](${config.repoUrl}#multi-tenant-architecture): Cross-service access control`)
  content.push(`- [RequestValidator](${config.repoUrl}#requestvalidator---the-key-to-cross-service-access): JWT validation middleware`)
  content.push(`- [Configuration](${config.repoUrl}/tree/main/pkg/config): Runtime database-driven config`)
  content.push(`- [Providers](${config.repoUrl}/tree/main/pkg/providers): OAuth, SAML, SMS, Email integrations`)
  content.push('')
  
  content.push('## Testing')
  content.push('')
  content.push(`- [Test Suite](${config.repoUrl}/tree/main/tests): Comprehensive backend tests`)
  content.push(`- [Demo Application](${config.repoUrl}/tree/main/demo): Example backend implementation`)
  content.push('')
  
  content.push('## Optional')
  content.push('')
  content.push(`- [Go Package](${config.pkgGoDevUrl}): Browse on pkg.go.dev`)
  content.push(`- [Source Code](${config.repoUrl}/tree/main/pkg): Browse Go source files`)
  content.push(`- [OpenAPI Specs](${config.repoUrl}/tree/main/docs/specs): API specifications`)
  content.push(`- [CONTRIBUTING](${config.repoUrl}/blob/main/CONTRIBUTING.md): Development guidelines`)
  content.push('')

  // Write llms.txt
  const llmsTxtPath = path.join(pkgDir, 'llms.txt')
  fs.writeFileSync(llmsTxtPath, content.join('\n'))
  console.log('✓ Generated pkg/llms.txt')
  console.log('✓ Generated pkg/docs/*.md')
}

// Generate detailed AuthApi documentation
async function generateAuthApiDocs(authApiPath, docsDir) {
  const content = []
  const authApiContent = fs.readFileSync(authApiPath, 'utf-8')
  const authMethods = extractClassMethods(authApiContent, 'AuthApi')
  
  content.push('# AuthApi Reference')
  content.push('')
  content.push('Authentication API client for user-facing operations.')
  content.push('')
  content.push('## Methods')
  content.push('')
  
  authMethods.forEach(method => {
    content.push(`### ${method.name}`)
    content.push('')
    if (method.comment) {
      content.push(method.comment)
      content.push('')
    }
    content.push('```typescript')
    content.push(method.signature)
    content.push('```')
    content.push('')
  })
  
  fs.writeFileSync(path.join(docsDir, 'auth-api.md'), content.join('\n'))
}

// Generate detailed AdminApi documentation
async function generateAdminApiDocs(adminApiPath, docsDir) {
  const content = []
  const adminApiContent = fs.readFileSync(adminApiPath, 'utf-8')
  const adminMethods = extractClassMethods(adminApiContent, 'AdminApi')
  
  content.push('# AdminApi Reference')
  content.push('')
  content.push('Admin API client for user management operations.')
  content.push('')
  content.push('## Methods')
  content.push('')
  
  adminMethods.forEach(method => {
    content.push(`### ${method.name}`)
    content.push('')
    if (method.comment) {
      content.push(method.comment)
      content.push('')
    }
    content.push('```typescript')
    content.push(method.signature)
    content.push('```')
    content.push('')
  })
  
  fs.writeFileSync(path.join(docsDir, 'admin-api.md'), content.join('\n'))
}

// Generate Vue components documentation
async function generateComponentsDocs(srcDir, docsDir) {
  const content = []
  const componentsDir = path.join(srcDir, 'components')
  
  content.push('# Components Reference')
  content.push('')
  
  const mainComponents = [
    'Auth.vue', 'SignIn.vue', 'SignUp.vue', 'VerifyOtp.vue',
    'ForgotPassword.vue', 'UpdatePassword.vue', 'MagicLink.vue'
  ]
  
  for (const comp of mainComponents) {
    const compPath = path.join(componentsDir, comp)
    if (fs.existsSync(compPath)) {
      const compInfo = extractVueComponentInfo(compPath)
      content.push(`## ${comp.replace('.vue', '')}`)
      content.push('')
      
      if (compInfo.comment) {
        content.push(compInfo.comment)
        content.push('')
      }
      
      if (compInfo.props.length > 0) {
        content.push('**Props:**')
        content.push('')
        compInfo.props.forEach(prop => {
          content.push(`- \`${prop.name}\`: ${prop.type}${prop.required ? ' (required)' : ''}`)
          if (prop.comment) {
            content.push(`  ${prop.comment}`)
          }
        })
        content.push('')
      }
      
      if (compInfo.events.length > 0) {
        content.push('**Events:**')
        content.push('')
        compInfo.events.forEach(event => {
          content.push(`- \`@${event.name}\`: ${event.type || 'void'}`)
          if (event.comment) {
            content.push(`  ${event.comment}`)
          }
        })
        content.push('')
      }
    }
  }
  
  fs.writeFileSync(path.join(docsDir, 'components.md'), content.join('\n'))
}

// Generate composables documentation
async function generateComposablesDocs(srcDir, docsDir) {
  const content = []
  const composablesDir = path.join(srcDir, 'composables')
  
  content.push('# Composables Reference')
  content.push('')
  
  const composableFiles = fs.readdirSync(composablesDir).filter(f => f.endsWith('.ts'))
  
  for (const file of composableFiles) {
    const filePath = path.join(composablesDir, file)
    const fileContent = fs.readFileSync(filePath, 'utf-8')
    const funcName = file.replace('.ts', '')
    const funcInfo = extractFunctionSignature(fileContent, funcName)
    
    if (funcInfo) {
      content.push(`## ${funcName}`)
      content.push('')
      if (funcInfo.comment) {
        content.push(funcInfo.comment)
        content.push('')
      }
      content.push('```typescript')
      content.push(funcInfo.signature)
      content.push('```')
      content.push('')
    }
  }
  
  fs.writeFileSync(path.join(docsDir, 'composables.md'), content.join('\n'))
}

// Generate Go package structure documentation
async function generatePackageStructureDocs(pkgDir, docsDir) {
  const content = []
  
  content.push('# Package Structure')
  content.push('')
  content.push('Overview of Slauth Go package organization.')
  content.push('')
  
  const dirs = fs.readdirSync(pkgDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name)
    .sort()
  
  for (const dir of dirs) {
    const dirPath = path.join(pkgDir, dir)
    const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.go') && !f.endsWith('_test.go'))
    
    content.push(`## ${dir}/`)
    content.push('')
    
    if (files.length > 0) {
      const firstFile = path.join(dirPath, files[0])
      const fileContent = fs.readFileSync(firstFile, 'utf-8')
      const packageComment = extractGoPackageComment(fileContent)
      if (packageComment) {
        content.push(packageComment)
        content.push('')
      }
    }
    
    content.push('**Files:**')
    content.push('')
    files.forEach(file => {
      content.push(`- ${file}`)
      const filePath = path.join(dirPath, file)
      const fileContent = fs.readFileSync(filePath, 'utf-8')
      const exports = extractGoExports(fileContent)
      
      if (exports.length > 0 && exports.length <= 10) {
        exports.forEach(exp => {
          content.push(`  - ${exp.type}: \`${exp.name}\``)
          if (exp.comment) {
            content.push(`    ${exp.comment}`)
          }
        })
      }
    })
    content.push('')
  }
  
  fs.writeFileSync(path.join(docsDir, 'structure.md'), content.join('\n'))
}

// Helper functions for TypeScript parsing
function extractExports(content) {
  const exports = []
  const exportRegex = /export\s+(?:const|function|class|interface|type)\s+(\w+)/g
  const exportFromRegex = /export\s+\{([^}]+)\}/g
  
  let match
  while ((match = exportRegex.exec(content)) !== null) {
    exports.push(match[1])
  }
  
  while ((match = exportFromRegex.exec(content)) !== null) {
    const items = match[1].split(',').map(s => s.trim().split(' as ')[0])
    exports.push(...items)
  }
  
  return [...new Set(exports)]
}

function extractClassMethods(content, className) {
  const methods = []
  
  // Find class definition
  const classRegex = new RegExp(`class\\s+${className}[^{]*\\{([\\s\\S]*?)\\n\\}`, 'm')
  const classMatch = content.match(classRegex)
  
  if (!classMatch) return methods
  
  const classBody = classMatch[1]
  
  // Extract methods with JSDoc comments
  const methodRegex = /(?:\/\*\*([\s\S]*?)\*\/\s*)?(?:async\s+)?(\w+)\s*\([^)]*\)\s*:\s*([^{]+)\s*\{/g
  
  let match
  while ((match = methodRegex.exec(classBody)) !== null) {
    const [, commentBlock, methodName, returnType] = match
    
    // Skip constructor and private methods
    if (methodName === 'constructor' || methodName.startsWith('_')) continue
    
    // Extract full method signature
    const methodStart = match.index
    const signatureMatch = classBody.slice(methodStart).match(/(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*:\s*([^{]+)/)
    
    if (signatureMatch) {
      const [, name, params, retType] = signatureMatch
      
      methods.push({
        name,
        signature: `${name}(${params}): ${retType.trim()}`,
        comment: commentBlock ? parseJSDoc(commentBlock) : null
      })
    }
  }
  
  return methods
}

function extractFunctionSignature(content, functionName) {
  // Match function with JSDoc
  const funcRegex = new RegExp(
    `(?:\\/\\*\\*([\\s\\S]*?)\\*\\/\\s*)?export\\s+(?:async\\s+)?function\\s+${functionName}\\s*(<[^>]*>)?\\s*\\(([^)]*)\\)\\s*:\\s*([^{]+)`,
    'm'
  )
  
  const match = content.match(funcRegex)
  if (!match) return null
  
  const [, commentBlock, generics, params, returnType] = match
  
  return {
    name: functionName,
    signature: `function ${functionName}${generics || ''}(${params}): ${returnType.trim()}`,
    comment: commentBlock ? parseJSDoc(commentBlock) : null
  }
}

function parseJSDoc(jsDocBlock) {
  const lines = jsDocBlock.split('\n')
    .map(line => line.trim().replace(/^\*\s?/, ''))
    .filter(line => line && !line.startsWith('@'))
  
  return lines.join(' ').trim()
}

// Helper functions for Vue parsing
function extractVueComponentInfo(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8')
  
  const info = {
    comment: null,
    props: [],
    events: []
  }
  
  // Extract props from defineProps
  const propsRegex = /defineProps<\{([^}]+)\}>/s
  const propsMatch = content.match(propsRegex)
  
  if (propsMatch) {
    const propsBlock = propsMatch[1]
    const propRegex = /(?:\/\*\*([\s\S]*?)\*\/\s*)?(\w+)(\??)\s*:\s*([^\n;]+)/g
    
    let match
    while ((match = propRegex.exec(propsBlock)) !== null) {
      const [, comment, name, optional, type] = match
      info.props.push({
        name,
        type: type.trim(),
        required: !optional,
        comment: comment ? parseJSDoc(comment) : null
      })
    }
  }
  
  // Extract events from defineEmits
  const emitsRegex = /defineEmits<\{([^}]+)\}>/s
  const emitsMatch = content.match(emitsRegex)
  
  if (emitsMatch) {
    const emitsBlock = emitsMatch[1]
    const eventRegex = /(?:\/\*\*([\s\S]*?)\*\/\s*)?(\w+)\s*:\s*\[([^\]]*)\]/g
    
    let match
    while ((match = eventRegex.exec(emitsBlock)) !== null) {
      const [, comment, name, params] = match
      info.events.push({
        name,
        type: params.trim() || 'void',
        comment: comment ? parseJSDoc(comment) : null
      })
    }
  }
  
  return info
}

// Helper functions for Go parsing
function extractGoPackageComment(content) {
  const lines = content.split('\n')
  const comments = []
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    
    if (line.startsWith('//')) {
      comments.push(line.replace('//', '').trim())
    } else if (line.startsWith('package ')) {
      break
    } else if (line && !line.startsWith('//')) {
      comments.length = 0
    }
  }
  
  return comments.join(' ').trim()
}

function extractGoExports(content) {
  const exports = []
  
  // Extract exported types, structs, interfaces
  const typeRegex = /(?:\/\/\s*([^\n]+)\n)?type\s+([A-Z]\w+)\s+(struct|interface)/g
  let match
  
  while ((match = typeRegex.exec(content)) !== null) {
    const [, comment, name, kind] = match
    exports.push({
      type: kind,
      name,
      comment: comment ? comment.trim() : null
    })
  }
  
  // Extract exported functions
  const funcRegex = /(?:\/\/\s*([^\n]+)\n)?func\s+([A-Z]\w+)/g
  
  while ((match = funcRegex.exec(content)) !== null) {
    const [, comment, name] = match
    exports.push({
      type: 'func',
      name,
      comment: comment ? comment.trim() : null
    })
  }
  
  return exports
}

// Main execution
async function main() {
  console.log('Generating llms.txt files...\n')
  
  await generateSlauthTS()
  await generateSlauthUIVue()
  await generatePkg()
  
  console.log('\n✓ All llms.txt files generated successfully!')
}

main().catch(err => {
  console.error('Error generating llms.txt files:', err)
  process.exit(1)
})

