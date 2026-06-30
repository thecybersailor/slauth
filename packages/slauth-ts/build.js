#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')

console.log('🏗️  Building @cybersailor/slauth-ts...')

// Clean dist directory
console.log('🧹 Cleaning dist directory...')
execSync('npm run clean', { stdio: 'inherit' })

// Build CommonJS
console.log('📦 Building CommonJS...')
execSync('npm run build:cjs', { stdio: 'inherit' })

// Build ESM
console.log('📦 Building ESM...')
execSync('npm run build:esm', { stdio: 'inherit' })

// TypeScript's ESNext emit preserves extensionless relative imports. The package
// ESM export is loaded directly by Node, so published files must use .js suffixes.
console.log('🔗 Fixing ESM import specifiers...')
fixEsmImportSpecifiers(path.join(__dirname, 'dist/esm'))

// Build types
console.log('📦 Building types...')
execSync('npm run build:types', { stdio: 'inherit' })

// Copy main type definition to root
console.log('📋 Copying type definitions...')
const mainTypesPath = path.join(__dirname, 'dist/types/index.d.ts')
const rootTypesPath = path.join(__dirname, 'dist/index.d.ts')

if (fs.existsSync(mainTypesPath)) {
  fs.copyFileSync(mainTypesPath, rootTypesPath)
  console.log('✅ Type definitions copied')
} else {
  console.warn('⚠️  Main type definition not found')
}

// Create package.json for ESM
console.log('📄 Creating ESM package.json...')
const esmPackageJson = {
  type: 'module'
}

fs.writeFileSync(
  path.join(__dirname, 'dist/esm/package.json'),
  JSON.stringify(esmPackageJson, null, 2)
)

// Create package.json for CJS
console.log('📄 Creating CJS package.json...')
const cjsPackageJson = {
  type: 'commonjs'
}

fs.writeFileSync(
  path.join(__dirname, 'dist/cjs/package.json'),
  JSON.stringify(cjsPackageJson, null, 2)
)

console.log('✅ Build completed successfully!')
console.log('')
console.log('📁 Output structure:')
console.log('  dist/')
console.log('  ├── cjs/           # CommonJS build')
console.log('  ├── esm/           # ESM build')
console.log('  ├── types/         # TypeScript definitions')
console.log('  └── index.d.ts     # Main type definitions')

function fixEsmImportSpecifiers(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      fixEsmImportSpecifiers(fullPath)
      continue
    }
    if (!entry.isFile() || !entry.name.endsWith('.js')) continue
    const before = fs.readFileSync(fullPath, 'utf8')
    const after = before
      .replace(/\b(from\s*['"])(\.{1,2}\/[^'"]+)(['"])/g, addJsExtension)
      .replace(/\b(import\s*\(\s*['"])(\.{1,2}\/[^'"]+)(['"]\s*\))/g, addJsExtension)
    if (after !== before) {
      fs.writeFileSync(fullPath, after)
    }
  }
}

function addJsExtension(_match, prefix, specifier, suffix) {
  if (/\.(?:mjs|cjs|js|json|node)$/.test(specifier)) {
    return `${prefix}${specifier}${suffix}`
  }
  return `${prefix}${specifier}.js${suffix}`
}
