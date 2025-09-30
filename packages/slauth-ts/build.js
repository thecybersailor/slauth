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
