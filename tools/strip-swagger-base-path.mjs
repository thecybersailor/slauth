#!/usr/bin/env node

import fs from 'fs'

const [, , filePath, prefix] = process.argv

if (!filePath || !prefix) {
  console.error('Usage: node tools/strip-swagger-base-path.mjs <swagger-json> <prefix>')
  process.exit(1)
}

const normalizedPrefix = prefix.replace(/\/+$/, '')
if (!normalizedPrefix.startsWith('/')) {
  console.error('prefix must start with /')
  process.exit(1)
}

const spec = JSON.parse(fs.readFileSync(filePath, 'utf8'))
const nextPaths = {}

for (const [path, value] of Object.entries(spec.paths || {})) {
  if (!path.startsWith(normalizedPrefix + '/') && path !== normalizedPrefix) {
    nextPaths[path] = value
    continue
  }
  const stripped = path.slice(normalizedPrefix.length) || '/'
  nextPaths[stripped] = value
}

spec.paths = nextPaths
fs.writeFileSync(filePath, JSON.stringify(spec, null, 2) + '\n')
