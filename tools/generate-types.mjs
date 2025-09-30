#!/usr/bin/env node

/**
 * Custom TypeScript type generator for @cybersailor/slauth-ts
 * This script generates TypeScript types from Swagger JSON and optimizes naming
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const config = {
  authApiPath: path.resolve(__dirname, '../docs/specs/auth-api.json'),
  adminApiPath: path.resolve(__dirname, '../docs/specs/admin-api.json'),
  outputDir: path.resolve(__dirname, '../packages/slauth-ts/src/types'),
  authOutputFile: 'auth-api.ts',
  adminOutputFile: 'admin-api.ts'
};

// Package name prefixes to remove
const packagePrefixes = [
  'GithubComThecybersailorSlauthPkgTypes',
  'PkgController'
];

/**
 * Optimize type names in generated TypeScript content
 */
function optimizeTypeNames(content) {
  let optimizedContent = content;

  // Remove package prefixes from type names
  for (const prefix of packagePrefixes) {
    // Replace export declarations (enum, interface, type)
    const exportRegex = new RegExp(`export (enum|interface|type) ${prefix}([A-Z][a-zA-Z0-9_]*)`, 'g');
    optimizedContent = optimizedContent.replace(exportRegex, 'export $1 $2');

    // Replace type references in the content
    const referenceRegex = new RegExp(`\\b${prefix}([A-Z][a-zA-Z0-9_]*)\\b`, 'g');
    optimizedContent = optimizedContent.replace(referenceRegex, '$1');
  }

  return optimizedContent;
}

/**
 * Generate TypeScript types for a specific API
 */
function generateTypesForApi(apiPath, outputFile) {
  console.log(`Generating types from ${apiPath}...`);

  try {
    const outputPath = path.join(config.outputDir, outputFile);

    // Use npx to generate the types first
    const command = `npx swagger-typescript-api generate --path "${apiPath}" --output "${config.outputDir}" --name "${outputFile}" --no-client`;
    console.log(`Running: ${command}`);

    execSync(command, {
      cwd: path.join(__dirname, '../packages/slauth-ts'),
      stdio: 'inherit'
    });

    // Read the generated file
    const generatedContent = fs.readFileSync(outputPath, 'utf8');

    // Optimize the generated content
    const optimizedContent = optimizeTypeNames(generatedContent);

    // Write the optimized content back to file
    fs.writeFileSync(outputPath, optimizedContent, 'utf8');

    console.log(`✅ Generated and optimized types: ${outputPath}`);

  } catch (error) {
    console.error(`❌ Error generating types for ${apiPath}:`, error);
    throw error;
  }
}

/**
 * Main function
 */
function main() {
  console.log('🚀 Starting TypeScript type generation with optimized naming...');

  // Ensure output directory exists
  if (!fs.existsSync(config.outputDir)) {
    fs.mkdirSync(config.outputDir, { recursive: true });
  }

  try {
    // Generate auth API types
    if (fs.existsSync(config.authApiPath)) {
      generateTypesForApi(config.authApiPath, config.authOutputFile);
    } else {
      console.warn(`⚠️  Auth API spec not found: ${config.authApiPath}`);
    }

    // Generate admin API types
    if (fs.existsSync(config.adminApiPath)) {
      generateTypesForApi(config.adminApiPath, config.adminOutputFile);
    } else {
      console.warn(`⚠️  Admin API spec not found: ${config.adminApiPath}`);
    }

    console.log('🎉 Type generation completed successfully!');

  } catch (error) {
    console.error('💥 Type generation failed:', error);
    process.exit(1);
  }
}

// Run the script
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main, optimizeTypeNames };
