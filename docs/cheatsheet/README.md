# Slauth Cheatsheets

Quick reference guides for common development patterns in the Slauth authentication system.

## Available Cheatsheets

### [Tags System](./tags.md)
How to implement tagging system for any entity with polymorphic relations.
- Model configuration
- Controller filtering
- Frontend components
- Tag management operations

### [Pin Response Format & Testing](./pin-response-testing.md)
Understanding Pin framework response format and writing correct test assertions.
- Pin Response structure
- HTTP status code rules (401 vs 200)
- Test assertion methods (HasError, MatchObject)
- Common test patterns
- Error handling in controllers

## Usage Guidelines

1. **For AI Assistants**: These cheatsheets are designed to be AI-readable and directly executable
2. **Keep It Concise**: Each cheatsheet should be under 200 lines
3. **Show, Don't Tell**: Include code examples, not explanations
4. **Include Context**: Provide file paths, search keywords, and test cases

## Contributing

When adding a new cheatsheet:
1. Follow the template in `tags.md`
2. Keep it under 200 lines
3. Include all required sections (Steps, Files, Reference Code, Test Cases, Search Keywords)
4. Update this README.md

