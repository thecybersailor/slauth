# Contributing to Slauth

Thank you for your interest in contributing to Slauth! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Detailed steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (Go version, OS, database)
- Any relevant logs or error messages

### Suggesting Features

Feature requests are welcome! Please provide:

- A clear and descriptive title
- Detailed description of the proposed feature
- Why this feature would be useful
- Any examples of how it would work

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write or update tests
5. Ensure all tests pass
6. Commit your changes (see commit message guidelines below)
7. Push to your fork
8. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Node.js 16.0 or higher
- PostgreSQL, MySQL, or SQLite for testing
- Make

### Getting Started

1. Clone the repository:
```bash
git clone https://github.com/thecybersailor/slauth.git
cd slauth
```

2. Install dependencies:
```bash
# Install Go dependencies
go mod download

# Install frontend dependencies
cd packages/slauth-ts
npm install

cd ../slauth-ui-vue
npm install
```

3. Build the project:
```bash
make all
```

4. Run tests:
```bash
make test
```

## Development Workflow

### Project Structure

- `pkg/` - Core Go library code
- `packages/slauth-ts/` - TypeScript SDK
- `packages/slauth-ui-vue/` - Vue 3 UI components
- `tests/` - Comprehensive test suite
- `demo/` - Example applications
- `templates/` - Email and SMS templates

### Running Tests

```bash
# All tests with SQLite (default)
make test

# PostgreSQL tests
make test-pgsql

# MySQL tests
make test-mysql

# Custom configuration
make test-custom CONF_FILE=your-config.conf
```

### Building Documentation

```bash
# Generate API documentation
make docs-install  # Install swag tool (first time only)
make all          # Generates API specs and types
```

### Code Style

#### Go Code

- Follow standard Go conventions (`gofmt`, `golint`)
- Use meaningful variable and function names
- Add comments for exported functions
- Keep functions focused and small
- Avoid unnecessary abstractions

**Important Project Rules:**
- Do NOT use try-catch error wrapping patterns
- Do NOT add fallback mechanisms or error recovery
- Keep error handling direct and simple
- Minimize abstractions - only add when absolutely necessary

#### TypeScript/Vue Code

- Use TypeScript for type safety
- Follow Vue 3 Composition API patterns
- Use Prettier for formatting
- Write descriptive component names

### Testing Guidelines

- Maintain 100% test coverage for critical paths
- Write tests that are clear and maintainable
- Test both success and failure cases
- Use meaningful test names that describe the scenario
- All tests must be placed in the `tests/` directory

Example test structure:
```go
func TestUserSignUp(t *testing.T) {
    // Setup
    ctx := context.Background()
    
    // Execute
    result, err := authService.SignUp(ctx, validRequest)
    
    // Assert
    assert.NoError(t, err)
    assert.NotNil(t, result.User)
}
```

### Commit Message Guidelines

Follow the conventional commits specification:

```
type(scope): subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(auth): add WebAuthn support

fix(oauth): correct Google OAuth token refresh

docs(readme): update installation instructions

test(mfa): add tests for TOTP verification
```

### Pull Request Process

1. Update documentation if needed
2. Add or update tests for your changes
3. Ensure all tests pass
4. Update CHANGELOG.md with your changes
5. Request review from maintainers

Your PR should:
- Have a clear title and description
- Reference any related issues
- Include test coverage
- Pass all CI checks
- Follow code style guidelines

## API Design Guidelines

When adding or modifying APIs:

1. Follow RESTful conventions
2. Use consistent naming patterns
3. Provide clear error messages
4. Add OpenAPI documentation
5. Consider backward compatibility
6. Version breaking changes appropriately

## Adding Custom Providers

To add a new authentication provider:

1. Create provider in `pkg/providers/`
2. Implement the provider interface
3. Add configuration options
4. Write comprehensive tests
5. Update documentation
6. Add example usage

## Release Process

Maintainers handle releases. The process includes:

1. Update version numbers
2. Update CHANGELOG.md
3. Create git tag
4. Build and test release artifacts
5. Publish npm packages
6. Create GitHub release

## Getting Help

- Check existing documentation and issues
- Ask questions in GitHub Discussions
- Contact maintainers for complex questions

## Contributor License Agreement

By contributing to Slauth, you agree that:

1. CYBERSAILOR PTE. LTD. may adjust the open-source license as needed
2. Your contributed code may be used for commercial purposes
3. You have the right to submit your contributions
4. Your contributions are provided under the project's license

## Recognition

Contributors will be recognized in:
- GitHub contributors page
- Release notes (for significant contributions)
- Project acknowledgments

Thank you for contributing to Slauth!
