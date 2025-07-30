# Contributing to Morden Security

Thank you for your interest in contributing to Morden Security! This document outlines the guidelines for contributing to this project.

## Development Setup

### Prerequisites
- PHP 7.4 or higher
- WordPress 5.0 or higher
- SQLite3 extension
- Composer
- Node.js (for asset building)

### Local Development
git clone https://github.com/sadewadee/morden-security.git
cd morden-security
composer install
npm install


## Code Standards

### PHP Standards
- Follow WordPress Coding Standards
- Use PSR-4 autoloading
- Write unit tests for new functionality
- Maintain backward compatibility

### Security Guidelines
- Never trust user input
- Use WordPress security functions
- Validate and sanitize all data
- Use nonces for form submissions

### Testing Requirements
### Run PHPUnit tests
vendor/bin/phpunit
### Run code style checks
vendor/bin/phpcs –standard=WordPress src/
### Fix code style issues
vendor/bin/phpcbf –standard=WordPress src/


## Submitting Changes

### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Commit Messages
Use conventional commit messages:
feat: add new bot detection algorithm fix: resolve IP blocking issue docs: update installation guide test: add unit tests for firewall


## Security Vulnerabilities

If you discover a security vulnerability, please email security@mordenhost.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the GPL v2 or later license.
