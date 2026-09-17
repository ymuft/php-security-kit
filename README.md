# PHP Security Kit

A lightweight PHP security middleware experiment focused on common protections for small applications without requiring a full framework.

## What it covers

- secure session cookie settings (`HttpOnly`, `Secure`, `SameSite`)
- periodic session ID regeneration
- basic session fingerprinting using client information
- CSRF token generation and validation for POST requests
- simple request rate limiting
- role-based access checks
- security-related HTTP headers
- automatic session timeout handling
- HTML output escaping helper

## Usage

Copy `security.php` into your project and include it before protected page output:

```php
require_once __DIR__ . '/security.php';
```

The middleware expects an authenticated session to contain `$_SESSION['username']`. Pages that use role checks can also provide `$_SESSION['role']`.

### CSRF-protected form

```php
<form method="POST">
    <?= csrf_token_input() ?>
    <input type="text" name="data">
    <button type="submit">Send</button>
</form>
```

### Role check

```php
require_role('admin');
```

## Project structure

```text
php-security-kit/
├── security.php
├── README.md
└── LICENSE
```

## Notes

This repository is intentionally small and dependency-free. It is useful as a reference implementation and as a starting point for controlled projects, but security requirements vary by application and deployment environment. Review and adapt the controls before using them in production.

## License

Released under the MIT License.
