# 🔐 PHP Security Core

Minimal and practical security middleware for PHP applications.

Designed for developers who want solid protection without relying on heavy frameworks.

---

## 🚀 Features

- Secure session configuration (HttpOnly, Secure, SameSite)
- Protection against session fixation
- Basic session hijacking detection (IP + User-Agent)
- CSRF protection (automatic token validation)
- Basic rate limiting (per IP + endpoint)
- Role-based access control
- Security headers (XSS, clickjacking, etc.)
- Session timeout handling

---

## 📦 Installation

Just include the middleware in any protected page:

```php
require_once __DIR__ . '/core/security.php';
```

## 🧪 CSRF Protection Example

```php
<form method="POST">
    <?php echo csrf_token_input(); ?>
    <input type="text" name="data">
    <button type="submit">Send</button>
</form>
```

---

### ✔ Estrutura de pastas formatada:

```md
## 📁 Suggested Structure
/core
    security.php

/logs
    php-error.log

/public
    index.php
    login.php
