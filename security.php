<?php
/*
|--------------------------------------------------------------------------
| Security Middleware - Gabriel Poças
|--------------------------------------------------------------------------
| Proteções implementadas:
| - Sessão segura (cookies protegidos)
| - Regeneração contra Session Fixation
| - Proteção contra Session Hijacking
| - CSRF Token (validação + geração)
| - Rate Limiting básico
| - Sanitização de saída
| - Controle de acesso por role
| - Headers de segurança
| - Timeout de sessão
|
| Autor: Gabriel
|--------------------------------------------------------------------------
*/

// ----------------------------------
// 1. Configuração de erros (produção)
// ----------------------------------
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/php-error.log');

// ----------------------------------
// 2. Headers de segurança
// ----------------------------------
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer");

// ----------------------------------
// 3. Sessão segura
// ----------------------------------
session_start([
    'cookie_httponly' => true,
    'cookie_secure'   => isset($_SERVER['HTTPS']),
    'cookie_samesite' => 'Strict'
]);

// ----------------------------------
// 4. Timeout de sessão (30 min)
// ----------------------------------
if (isset($_SESSION['last_activity']) && time() - $_SESSION['last_activity'] > 1800) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=session_timeout");
    exit;
}
$_SESSION['last_activity'] = time();

// ----------------------------------
// 5. Bloqueio de usuário não autenticado
// ----------------------------------
if (!isset($_SESSION['username'])) {
    header("Location: login.php?error=auth");
    exit;
}

// ----------------------------------
// 6. Proteção contra Session Fixation
// ----------------------------------
if (empty($_SESSION['session_regenerated'])) {
    session_regenerate_id(true);
    $_SESSION['session_regenerated'] = time();
}

// Regenera a cada 5 minutos
if (time() - $_SESSION['session_regenerated'] > 300) {
    session_regenerate_id(true);
    $_SESSION['session_regenerated'] = time();
}

// ----------------------------------
// 7. Proteção contra Session Hijacking
// (User-Agent + parte do IP)
// ----------------------------------
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$ip_parts = explode('.', $ip);
$ip_partial = $ip_parts[0] ?? ''; // evita instabilidade de IP dinâmico

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$fingerprint = hash('sha256', $ip_partial . $ua);

if (!isset($_SESSION['fingerprint'])) {
    $_SESSION['fingerprint'] = $fingerprint;
} elseif ($_SESSION['fingerprint'] !== $fingerprint) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=session_hijack");
    exit;
}

// ----------------------------------
// 8. CSRF Protection (POST)
// ----------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!isset($_POST['csrf_token'], $_SESSION['csrf_token'])) {
        http_response_code(403);
        exit("CSRF ERROR");
    }

    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        exit("CSRF INVALID TOKEN");
    }
}

// Geração de token (rotaciona a cada request)
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// ----------------------------------
// 9. Rate Limit básico por IP + página
// ----------------------------------
$page = basename($_SERVER['PHP_SELF']);
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

$key = $client_ip . '_' . $page;

if (!isset($_SESSION['rate_limit'][$key])) {
    $_SESSION['rate_limit'][$key] = ['count' => 0, 'time' => time()];
}

if (time() - $_SESSION['rate_limit'][$key]['time'] > 60) {
    $_SESSION['rate_limit'][$key] = ['count' => 0, 'time' => time()];
}

$_SESSION['rate_limit'][$key]['count']++;

if ($_SESSION['rate_limit'][$key]['count'] > 300) {
    http_response_code(429);
    exit("Too many requests");
}

// ----------------------------------
// 10. Função para escapar saída (XSS)
// ----------------------------------
function escape_html($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// ----------------------------------
// 11. Controle de acesso por role
// ----------------------------------
function require_role($role) {
    if (($_SESSION['role'] ?? '') !== $role) {
        http_response_code(403);
        exit("ACCESS DENIED");
    }
}

// ----------------------------------
// 12. Helper para CSRF no formulário
// ----------------------------------
function csrf_token_input() {
    return '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
}
