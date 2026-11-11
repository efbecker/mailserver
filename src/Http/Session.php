<?php

declare(strict_types=1);

namespace MailPlatform\Http;

/**
 * Sessão PHP endurecida (cookie Secure/HttpOnly/SameSite=Strict, id regenerado
 * no login) + token CSRF exigido em toda requisição que altera estado.
 *
 * Áreas independentes: "admin" (painel) e "webmail" (cliente final).
 */
final class Session
{
    public const IDLE_TIMEOUT = 1800;     // 30 min sem atividade
    public const ABSOLUTE_TIMEOUT = 43200; // 12 h

    private bool $started = false;

    public function __construct(private readonly bool $secure = true)
    {
    }

    public function start(): void
    {
        if ($this->started) {
            return;
        }
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_name('MPSESSID');
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'secure' => $this->secure,
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');
            session_start();
        }
        $this->started = true;
        $now = time();
        if (!isset($_SESSION['_created'])) {
            $_SESSION['_created'] = $now;
        }
        foreach (['admin', 'webmail'] as $area) {
            $a = $_SESSION[$area] ?? null;
            if (is_array($a) && (
                $now - (int) ($a['last_seen'] ?? 0) > self::IDLE_TIMEOUT
                || $now - (int) ($a['login_at'] ?? 0) > self::ABSOLUTE_TIMEOUT
            )) {
                unset($_SESSION[$area]);
            }
        }
        if (empty($_SESSION['_csrf'])) {
            $_SESSION['_csrf'] = bin2hex(random_bytes(32));
        }
    }

    /** Libera o lock do arquivo de sessão (necessário antes de streams SSE longos). */
    public function close(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }

    public function csrfToken(): string
    {
        $this->start();
        return (string) $_SESSION['_csrf'];
    }

    public function verifyCsrf(Request $request): void
    {
        $this->start();
        $token = $request->header('x-csrf-token') ?? '';
        if (!is_string($token) || $token === '' || !hash_equals((string) $_SESSION['_csrf'], $token)) {
            throw new HttpException(403, 'csrf', 'Token CSRF inválido');
        }
    }

    /** @param array<string,mixed> $data */
    public function login(string $area, array $data): void
    {
        $this->start();
        session_regenerate_id(true);
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
        $_SESSION[$area] = $data + ['login_at' => time(), 'last_seen' => time()];
    }

    public function logout(string $area): void
    {
        $this->start();
        unset($_SESSION[$area]);
        session_regenerate_id(true);
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    }

    /** @return array<string,mixed>|null */
    public function area(string $area): ?array
    {
        $this->start();
        $a = $_SESSION[$area] ?? null;
        if (!is_array($a)) {
            return null;
        }
        $_SESSION[$area]['last_seen'] = time();
        return $a;
    }

    public function set(string $area, string $key, mixed $value): void
    {
        $this->start();
        if (isset($_SESSION[$area]) && is_array($_SESSION[$area])) {
            $_SESSION[$area][$key] = $value;
        }
    }

    public function id(): string
    {
        $this->start();
        return session_id() ?: '';
    }

    public function isSecure(): bool
    {
        return $this->secure;
    }
}
