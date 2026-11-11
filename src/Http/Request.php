<?php

declare(strict_types=1);

namespace MailPlatform\Http;

/** Requisição HTTP imutável com helpers de validação. */
final class Request
{
    /** @var array<string,mixed>|null */
    private ?array $json = null;

    /**
     * @param array<string,string> $query
     * @param array<string,mixed>  $post
     * @param array<string,mixed>  $files
     * @param array<string,string> $headers
     * @param array<string,string> $cookies
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $query,
        public readonly array $post,
        public readonly array $files,
        public readonly array $headers,
        public readonly array $cookies,
        public readonly string $clientIp,
        private readonly string $rawBody,
        /** @var array<string,string> */
        public array $params = [],
    ) {
    }

    public static function fromGlobals(): self
    {
        $headers = [];
        foreach ($_SERVER as $k => $v) {
            if (str_starts_with($k, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = (string) $v;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
        }
        $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
        $path = '/' . ltrim(rawurldecode($path), '/');
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $raw = in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true) ? (string) file_get_contents('php://input') : '';

        return new self(
            $method,
            $path,
            array_map('strval', array_filter($_GET, 'is_scalar')),
            $_POST,
            $_FILES,
            $headers,
            array_map('strval', array_filter($_COOKIE, 'is_scalar')),
            (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'),
            $raw,
        );
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function isJson(): bool
    {
        return str_contains(strtolower($this->header('content-type') ?? ''), 'application/json');
    }

    /** @return array<string,mixed> */
    public function body(): array
    {
        if ($this->isJson()) {
            if ($this->json === null) {
                if ($this->rawBody === '') {
                    $this->json = [];
                } else {
                    $decoded = json_decode($this->rawBody, true, 32);
                    if (!is_array($decoded)) {
                        throw HttpException::badRequest('JSON inválido', 'invalid_json');
                    }
                    $this->json = $decoded;
                }
            }
            return $this->json;
        }
        return $this->post;
    }

    public function input(string $key, mixed $default = null): mixed
    {
        return $this->body()[$key] ?? $default;
    }

    public function string(string $key, int $maxLength = 255, bool $required = true, ?string $default = null): ?string
    {
        $v = $this->input($key);
        if ($v === null || $v === '') {
            if ($required) {
                throw HttpException::badRequest("Campo obrigatório: {$key}", 'missing_field');
            }
            return $default;
        }
        if (!is_string($v) && !is_int($v) && !is_float($v)) {
            throw HttpException::badRequest("Campo inválido: {$key}", 'invalid_field');
        }
        $v = trim((string) $v);
        if (!mb_check_encoding($v, 'UTF-8') || mb_strlen($v) > $maxLength) {
            throw HttpException::badRequest("Campo inválido ou longo demais: {$key}", 'invalid_field');
        }
        return $v;
    }

    public function int(string $key, ?int $default = null, int $min = PHP_INT_MIN, int $max = PHP_INT_MAX): ?int
    {
        $v = $this->input($key);
        if ($v === null || $v === '') {
            return $default;
        }
        if (is_string($v) && preg_match('/^-?\d+$/', $v)) {
            $v = (int) $v;
        }
        if (!is_int($v) || $v < $min || $v > $max) {
            throw HttpException::badRequest("Número inválido: {$key}", 'invalid_field');
        }
        return $v;
    }

    public function bool(string $key, ?bool $default = null): ?bool
    {
        $v = $this->input($key);
        if ($v === null || $v === '') {
            return $default;
        }
        if (is_bool($v)) {
            return $v;
        }
        $f = filter_var($v, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        if ($f === null) {
            throw HttpException::badRequest("Booleano inválido: {$key}", 'invalid_field');
        }
        return $f;
    }

    public function queryString(string $key, ?string $default = null, int $maxLength = 255): ?string
    {
        $v = $this->query[$key] ?? null;
        if ($v === null || $v === '') {
            return $default;
        }
        if (!mb_check_encoding($v, 'UTF-8') || mb_strlen($v) > $maxLength) {
            throw HttpException::badRequest("Parâmetro inválido: {$key}", 'invalid_query');
        }
        return $v;
    }

    public function queryInt(string $key, int $default, int $min, int $max): int
    {
        $v = $this->query[$key] ?? null;
        if ($v === null || $v === '') {
            return $default;
        }
        if (!preg_match('/^-?\d+$/', $v)) {
            throw HttpException::badRequest("Parâmetro inválido: {$key}", 'invalid_query');
        }
        return max($min, min($max, (int) $v));
    }

    public function param(string $name): string
    {
        return $this->params[$name] ?? throw HttpException::badRequest("Parâmetro ausente: {$name}");
    }

    public function isSecure(): bool
    {
        return (($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? '') !== 'off')
            || (string) ($_SERVER['SERVER_PORT'] ?? '') === '443';
    }
}
