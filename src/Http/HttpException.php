<?php

declare(strict_types=1);

namespace MailPlatform\Http;

use RuntimeException;

/** Erro com status HTTP e código de erro estável para o frontend. */
final class HttpException extends RuntimeException
{
    /** @param array<string,mixed> $extra */
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        string $message,
        public readonly array $extra = [],
    ) {
        parent::__construct($message, $status);
    }

    public static function badRequest(string $message, string $code = 'bad_request'): self
    {
        return new self(400, $code, $message);
    }

    public static function unauthorized(string $message = 'Autenticação necessária'): self
    {
        return new self(401, 'unauthorized', $message);
    }

    public static function forbidden(string $message = 'Acesso negado'): self
    {
        return new self(403, 'forbidden', $message);
    }

    public static function notFound(string $message = 'Não encontrado'): self
    {
        return new self(404, 'not_found', $message);
    }

    public static function conflict(string $message, string $code = 'conflict'): self
    {
        return new self(409, $code, $message);
    }
}
