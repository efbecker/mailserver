<?php

declare(strict_types=1);

namespace MailPlatform\Http;

/** Resposta HTTP (JSON, binária ou HTML) com cabeçalhos de segurança. */
final class Response
{
    /** @param array<string,string> $headers */
    public function __construct(
        public int $status = 200,
        public string $body = '',
        public array $headers = [],
    ) {
    }

    /** @param mixed $data */
    public static function json(mixed $data, int $status = 200): self
    {
        return new self(
            $status,
            (string) json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
            ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store'],
        );
    }

    public static function noContent(): self
    {
        return new self(204, '', ['Cache-Control' => 'no-store']);
    }

    public static function error(HttpException $e): self
    {
        return self::json(['error' => $e->errorCode, 'message' => $e->getMessage()] + $e->extra, $e->status);
    }

    public static function redirect(string $location, int $status = 302): self
    {
        return new self($status, '', ['Location' => $location]);
    }

    public static function download(string $content, string $filename, string $mime, bool $inline = false): self
    {
        $safeMime = preg_match('#^[a-z0-9][a-z0-9!\#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!\#$&^_.+-]{0,126}$#i', $mime) ? $mime : 'application/octet-stream';
        // Inline apenas para imagens rasterizadas (nunca SVG/HTML: podem conter script).
        $inline = $inline && preg_match('#^image/(png|jpe?g|gif|webp|bmp)$#i', $safeMime) === 1;
        if (!$inline) {
            $safeMime = $safeMime === 'text/html' || str_contains($safeMime, 'svg') ? 'application/octet-stream' : $safeMime;
        }
        $ascii = preg_replace('/[^A-Za-z0-9._-]+/', '_', $filename) ?: 'anexo';
        $disposition = ($inline ? 'inline' : 'attachment')
            . '; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($filename);
        return new self(200, $content, [
            'Content-Type' => $safeMime,
            'Content-Disposition' => $disposition,
            'Content-Length' => (string) strlen($content),
            'X-Content-Type-Options' => 'nosniff',
            'Cache-Control' => 'private, no-store',
            'Content-Security-Policy' => "default-src 'none'; img-src 'self' data:; sandbox",
        ]);
    }

    public function withHeader(string $name, string $value): self
    {
        $clone = clone $this;
        $clone->headers[$name] = $value;
        return $clone;
    }

    public function send(): void
    {
        if (!headers_sent()) {
            http_response_code($this->status);
            foreach ($this->headers as $name => $value) {
                header($name . ': ' . str_replace(["\r", "\n"], '', $value), true);
            }
        }
        echo $this->body;
    }
}
