<?php

declare(strict_types=1);

namespace MailPlatform\Config;

/** Marca um valor como bytea para Database::run(). */
final class Binary
{
    public function __construct(public readonly string $bytes)
    {
    }

    public static function orNull(?string $bytes): ?self
    {
        return $bytes === null ? null : new self($bytes);
    }
}
