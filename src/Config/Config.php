<?php

declare(strict_types=1);

namespace MailPlatform\Config;

use RuntimeException;

/**
 * Configuração da aplicação lida de /etc/mail-platform/app.env (KEY='valor'),
 * gerado por bin/deploy-mail-node.sh. O arquivo nunca é executado/interpretado
 * como shell: apenas linhas no formato exato MP_CHAVE='valor' são aceitas.
 */
final class Config
{
    private static ?self $instance = null;

    /** @param array<string,string> $values */
    private function __construct(private array $values)
    {
    }

    public static function load(?string $file = null): self
    {
        if (self::$instance !== null && $file === null) {
            return self::$instance;
        }
        $file ??= getenv('MP_CONFIG_FILE') ?: '/etc/mail-platform/app.env';
        if (!is_readable($file)) {
            throw new RuntimeException("Configuração não encontrada: {$file}");
        }
        $values = [];
        foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            if (preg_match("/^(MP_[A-Z0-9_]+)='([^']*)'\\s*$/", $line, $m)) {
                $values[$m[1]] = $m[2];
            }
        }
        // Variáveis de ambiente MP_* sobrescrevem (útil em testes/CI).
        foreach (getenv() as $k => $v) {
            if (is_string($k) && str_starts_with($k, 'MP_') && $k !== 'MP_CONFIG_FILE') {
                $values[$k] = (string) $v;
            }
        }
        return self::$instance = new self($values);
    }

    public function get(string $key, ?string $default = null): ?string
    {
        $v = $this->values[$key] ?? null;
        return ($v === null || $v === '') ? $default : $v;
    }

    public function require(string $key): string
    {
        $v = $this->get($key);
        if ($v === null) {
            throw new RuntimeException("{$key} ausente na configuração");
        }
        return $v;
    }

    public function int(string $key, int $default): int
    {
        $v = $this->get($key);
        return ($v !== null && preg_match('/^-?\d+$/', $v)) ? (int) $v : $default;
    }

    public function appDir(): string
    {
        return rtrim($this->get('MP_APP_DIR', dirname(__DIR__, 2)) ?? '', '/');
    }

    public function dataDir(): string
    {
        return rtrim($this->get('MP_DATA_DIR', '/var/lib/mail-platform') ?? '', '/');
    }
}
