<?php

declare(strict_types=1);

namespace MailPlatform\Config;

use PDO;
use PDOException;
use PDOStatement;
use RuntimeException;

/**
 * Conexão PDO com o PostgreSQL 17 + TimescaleDB do Servidor 2.
 *
 * TLS estrito: sslmode=verify-full com a CA privada da plataforma
 * (MP_DB_SSLROOTCERT). O deploy do banco (pg_hba hostssl) recusa qualquer
 * conexão sem TLS, então um downgrade não é possível.
 */
final class Database
{
    private static ?self $instance = null;
    private PDO $pdo;

    private function __construct(Config $config)
    {
        $sslmode = $config->get('MP_DB_SSLMODE', 'verify-full');
        $allowed = ['verify-full', 'verify-ca', 'require', 'disable'];
        if (!in_array($sslmode, $allowed, true)) {
            throw new RuntimeException('MP_DB_SSLMODE inválido');
        }
        if ($sslmode === 'disable' && $config->get('MP_ENV') === 'production') {
            throw new RuntimeException('TLS do banco não pode ser desativado em produção');
        }
        $parts = [
            'host' => $config->require('MP_DB_HOST'),
            'port' => $config->get('MP_DB_PORT', '5432'),
            'dbname' => $config->require('MP_DB_NAME'),
            'sslmode' => $sslmode,
            'application_name' => 'mail-platform-web',
            'connect_timeout' => '5',
        ];
        if ($sslmode !== 'disable') {
            $parts['sslrootcert'] = $config->require('MP_DB_SSLROOTCERT');
        }
        $dsn = 'pgsql:' . implode(';', array_map(
            static fn (string $k, string $v): string => $k . '=' . $v,
            array_keys($parts),
            $parts,
        ));
        try {
            $this->pdo = new PDO($dsn, $config->require('MP_DB_USER'), $config->get('MP_DB_PASSWORD', ''), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_STRINGIFY_FETCHES => false,
            ]);
        } catch (PDOException $e) {
            // Nunca propaga a DSN/senha para a resposta HTTP.
            error_log('mail-platform: falha de conexão com o banco: ' . $e->getMessage());
            throw new RuntimeException('Banco de dados indisponível', 503, $e);
        }
        $this->pdo->exec("SET TIME ZONE 'UTC'");
    }

    public static function get(?Config $config = null): self
    {
        return self::$instance ??= new self($config ?? Config::load());
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * Executa uma consulta parametrizada. Valores binários devem ser passados
     * como instâncias de Binary para serem enviados como bytea.
     *
     * @param array<string|int,mixed> $params
     */
    public function run(string $sql, array $params = []): PDOStatement
    {
        $stmt = $this->pdo->prepare($sql);
        foreach ($params as $key => $value) {
            $name = is_int($key) ? $key + 1 : (str_starts_with($key, ':') ? $key : ':' . $key);
            if ($value instanceof Binary) {
                $stmt->bindValue($name, $value->bytes, PDO::PARAM_LOB);
            } elseif (is_bool($value)) {
                $stmt->bindValue($name, $value, PDO::PARAM_BOOL);
            } elseif (is_int($value)) {
                $stmt->bindValue($name, $value, PDO::PARAM_INT);
            } elseif ($value === null) {
                $stmt->bindValue($name, null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue($name, (string) $value, PDO::PARAM_STR);
            }
        }
        $stmt->execute();
        return $stmt;
    }

    /** @return array<string,mixed>|null */
    public function one(string $sql, array $params = []): ?array
    {
        $row = $this->run($sql, $params)->fetch();
        return $row === false ? null : $row;
    }

    /** @return list<array<string,mixed>> */
    public function all(string $sql, array $params = []): array
    {
        return $this->run($sql, $params)->fetchAll();
    }

    public function scalar(string $sql, array $params = []): mixed
    {
        $v = $this->run($sql, $params)->fetchColumn();
        return $v === false ? null : $v;
    }

    /**
     * @template T
     * @param callable(self):T $fn
     * @return T
     */
    public function transaction(callable $fn): mixed
    {
        $this->pdo->beginTransaction();
        try {
            $result = $fn($this);
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }
}
