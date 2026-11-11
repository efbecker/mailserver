<?php

declare(strict_types=1);

namespace MailPlatform\Services;

use MailPlatform\Config\Config;
use MailPlatform\Config\Database;

/**
 * Registro de eventos de segurança:
 *  - /var/log/mail-platform/auth.log  (lido pelo Fail2ban, jail mail-platform-auth)
 *  - hypertable security_events        (telemetria exibida no painel)
 */
final class SecurityLog
{
    public function __construct(private readonly Config $config, private readonly ?Database $db = null)
    {
    }

    /** Falha de autenticação: alimenta o Fail2ban e a telemetria. */
    public function authFailure(string $area, string $ip, string $user, string $reason = 'invalid_credentials'): void
    {
        $user = substr((string) preg_replace('/[^\w.@+-]/u', '_', $user), 0, 120);
        $line = sprintf(
            "%s %s AUTH_FAIL ip=%s user=\"%s\" reason=%s\n",
            gmdate('Y-m-d\TH:i:s+00:00'),
            $area === 'admin' ? 'admin' : 'webmail',
            $this->cleanIp($ip),
            $user,
            preg_replace('/[^a-z_]/', '', $reason),
        );
        $file = $this->config->get('MP_AUTH_LOG', '/var/log/mail-platform/auth.log');
        if ($file !== null) {
            @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
        }
        $this->event($area === 'admin' ? 'admin_auth' : 'webmail_auth', 'AUTH_FAIL', $ip, "user={$user} reason={$reason}");
    }

    public function event(string $service, string $action, ?string $ip = null, ?string $details = null, ?string $jail = null): void
    {
        if ($this->db === null) {
            return;
        }
        try {
            $this->db->run(
                'INSERT INTO security_events (service, jail_name, source_ip, action, details) VALUES (?, ?, ?::inet, ?, ?)',
                [
                    substr($service, 0, 50),
                    $jail !== null ? substr($jail, 0, 50) : null,
                    $ip !== null && filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null,
                    substr(strtoupper($action), 0, 32),
                    $details !== null ? mb_substr($details, 0, 2000) : null,
                ],
            );
        } catch (\Throwable $e) {
            error_log('mail-platform: falha ao gravar security_events: ' . $e->getMessage());
        }
    }

    private function cleanIp(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }
}
