<?php

declare(strict_types=1);

namespace MailPlatform\Services;

use MailPlatform\Config\Config;
use RuntimeException;

/**
 * Execução local de comandos privilegiados SOMENTE via wrappers validados
 * (/usr/local/sbin/mp-f2b-ctl e mp-dkim-ctl) autorizados no sudoers.
 * Nunca usa shell: argumentos são passados como array para proc_open.
 */
final class SystemControl
{
    public function __construct(private readonly Config $config)
    {
    }

    /**
     * @param list<string> $args
     * @return array{exit:int,stdout:string,stderr:string}
     */
    public function run(string $tool, array $args, ?string $stdin = null, int $timeout = 30): array
    {
        $bin = match ($tool) {
            'f2b' => $this->config->get('MP_F2B_CTL', '/usr/local/sbin/mp-f2b-ctl'),
            'dkim' => $this->config->get('MP_DKIM_CTL', '/usr/local/sbin/mp-dkim-ctl'),
            default => throw new RuntimeException('Ferramenta não permitida'),
        };
        foreach ($args as $a) {
            if (!is_string($a) || !preg_match('/^[A-Za-z0-9._:@-]{1,253}$/', $a)) {
                throw new RuntimeException('Argumento inválido para ' . $tool);
            }
        }
        $cmd = array_merge(['/usr/bin/sudo', '-n', (string) $bin], $args);
        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['PATH' => '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL' => 'C.UTF-8']);
        if (!is_resource($proc)) {
            throw new RuntimeException('Falha ao executar ' . $tool);
        }
        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = $err = '';
        $deadline = microtime(true) + $timeout;
        while (true) {
            $status = proc_get_status($proc);
            $out .= (string) stream_get_contents($pipes[1]);
            $err .= (string) stream_get_contents($pipes[2]);
            if (!$status['running']) {
                $exit = (int) $status['exitcode'];
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($proc, 9);
                $exit = 124;
                $err .= "\ntimeout";
                break;
            }
            usleep(20000);
        }
        $out .= (string) stream_get_contents($pipes[1]);
        $err .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);
        return ['exit' => $exit, 'stdout' => $out, 'stderr' => trim($err)];
    }
}
