<?php

declare(strict_types=1);

namespace MailPlatform\Controllers;

use MailPlatform\Config\Binary;
use MailPlatform\Config\Config;
use MailPlatform\Config\Database;
use MailPlatform\Crypto\ZeroKnowledgeVault;
use MailPlatform\Http\HttpException;
use MailPlatform\Http\Request;
use MailPlatform\Http\Response;
use MailPlatform\Http\Router;
use MailPlatform\Http\Session;
use MailPlatform\Services\DnsValidator;
use MailPlatform\Services\SecurityLog;
use MailPlatform\Services\SshOrchestrator;
use MailPlatform\Services\SystemControl;

/**
 * APIs do Painel Admin: autenticação, nós SSH e deploy com streaming (SSE),
 * domínios + DNS/DKIM, contas, Fail2ban, fila do Postfix e telemetria.
 *
 * Todas as rotas (exceto GET /session) exigem sessão de admin; métodos que
 * alteram estado exigem o cabeçalho X-CSRF-Token.
 */
final class AdminController
{
    private const SSH_KEY_CONTEXT = 'infra_nodes.ssh_private_key';
    private const DKIM_KEY_CONTEXT = 'mail_domains.dkim_private_key';
    private const FOLDERS = ['INBOX', 'SENT', 'DRAFTS', 'SPAM', 'TRASH', 'ARCHIVE'];

    private ?Database $db = null;
    private ?ZeroKnowledgeVault $vault = null;

    public function __construct(
        private readonly Config $config,
        private readonly Session $session,
    ) {
    }

    public function register(Router $r): void
    {
        $r->add('GET', '/api/admin/session', fn (Request $q) => $this->sessionInfo($q));
        $r->add('POST', '/api/admin/login', fn (Request $q) => $this->login($q));
        $r->add('POST', '/api/admin/logout', fn (Request $q) => $this->guard($q, fn () => $this->logout()));
        $r->add('GET', '/api/admin/overview', fn (Request $q) => $this->guard($q, fn () => $this->overview()));

        $r->add('GET', '/api/admin/nodes', fn (Request $q) => $this->guard($q, fn () => $this->listNodes()));
        $r->add('POST', '/api/admin/nodes', fn (Request $q) => $this->guard($q, fn () => $this->createNode($q)));
        $r->add('DELETE', '/api/admin/nodes/{id}', fn (Request $q) => $this->guard($q, fn () => $this->deleteNode($q)));
        $r->add('POST', '/api/admin/nodes/{id}/test', fn (Request $q) => $this->guard($q, fn () => $this->testNode($q)));
        $r->add('POST', '/api/admin/nodes/{id}/forget-hostkey', fn (Request $q) => $this->guard($q, fn () => $this->forgetHostKey($q)));
        $r->add('POST', '/api/admin/deploy', fn (Request $q) => $this->guard($q, fn () => $this->createDeployJob($q)));
        $r->add('GET', '/api/admin/deploy/{job}/stream', fn (Request $q) => $this->guard($q, fn () => $this->streamDeploy($q)));

        $r->add('GET', '/api/admin/domains', fn (Request $q) => $this->guard($q, fn () => $this->listDomains()));
        $r->add('POST', '/api/admin/domains', fn (Request $q) => $this->guard($q, fn () => $this->createDomain($q)));
        $r->add('GET', '/api/admin/domains/{id}', fn (Request $q) => $this->guard($q, fn () => $this->getDomain($q)));
        $r->add('PATCH', '/api/admin/domains/{id}', fn (Request $q) => $this->guard($q, fn () => $this->updateDomain($q)));
        $r->add('DELETE', '/api/admin/domains/{id}', fn (Request $q) => $this->guard($q, fn () => $this->deleteDomain($q)));
        $r->add('POST', '/api/admin/domains/{id}/verify', fn (Request $q) => $this->guard($q, fn () => $this->verifyDomain($q)));
        $r->add('POST', '/api/admin/domains/{id}/dkim/install', fn (Request $q) => $this->guard($q, fn () => $this->installDkim($q)));

        $r->add('GET', '/api/admin/accounts', fn (Request $q) => $this->guard($q, fn () => $this->listAccounts($q)));
        $r->add('POST', '/api/admin/accounts', fn (Request $q) => $this->guard($q, fn () => $this->createAccount($q)));
        $r->add('PATCH', '/api/admin/accounts/{id}', fn (Request $q) => $this->guard($q, fn () => $this->updateAccount($q)));
        $r->add('DELETE', '/api/admin/accounts/{id}', fn (Request $q) => $this->guard($q, fn () => $this->deleteAccount($q)));
        $r->add('POST', '/api/admin/accounts/{id}/reset-password', fn (Request $q) => $this->guard($q, fn () => $this->resetAccountPassword($q)));

        $r->add('GET', '/api/admin/fail2ban', fn (Request $q) => $this->guard($q, fn () => $this->fail2banStatus()));
        $r->add('POST', '/api/admin/fail2ban/ban', fn (Request $q) => $this->guard($q, fn () => $this->fail2banAction($q, 'ban')));
        $r->add('POST', '/api/admin/fail2ban/unban', fn (Request $q) => $this->guard($q, fn () => $this->fail2banAction($q, 'unban')));
        $r->add('GET', '/api/admin/queue', fn (Request $q) => $this->guard($q, fn () => $this->mailQueue()));
        $r->add('POST', '/api/admin/queue/flush', fn (Request $q) => $this->guard($q, fn () => $this->flushQueue()));
        $r->add('GET', '/api/admin/security-events', fn (Request $q) => $this->guard($q, fn () => $this->securityEvents($q)));
    }

    // =====================================================================
    // Autenticação
    // =====================================================================

    private function guard(Request $request, callable $fn): Response
    {
        $admin = $this->session->area('admin');
        if ($admin === null) {
            throw HttpException::unauthorized();
        }
        if ($request->method !== 'GET' && $request->method !== 'HEAD') {
            $this->session->verifyCsrf($request);
        }
        return $fn();
    }

    private function sessionInfo(Request $request): Response
    {
        $admin = $this->session->area('admin');
        return Response::json([
            'authenticated' => $admin !== null,
            'user' => $admin['user'] ?? null,
            'csrf' => $this->session->csrfToken(),
            'hostname' => $this->config->get('MP_HOSTNAME'),
            'public_ip' => $this->config->get('MP_PUBLIC_IP'),
        ]);
    }

    private function login(Request $request): Response
    {
        $this->session->verifyCsrf($request);
        $user = $request->string('username', 64);
        $password = (string) $request->string('password', 1024);
        $expectedUser = $this->config->get('MP_ADMIN_USER', 'admin');
        $hash = $this->config->get('MP_ADMIN_PASSWORD_HASH', '');
        $okUser = hash_equals((string) $expectedUser, (string) $user);
        // password_verify sempre executado (tempo constante entre usuário certo/errado)
        $okPass = password_verify($password, $hash !== '' ? (string) $hash : '$argon2id$v=19$m=65536,t=4,p=1$bXl3N0w1VnVNYjUyNXQwdw$jauTCN7ZD/Br+qbSYCa20p4uDGw9iHgazatpwQz0znE');
        if (!$okUser || !$okPass || $hash === '') {
            (new SecurityLog($this->config, $this->dbOrNull()))->authFailure('admin', $request->clientIp, (string) $user);
            usleep(random_int(200000, 400000));
            throw new HttpException(401, 'invalid_credentials', 'Usuário ou senha inválidos');
        }
        $this->session->login('admin', ['user' => $user]);
        (new SecurityLog($this->config, $this->dbOrNull()))->event('admin_auth', 'LOGIN_OK', $request->clientIp, "user={$user}");
        return Response::json(['authenticated' => true, 'user' => $user, 'csrf' => $this->session->csrfToken()]);
    }

    private function logout(): Response
    {
        $this->session->logout('admin');
        return Response::json(['authenticated' => false, 'csrf' => $this->session->csrfToken()]);
    }

    private function overview(): Response
    {
        $db = $this->db();
        $stats = $db->one(
            "SELECT
                (SELECT count(*) FROM mail_domains) AS domains,
                (SELECT count(*) FROM mail_accounts) AS accounts,
                (SELECT count(*) FROM infra_nodes) AS nodes,
                (SELECT count(*) FROM messages WHERE received_at > NOW() - INTERVAL '24 hours' AND folder <> 'SENT') AS received_24h,
                (SELECT count(*) FROM messages WHERE received_at > NOW() - INTERVAL '24 hours' AND folder = 'SENT') AS sent_24h,
                (SELECT count(*) FROM messages WHERE received_at > NOW() - INTERVAL '24 hours' AND folder = 'SPAM') AS spam_24h,
                (SELECT count(*) FROM security_events WHERE event_time > NOW() - INTERVAL '24 hours' AND action = 'BAN') AS bans_24h,
                (SELECT count(*) FROM security_events WHERE event_time > NOW() - INTERVAL '24 hours' AND action = 'AUTH_FAIL') AS auth_fail_24h,
                (SELECT COALESCE(sum(used_bytes), 0) FROM mail_accounts) AS storage_bytes"
        ) ?? [];
        return Response::json(array_map(static fn ($v) => (int) $v, $stats) + [
            'hostname' => $this->config->get('MP_HOSTNAME'),
            'public_ip' => $this->config->get('MP_PUBLIC_IP'),
        ]);
    }

    // =====================================================================
    // Nós de infraestrutura e deploy SSH
    // =====================================================================

    private function listNodes(): Response
    {
        $rows = $this->db()->all('SELECT id, node_role, hostname, host(ip_address) AS ip_address, ssh_port, ssh_user, ssh_private_key_enc,
            deploy_status, last_check, created_at FROM infra_nodes ORDER BY id');
        $out = [];
        foreach ($rows as $row) {
            $pub = null;
            try {
                $key = $this->vault()->decryptServerSecret(ZeroKnowledgeVault::bin($row['ssh_private_key_enc'], null, 'ssh'), self::SSH_KEY_CONTEXT);
                $pub = SshOrchestrator::derivePublicKey($key);
                sodium_memzero($key);
            } catch (\Throwable) {
                $pub = null;
            }
            unset($row['ssh_private_key_enc']);
            $row['id'] = (int) $row['id'];
            $row['ssh_port'] = (int) $row['ssh_port'];
            $row['public_key'] = $pub;
            $row['has_db_credentials'] = is_file($this->dbCredentialsFile((int) $row['id']));
            $out[] = $row;
        }
        return Response::json(['nodes' => $out]);
    }

    private function createNode(Request $request): Response
    {
        $role = $request->string('node_role', 30);
        if (!in_array($role, ['mail_frontend', 'db_timescale'], true)) {
            throw HttpException::badRequest('node_role deve ser mail_frontend ou db_timescale');
        }
        $hostname = strtolower((string) $request->string('hostname', 255));
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/', $hostname)) {
            throw HttpException::badRequest('Hostname inválido');
        }
        $ip = (string) $request->string('ip_address', 45);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw HttpException::badRequest('Endereço IP inválido');
        }
        $port = (int) $request->int('ssh_port', 22, 1, 65535);
        $user = (string) $request->string('ssh_user', 32, false, 'root');
        if (!preg_match('/^[a-z_][a-z0-9_.-]{0,31}$/i', $user)) {
            throw HttpException::badRequest('Usuário SSH inválido');
        }
        $key = (string) $request->string('ssh_private_key', 16384);
        try {
            $pub = SshOrchestrator::derivePublicKey($key);
        } catch (\Throwable $e) {
            throw HttpException::badRequest($e->getMessage(), 'invalid_ssh_key');
        }
        $enc = $this->vault()->encryptServerSecret(str_replace("\r\n", "\n", trim($key)) . "\n", self::SSH_KEY_CONTEXT);
        $id = (int) $this->db()->scalar(
            'INSERT INTO infra_nodes (node_role, hostname, ip_address, ssh_port, ssh_user, ssh_private_key_enc, deploy_status)
             VALUES (?, ?, ?::inet, ?, ?, ?, ?) RETURNING id',
            [$role, $hostname, $ip, $port, $user, new Binary($enc), 'pending'],
        );
        return Response::json(['id' => $id, 'public_key' => $pub], 201);
    }

    private function deleteNode(Request $request): Response
    {
        $id = $this->intParam($request, 'id');
        $n = $this->db()->run('DELETE FROM infra_nodes WHERE id = ?', [$id])->rowCount();
        if ($n === 0) {
            throw HttpException::notFound('Nó não encontrado');
        }
        @unlink($this->dbCredentialsFile($id));
        return Response::noContent();
    }

    private function testNode(Request $request): Response
    {
        $node = $this->node($this->intParam($request, 'id'));
        try {
            [$ssh, $info] = $this->sshConnect($node);
            [$exit, $out] = $ssh->exec('uname -srm; . /etc/os-release && echo "$PRETTY_NAME"; id -un; uptime -p 2>/dev/null || true', 30);
            $ssh->disconnect();
        } catch (HttpException $e) {
            throw $e;
        } catch (\RuntimeException $e) {
            throw new HttpException(502, 'ssh_error', 'Falha SSH: ' . $e->getMessage());
        }
        $this->db()->run('UPDATE infra_nodes SET last_check = NOW() WHERE id = ?', [(int) $node['id']]);
        return Response::json(['ok' => $exit === 0, 'output' => $out, 'host_key' => $info['fingerprint'], 'first_use' => $info['first_use']]);
    }

    private function forgetHostKey(Request $request): Response
    {
        $node = $this->node($this->intParam($request, 'id'));
        $this->ssh()->forgetHost((string) $node['ip_address'], (int) $node['ssh_port']);
        return Response::noContent();
    }

    /**
     * Cria um job de deploy (executado no GET .../stream via SSE).
     * Opções aceitas:
     *  - db_timescale : allowed_ip (IP do Servidor 1), timescale_edition (tsl|oss)
     *  - mail_frontend: hostname, db_node_id, acme_email, admin_allow, public_ip
     */
    private function createDeployJob(Request $request): Response
    {
        $node = $this->node((int) $request->int('node_id', null, 1));
        $opts = [];
        if ($node['node_role'] === 'db_timescale') {
            $allowed = (string) ($request->string('allowed_ip', 45, false) ?? $this->config->get('MP_PUBLIC_IP', ''));
            if (!filter_var($allowed, FILTER_VALIDATE_IP)) {
                throw HttpException::badRequest('Informe allowed_ip (IP do Servidor 1 visto pelo Servidor 2)');
            }
            $edition = (string) $request->string('timescale_edition', 3, false, 'tsl');
            if (!in_array($edition, ['tsl', 'oss'], true)) {
                throw HttpException::badRequest('timescale_edition deve ser tsl ou oss');
            }
            $opts = ['allowed_ip' => $allowed, 'timescale_edition' => $edition];
        } else {
            $hostname = strtolower((string) ($request->string('hostname', 253, false) ?? $this->config->get('MP_HOSTNAME', '')));
            if (!preg_match('/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $hostname)) {
                throw HttpException::badRequest('Hostname (FQDN) inválido');
            }
            $dbNode = (int) $request->int('db_node_id', null, 1);
            if (!$dbNode || !is_file($this->dbCredentialsFile($dbNode))) {
                throw HttpException::badRequest('Faça primeiro o deploy do Servidor 2 (db_node_id sem credenciais)');
            }
            $acme = $request->string('acme_email', 254, false);
            if ($acme !== null && !filter_var($acme, FILTER_VALIDATE_EMAIL)) {
                throw HttpException::badRequest('acme_email inválido');
            }
            $allow = $request->string('admin_allow', 500, false);
            if ($allow !== null && !preg_match('#^[0-9a-fA-F:./, ]+$#', $allow)) {
                throw HttpException::badRequest('admin_allow inválido');
            }
            $publicIp = $request->string('public_ip', 45, false) ?? $this->config->get('MP_PUBLIC_IP');
            if ($publicIp !== null && !filter_var($publicIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                throw HttpException::badRequest('public_ip inválido');
            }
            $opts = ['hostname' => $hostname, 'db_node_id' => $dbNode, 'acme_email' => $acme, 'admin_allow' => $allow ? str_replace(' ', '', $allow) : null, 'public_ip' => $publicIp];
        }
        $jobId = bin2hex(random_bytes(16));
        $this->saveJob($jobId, [
            'id' => $jobId,
            'node_id' => (int) $node['id'],
            'role' => $node['node_role'],
            'options' => $opts,
            'status' => 'pending',
            'created_at' => time(),
        ]);
        return Response::json(['job_id' => $jobId, 'stream_url' => "/api/admin/deploy/{$jobId}/stream"], 201);
    }

    /** Executa o deploy e transmite a saída como Server-Sent Events. */
    private function streamDeploy(Request $request): Response
    {
        $jobId = $request->param('job');
        if (!preg_match('/^[0-9a-f]{32}$/', $jobId)) {
            throw HttpException::notFound('Job inexistente');
        }
        $job = $this->loadJob($jobId);
        if ($job === null) {
            throw HttpException::notFound('Job inexistente');
        }
        if ($job['status'] !== 'pending' || time() - (int) $job['created_at'] > 600) {
            throw HttpException::conflict('Job já executado ou expirado', 'job_used');
        }
        $job['status'] = 'running';
        $this->saveJob($jobId, $job);

        // A sessão é liberada: o deploy pode levar vários minutos.
        $this->session->close();
        ignore_user_abort(true);
        set_time_limit(0);
        while (ob_get_level() > 0) {
            ob_end_flush();
        }
        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache, no-transform');
        header('X-Accel-Buffering: no');
        $send = static function (string $event, array $data): void {
            echo 'event: ' . $event . "\n";
            echo 'data: ' . json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n\n";
            @flush();
        };
        $log = static fn (string $line) => $send('log', ['line' => $line, 'ts' => gmdate('H:i:s')]);
        echo "retry: 86400000\n\n";

        $node = $this->node((int) $job['node_id']);
        $nodeId = (int) $node['id'];
        $this->db()->run("UPDATE infra_nodes SET deploy_status = 'deploying', last_check = NOW() WHERE id = ?", [$nodeId]);
        $send('status', ['state' => 'running', 'node' => $node['hostname'], 'role' => $job['role']]);
        $ok = false;
        $exit = 255;
        $secLog = new SecurityLog($this->config, $this->db());
        $remoteDir = '/tmp/mail-platform-deploy-' . bin2hex(random_bytes(6));
        try {
            $log("[painel] Conectando em {$node['ssh_user']}@{$node['ip_address']}:{$node['ssh_port']} ...");
            [$ssh, $info] = $this->sshConnect($node);
            $log('[painel] Chave do host: ' . $info['fingerprint'] . ($info['first_use'] ? ' (registrada agora — primeiro contato)' : ' (confere)'));
            $sudo = $node['ssh_user'] === 'root' ? '' : 'sudo -n ';
            $appDir = $this->config->appDir();
            $heartbeat = static function (): void {
                echo ": keep-alive\n\n";
                @flush();
            };

            if ($job['role'] === 'db_timescale') {
                $o = $job['options'];
                $log('[painel] Enviando bin/deploy-db-node.sh e sql/schema_timescaledb.sql');
                $ssh->upload((string) file_get_contents($appDir . '/bin/deploy-db-node.sh'), $remoteDir . '/bin/deploy-db-node.sh', 0700);
                $ssh->upload((string) file_get_contents($appDir . '/sql/schema_timescaledb.sql'), $remoteDir . '/sql/schema_timescaledb.sql', 0600);
                $cmd = $sudo . 'bash ' . escapeshellarg($remoteDir . '/bin/deploy-db-node.sh')
                    . ' --allowed-ip ' . escapeshellarg($o['allowed_ip'])
                    . ' --schema ' . escapeshellarg($remoteDir . '/sql/schema_timescaledb.sql')
                    . ' --timescale-edition ' . escapeshellarg($o['timescale_edition'])
                    . ' --output /root/mail-platform-db-credentials.env';
                $exit = $ssh->execStream($cmd, $log, 3600, [], $heartbeat);
                if ($exit === 0) {
                    [$cexit, $creds] = $ssh->exec($sudo . 'cat /root/mail-platform-db-credentials.env', 30, false);
                    if ($cexit !== 0 || !str_contains($creds, "MP_DB_CA_PEM_B64='")) {
                        throw new \RuntimeException('Deploy concluído, mas não foi possível ler as credenciais geradas');
                    }
                    $this->writePrivateFile($this->dbCredentialsFile($nodeId), $creds . "\n");
                    $log('[painel] Credenciais do Servidor 2 guardadas no painel (usadas no deploy do Servidor 1)');
                }
            } else {
                $o = $job['options'];
                $creds = (string) file_get_contents($this->dbCredentialsFile((int) $o['db_node_id']));
                $ssh->upload($creds, $remoteDir . '/db.env', 0600);
                $installUrl = $this->config->get('MP_INSTALL_URL', 'https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh');
                $args = ' --role mail --hostname ' . escapeshellarg($o['hostname'])
                    . ' --db-env ' . escapeshellarg($remoteDir . '/db.env');
                foreach (['acme_email' => '--acme-email', 'admin_allow' => '--admin-allow', 'public_ip' => '--public-ip'] as $k => $flag) {
                    if (!empty($o[$k])) {
                        $args .= ' ' . $flag . ' ' . escapeshellarg((string) $o[$k]);
                    }
                }
                $cmd = 'curl -fsSL --proto =https ' . escapeshellarg($installUrl) . ' | ' . $sudo . 'bash -s --' . $args;
                $log('[painel] Executando instalador: ' . $installUrl);
                $exit = $ssh->execStream($cmd, $log, 3600, [], $heartbeat);
            }
            $ssh->exec('rm -rf ' . escapeshellarg($remoteDir), 30);
            $ssh->disconnect();
            $ok = $exit === 0;
        } catch (\Throwable $e) {
            $log('[painel] ERRO: ' . SshOrchestrator::sanitize($e->getMessage()));
        }

        $status = $ok ? 'deployed' : 'failed';
        $this->db()->run('UPDATE infra_nodes SET deploy_status = ?, last_check = NOW() WHERE id = ?', [$status, $nodeId]);
        $secLog->event('ssh_deploy', $ok ? 'DEPLOY_OK' : 'DEPLOY_FAIL', (string) $node['ip_address'], "role={$job['role']} node={$node['hostname']} exit={$exit}");
        $job['status'] = $status;
        $job['exit'] = $exit;
        $this->saveJob($jobId, $job);
        $send('done', ['ok' => $ok, 'exit' => $exit, 'status' => $status]);
        exit(0);
    }

    // =====================================================================
    // Domínios, DKIM e DNS
    // =====================================================================

    private function listDomains(): Response
    {
        $rows = $this->db()->all(
            'SELECT d.id, d.domain_name, d.dkim_selector, d.mx_verified, d.spf_verified, d.dkim_verified, d.dmarc_verified,
                    d.ptr_verified, d.quota_mb, d.active, d.created_at,
                    (SELECT count(*) FROM mail_accounts a WHERE a.domain_id = d.id) AS accounts
             FROM mail_domains d ORDER BY d.domain_name'
        );
        foreach ($rows as &$r) {
            $r['id'] = (int) $r['id'];
            $r['accounts'] = (int) $r['accounts'];
            $r['quota_mb'] = (int) $r['quota_mb'];
        }
        return Response::json(['domains' => $rows]);
    }

    private function createDomain(Request $request): Response
    {
        try {
            $domain = DnsValidator::normalizeDomain((string) $request->string('domain_name', 253));
        } catch (\InvalidArgumentException $e) {
            throw HttpException::badRequest($e->getMessage(), 'invalid_domain');
        }
        $selector = strtolower((string) $request->string('dkim_selector', 63, false, 'mail'));
        if (!DnsValidator::validSelector($selector)) {
            throw HttpException::badRequest('Seletor DKIM inválido');
        }
        $quotaMb = (int) $request->int('quota_mb', 10240, 1, 10485760);
        if ($this->db()->scalar('SELECT 1 FROM mail_domains WHERE lower(domain_name) = ?', [$domain])) {
            throw HttpException::conflict('Domínio já cadastrado', 'domain_exists');
        }
        $dkim = DnsValidator::generateDkimKeyPair();
        $dns = $this->dns();
        $spf = $dns->spfRecordValue();
        $dmarc = DnsValidator::dmarcRecordValue($domain);
        $enc = $this->vault()->encryptServerSecret($dkim['private_pem'], self::DKIM_KEY_CONTEXT . '|' . $domain);
        $id = (int) $this->db()->scalar(
            'INSERT INTO mail_domains (domain_name, dkim_selector, dkim_private_key_enc, dkim_public_key, spf_record, dmarc_record, quota_mb)
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id',
            [$domain, $selector, new Binary($enc), $dkim['public_b64'], $spf, $dmarc, $quotaMb],
        );
        $install = $this->installDkimKey($domain, $selector, $dkim['private_pem']);
        sodium_memzero($dkim['private_pem']);
        return Response::json([
            'id' => $id,
            'domain_name' => $domain,
            'records' => $dns->recommendedRecords($domain, $selector, $dkim['public_b64'], $spf, $dmarc),
            'dkim_installed' => $install['ok'],
            'dkim_message' => $install['message'],
        ], 201);
    }

    private function getDomain(Request $request): Response
    {
        $d = $this->domain($this->intParam($request, 'id'));
        $records = $this->dns()->recommendedRecords($d['domain_name'], $d['dkim_selector'], $d['dkim_public_key'], $d['spf_record'], $d['dmarc_record']);
        unset($d['dkim_private_key_enc']);
        $d['id'] = (int) $d['id'];
        $d['quota_mb'] = (int) $d['quota_mb'];
        return Response::json(['domain' => $d, 'records' => $records]);
    }

    private function updateDomain(Request $request): Response
    {
        $d = $this->domain($this->intParam($request, 'id'));
        $active = $request->bool('active');
        $quota = $request->int('quota_mb', null, 1, 10485760);
        $this->db()->run(
            'UPDATE mail_domains SET active = COALESCE(?, active), quota_mb = COALESCE(?, quota_mb) WHERE id = ?',
            [$active, $quota, (int) $d['id']],
        );
        return $this->getDomain($request);
    }

    private function deleteDomain(Request $request): Response
    {
        $d = $this->domain($this->intParam($request, 'id'));
        if ($request->string('confirm', 253) !== $d['domain_name']) {
            throw HttpException::badRequest('Confirme digitando o nome do domínio (apaga contas e mensagens)', 'confirmation_required');
        }
        $this->db()->run('DELETE FROM mail_domains WHERE id = ?', [(int) $d['id']]);
        $res = $this->system()->run('dkim', ['remove', $d['domain_name']]);
        return Response::json(['deleted' => true, 'dkim_removed' => $res['exit'] === 0]);
    }

    private function verifyDomain(Request $request): Response
    {
        $d = $this->domain($this->intParam($request, 'id'));
        $result = $this->dns()->verify($d['domain_name'], $d['dkim_selector'], $d['dkim_public_key']);
        $this->db()->run(
            'UPDATE mail_domains SET mx_verified = ?, spf_verified = ?, dkim_verified = ?, dmarc_verified = ?, ptr_verified = ? WHERE id = ?',
            [$result['mx']['ok'], $result['spf']['ok'], $result['dkim']['ok'], $result['dmarc']['ok'], $result['ptr']['ok'], (int) $d['id']],
        );
        return Response::json(['domain' => $d['domain_name'], 'checked_at' => gmdate('c'), 'results' => $result]);
    }

    private function installDkim(Request $request): Response
    {
        $d = $this->domain($this->intParam($request, 'id'));
        $pem = $this->vault()->decryptServerSecret(
            ZeroKnowledgeVault::bin($d['dkim_private_key_enc'], null, 'dkim'),
            self::DKIM_KEY_CONTEXT . '|' . $d['domain_name'],
        );
        $res = $this->installDkimKey($d['domain_name'], $d['dkim_selector'], $pem);
        sodium_memzero($pem);
        return Response::json(['dkim_installed' => $res['ok'], 'message' => $res['message']], $res['ok'] ? 200 : 502);
    }

    /** @return array{ok:bool,message:string} */
    private function installDkimKey(string $domain, string $selector, string $pem): array
    {
        try {
            $res = $this->system()->run('dkim', ['install', $domain, $selector], $pem);
            return $res['exit'] === 0
                ? ['ok' => true, 'message' => 'Chave instalada no OpenDKIM']
                : ['ok' => false, 'message' => 'Falha ao instalar no OpenDKIM: ' . mb_substr($res['stderr'], 0, 300)];
        } catch (\Throwable $e) {
            return ['ok' => false, 'message' => 'Falha ao instalar no OpenDKIM: ' . $e->getMessage()];
        }
    }

    // =====================================================================
    // Contas
    // =====================================================================

    private function listAccounts(Request $request): Response
    {
        $domainId = $request->queryInt('domain_id', 0, 0, PHP_INT_MAX);
        $rows = $this->db()->all(
            'SELECT a.id, a.email, a.full_name, a.quota_bytes, a.used_bytes, a.active, a.created_at, a.domain_id, d.domain_name
             FROM mail_accounts a JOIN mail_domains d ON d.id = a.domain_id
             WHERE (? = 0 OR a.domain_id = ?) ORDER BY a.email',
            [$domainId, $domainId],
        );
        foreach ($rows as &$r) {
            $r['quota_bytes'] = (int) $r['quota_bytes'];
            $r['used_bytes'] = (int) $r['used_bytes'];
            $r['domain_id'] = (int) $r['domain_id'];
        }
        return Response::json(['accounts' => $rows]);
    }

    private function createAccount(Request $request): Response
    {
        $email = strtolower((string) $request->string('email', 254));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[a-z0-9._%+-]{1,64}@/', $email)) {
            throw HttpException::badRequest('E-mail inválido');
        }
        if (str_contains(explode('@', $email)[0], '+')) {
            throw HttpException::badRequest('O caractere + é reservado para subendereços (usuario+tag@)');
        }
        $domainName = substr($email, strpos($email, '@') + 1);
        $domain = $this->db()->one('SELECT id, quota_mb FROM mail_domains WHERE lower(domain_name) = ?', [$domainName]);
        if ($domain === null) {
            throw HttpException::badRequest("Domínio {$domainName} não cadastrado", 'unknown_domain');
        }
        $fullName = (string) $request->string('full_name', 120);
        $password = (string) $request->string('password', 1024);
        $quotaMb = (int) $request->int('quota_mb', 5120, 1, 10485760);
        if ($this->db()->scalar('SELECT 1 FROM mail_accounts WHERE lower(email) = ?', [$email])) {
            throw HttpException::conflict('Conta já existe', 'account_exists');
        }
        try {
            $keys = $this->vault()->createAccountKeys($password);
        } catch (\InvalidArgumentException $e) {
            throw HttpException::badRequest($e->getMessage(), 'weak_password');
        }
        $id = (string) $this->db()->scalar(
            'INSERT INTO mail_accounts (domain_id, email, full_name, password_hash, kdf_salt, public_key, encrypted_private_key, private_key_nonce, quota_bytes)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id',
            [(int) $domain['id'], $email, $fullName, $keys['password_hash'], new Binary($keys['kdf_salt']), new Binary($keys['public_key']),
                new Binary($keys['encrypted_private_key']), new Binary($keys['private_key_nonce']), $quotaMb * 1048576],
        );
        return Response::json([
            'id' => $id,
            'email' => $email,
            'public_key' => base64_encode($keys['public_key']),
        ], 201);
    }

    private function updateAccount(Request $request): Response
    {
        $id = $this->uuidParam($request, 'id');
        $fullName = $request->string('full_name', 120, false);
        $active = $request->bool('active');
        $quotaMb = $request->int('quota_mb', null, 1, 10485760);
        $n = $this->db()->run(
            'UPDATE mail_accounts SET full_name = COALESCE(?, full_name), active = COALESCE(?, active),
                quota_bytes = COALESCE(?, quota_bytes) WHERE id = ?',
            [$fullName, $active, $quotaMb !== null ? $quotaMb * 1048576 : null, $id],
        )->rowCount();
        if ($n === 0) {
            throw HttpException::notFound('Conta não encontrada');
        }
        return Response::json(['updated' => true]);
    }

    private function deleteAccount(Request $request): Response
    {
        $id = $this->uuidParam($request, 'id');
        $acc = $this->db()->one('SELECT email FROM mail_accounts WHERE id = ?', [$id]) ?? throw HttpException::notFound('Conta não encontrada');
        if ($request->string('confirm', 254) !== $acc['email']) {
            throw HttpException::badRequest('Confirme digitando o e-mail (apaga todas as mensagens)', 'confirmation_required');
        }
        $this->db()->run('DELETE FROM mail_accounts WHERE id = ?', [$id]);
        return Response::json(['deleted' => true]);
    }

    /**
     * Redefinição administrativa de senha. Zero-knowledge: sem a senha antiga
     * a chave privada não pode ser recuperada, então um NOVO par de chaves é
     * gerado e as mensagens existentes tornam-se ilegíveis (podem ser apagadas
     * com purge_messages=true).
     */
    private function resetAccountPassword(Request $request): Response
    {
        $id = $this->uuidParam($request, 'id');
        if ($request->bool('confirm_data_loss') !== true) {
            throw HttpException::badRequest('Confirme confirm_data_loss=true: mensagens atuais ficarão ilegíveis', 'confirmation_required');
        }
        $password = (string) $request->string('password', 1024);
        $purge = (bool) $request->bool('purge_messages', false);
        try {
            $keys = $this->vault()->createAccountKeys($password);
        } catch (\InvalidArgumentException $e) {
            throw HttpException::badRequest($e->getMessage(), 'weak_password');
        }
        $db = $this->db();
        $result = $db->transaction(function (Database $db) use ($id, $keys, $purge): array {
            $n = $db->run(
                'UPDATE mail_accounts SET password_hash = ?, kdf_salt = ?, public_key = ?, encrypted_private_key = ?, private_key_nonce = ? WHERE id = ?',
                [$keys['password_hash'], new Binary($keys['kdf_salt']), new Binary($keys['public_key']),
                    new Binary($keys['encrypted_private_key']), new Binary($keys['private_key_nonce']), $id],
            )->rowCount();
            if ($n === 0) {
                throw HttpException::notFound('Conta não encontrada');
            }
            $unreadable = (int) $db->scalar('SELECT count(*) FROM messages WHERE account_id = ?', [$id]);
            if ($purge) {
                $db->run('DELETE FROM message_attachments WHERE account_id = ?', [$id]);
                $db->run('DELETE FROM messages WHERE account_id = ?', [$id]);
                $db->run('UPDATE mail_accounts SET used_bytes = 0 WHERE id = ?', [$id]);
            }
            return ['unreadable_messages' => $purge ? 0 : $unreadable, 'purged' => $purge ? $unreadable : 0];
        });
        return Response::json(['reset' => true] + $result);
    }

    // =====================================================================
    // Fail2ban, fila do Postfix e telemetria
    // =====================================================================

    private function fail2banStatus(): Response
    {
        $res = $this->system()->run('f2b', ['banned']);
        if ($res['exit'] !== 0) {
            throw new HttpException(502, 'fail2ban_error', 'Fail2ban indisponível: ' . mb_substr($res['stderr'], 0, 200));
        }
        $data = json_decode(trim($res['stdout']), true);
        $jails = [];
        foreach (is_array($data) ? $data : [] as $jail => $ips) {
            $jails[] = ['name' => (string) $jail, 'banned' => array_values(array_filter((array) $ips, static fn ($ip) => filter_var($ip, FILTER_VALIDATE_IP)))];
        }
        return Response::json(['jails' => $jails, 'total_banned' => array_sum(array_map(static fn ($j) => count($j['banned']), $jails))]);
    }

    private function fail2banAction(Request $request, string $action): Response
    {
        $jail = (string) $request->string('jail', 50);
        $ip = (string) $request->string('ip', 45);
        if (!preg_match('/^[A-Za-z0-9_.-]{1,50}$/', $jail) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            throw HttpException::badRequest('Jail ou IP inválido');
        }
        $res = $this->system()->run('f2b', [$action, $jail, $ip]);
        if ($res['exit'] !== 0) {
            throw new HttpException(502, 'fail2ban_error', mb_substr($res['stderr'] ?: $res['stdout'], 0, 300));
        }
        return Response::json(['ok' => true, 'action' => $action, 'jail' => $jail, 'ip' => $ip]);
    }

    private function mailQueue(): Response
    {
        $res = $this->system()->run('f2b', ['mailq']);
        if ($res['exit'] !== 0) {
            throw new HttpException(502, 'queue_error', 'Falha ao ler a fila: ' . mb_substr($res['stderr'], 0, 200));
        }
        $items = [];
        foreach (preg_split('/\R/', trim($res['stdout'])) ?: [] as $line) {
            $j = json_decode($line, true);
            if (!is_array($j)) {
                continue;
            }
            $items[] = [
                'queue_id' => (string) ($j['queue_id'] ?? ''),
                'queue_name' => (string) ($j['queue_name'] ?? ''),
                'arrival_time' => isset($j['arrival_time']) ? gmdate('c', (int) $j['arrival_time']) : null,
                'size' => (int) ($j['message_size'] ?? 0),
                'sender' => (string) ($j['sender'] ?? ''),
                'recipients' => array_map(static fn ($r) => [
                    'address' => (string) ($r['address'] ?? ''),
                    'reason' => (string) ($r['delay_reason'] ?? ''),
                ], (array) ($j['recipients'] ?? [])),
            ];
        }
        return Response::json(['queue' => $items, 'count' => count($items)]);
    }

    private function flushQueue(): Response
    {
        $res = $this->system()->run('f2b', ['flush']);
        return Response::json(['ok' => $res['exit'] === 0]);
    }

    private function securityEvents(Request $request): Response
    {
        $limit = $request->queryInt('limit', 200, 1, 1000);
        $service = $request->queryString('service', null, 50);
        $hours = $request->queryInt('hours', 168, 1, 8760);
        $rows = $this->db()->all(
            'SELECT event_time, service, jail_name, host(source_ip) AS source_ip, action, details FROM security_events
             WHERE event_time > NOW() - make_interval(hours => ?) AND (?::text IS NULL OR service = ?)
             ORDER BY event_time DESC LIMIT ?',
            [$hours, $service, $service, $limit],
        );
        $summary = $this->db()->all(
            "SELECT time_bucket('1 hour', event_time) AS bucket, action, count(*) AS total FROM security_events
             WHERE event_time > NOW() - INTERVAL '24 hours' GROUP BY bucket, action ORDER BY bucket",
        );
        return Response::json(['events' => $rows, 'hourly' => $summary]);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private function db(): Database
    {
        return $this->db ??= Database::get($this->config);
    }

    private function dbOrNull(): ?Database
    {
        try {
            return $this->db();
        } catch (\Throwable) {
            return null;
        }
    }

    private function vault(): ZeroKnowledgeVault
    {
        return $this->vault ??= new ZeroKnowledgeVault(
            $this->config->require('MP_APP_MASTER_KEY'),
            $this->config->require('MP_SUBJECT_HMAC_KEY'),
        );
    }

    private function dns(): DnsValidator
    {
        return new DnsValidator($this->config->get('MP_HOSTNAME', 'localhost') ?? 'localhost', $this->config->get('MP_PUBLIC_IP'));
    }

    private function system(): SystemControl
    {
        return new SystemControl($this->config);
    }

    private function ssh(): SshOrchestrator
    {
        $dir = $this->config->dataDir();
        return new SshOrchestrator($dir . '/ssh/known_hosts.json', $dir . '/tmp');
    }

    /**
     * @param array<string,mixed> $node
     * @return array{0:SshOrchestrator,1:array{fingerprint:string,first_use:bool}}
     */
    private function sshConnect(array $node): array
    {
        $key = $this->vault()->decryptServerSecret(ZeroKnowledgeVault::bin($node['ssh_private_key_enc'], null, 'ssh'), self::SSH_KEY_CONTEXT);
        $ssh = $this->ssh();
        try {
            $info = $ssh->connect((string) $node['ip_address'], (int) $node['ssh_port'], (string) $node['ssh_user'], $key);
        } catch (\RuntimeException $e) {
            throw new HttpException(502, 'ssh_error', $e->getMessage());
        } finally {
            sodium_memzero($key);
        }
        return [$ssh, $info];
    }

    /** @return array<string,mixed> */
    private function node(int $id): array
    {
        return $this->db()->one(
            'SELECT id, node_role, hostname, host(ip_address) AS ip_address, ssh_port, ssh_user, ssh_private_key_enc, deploy_status FROM infra_nodes WHERE id = ?',
            [$id],
        ) ?? throw HttpException::notFound('Nó não encontrado');
    }

    /** @return array<string,mixed> */
    private function domain(int $id): array
    {
        return $this->db()->one('SELECT * FROM mail_domains WHERE id = ?', [$id]) ?? throw HttpException::notFound('Domínio não encontrado');
    }

    private function intParam(Request $request, string $name): int
    {
        $v = $request->param($name);
        if (!ctype_digit($v)) {
            throw HttpException::notFound();
        }
        return (int) $v;
    }

    private function uuidParam(Request $request, string $name): string
    {
        $v = strtolower($request->param($name));
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $v)) {
            throw HttpException::notFound();
        }
        return $v;
    }

    private function dbCredentialsFile(int $nodeId): string
    {
        return $this->config->dataDir() . '/db-credentials/node-' . $nodeId . '.env';
    }

    private function jobFile(string $jobId): string
    {
        return $this->config->dataDir() . '/jobs/' . $jobId . '.json';
    }

    /** @param array<string,mixed> $job */
    private function saveJob(string $jobId, array $job): void
    {
        $this->writePrivateFile($this->jobFile($jobId), (string) json_encode($job));
        // Limpeza de jobs antigos (> 1 dia)
        foreach (glob($this->config->dataDir() . '/jobs/*.json') ?: [] as $f) {
            if (filemtime($f) < time() - 86400) {
                @unlink($f);
            }
        }
    }

    /** @return array<string,mixed>|null */
    private function loadJob(string $jobId): ?array
    {
        $f = $this->jobFile($jobId);
        if (!is_file($f)) {
            return null;
        }
        $j = json_decode((string) file_get_contents($f), true);
        return is_array($j) ? $j : null;
    }

    private function writePrivateFile(string $path, string $content): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            throw new \RuntimeException('Não foi possível criar ' . $dir);
        }
        $old = umask(0077);
        try {
            $tmp = $path . '.' . bin2hex(random_bytes(4));
            if (file_put_contents($tmp, $content, LOCK_EX) === false || !rename($tmp, $path)) {
                throw new \RuntimeException('Falha ao gravar ' . $path);
            }
        } finally {
            umask($old);
        }
    }
}
