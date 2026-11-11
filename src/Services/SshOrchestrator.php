<?php

declare(strict_types=1);

namespace MailPlatform\Services;

use RuntimeException;

/**
 * Orquestrador SSH (ext-ssh2 / libssh2).
 *
 *  - Autenticação por chave privada (Ed25519 no formato OpenSSH ou RSA PEM),
 *    sem senha. A chave vive em disco apenas o tempo do handshake, num arquivo
 *    0600 em diretório privado, e é sobrescrita antes de ser removida.
 *  - Verificação da chave do host por TOFU (trust on first use): a impressão
 *    digital SHA-256 é gravada no primeiro contato e qualquer mudança aborta.
 *  - Execução com streaming linha a linha (alimenta o SSE do painel), com
 *    remoção de sequências ANSI/controle e mascaramento de segredos.
 */
final class SshOrchestrator
{
    private const EXIT_MARKER = '__MP_EXIT_STATUS__=';

    /** @var resource|null */
    private $connection = null;
    private string $host = '';
    private int $port = 22;

    public function __construct(
        private readonly string $knownHostsFile,
        private readonly string $tmpDir,
    ) {
        if (!extension_loaded('ssh2')) {
            throw new RuntimeException('Extensão PHP ssh2 não instalada (php8.4-ssh2)');
        }
    }

    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Conecta e autentica.
     *
     * @param string $privateKey chave privada (texto PEM/OpenSSH, sem passphrase)
     * @return array{fingerprint:string,first_use:bool}
     */
    public function connect(string $host, int $port, string $user, string $privateKey): array
    {
        if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i', $host)) {
            throw new RuntimeException('Host inválido');
        }
        if ($port < 1 || $port > 65535) {
            throw new RuntimeException('Porta SSH inválida');
        }
        if (!preg_match('/^[a-z_][a-z0-9_.-]{0,31}$/i', $user)) {
            throw new RuntimeException('Usuário SSH inválido');
        }
        $this->disconnect();
        $this->host = $host;
        $this->port = $port;

        $conn = @ssh2_connect($host, $port, [
            'hostkey' => 'ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256',
        ]);
        if ($conn === false) {
            throw new RuntimeException("Não foi possível conectar em {$host}:{$port}");
        }

        $raw = (string) ssh2_fingerprint($conn, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_RAW);
        // libssh2 expõe SHA1/MD5; derivamos um identificador estável a partir dele.
        $fingerprint = 'SHA256:' . rtrim(base64_encode(hash('sha256', $raw, true)), '=');
        $firstUse = $this->verifyHostKey($host, $port, $fingerprint);

        [$pubFile, $privFile] = $this->writeKeyFiles($privateKey);
        try {
            $ok = @ssh2_auth_pubkey_file($conn, $user, $pubFile, $privFile);
        } finally {
            $this->shred($privFile);
            $this->shred($pubFile);
        }
        if (!$ok) {
            throw new RuntimeException('Autenticação SSH recusada (verifique usuário e chave)');
        }
        $this->connection = $conn;
        return ['fingerprint' => $fingerprint, 'first_use' => $firstUse];
    }

    public function disconnect(): void
    {
        if ($this->connection !== null) {
            @ssh2_disconnect($this->connection);
            $this->connection = null;
        }
    }

    /**
     * Executa um comando remoto com streaming linha a linha.
     *
     * @param callable(string):void $onLine recebe cada linha já sanitizada
     * @param list<string> $secrets valores a mascarar na saída
     * @return int código de saída do comando remoto
     */
    public function execStream(string $command, callable $onLine, int $timeout = 3600, array $secrets = [], ?callable $onIdle = null, bool $sanitize = true): int
    {
        $conn = $this->requireConnection();
        $wrapped = 'export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8; ( ' . $command . ' ) 2>&1; echo "'
            . self::EXIT_MARKER . '$?"';
        $stream = @ssh2_exec($conn, 'bash -c ' . escapeshellarg($wrapped));
        if ($stream === false) {
            throw new RuntimeException('Falha ao executar comando remoto');
        }
        stream_set_blocking($stream, false);
        $buffer = '';
        $exit = null;
        $deadline = time() + $timeout;
        $lastActivity = time();
        $emit = function (string $line) use (&$exit, $onLine, $secrets, $sanitize): void {
            $line = $sanitize ? self::sanitize($line, $secrets) : rtrim($line, "\r");
            if (str_starts_with($line, self::EXIT_MARKER)) {
                $exit = (int) substr($line, strlen(self::EXIT_MARKER));
                return;
            }
            $onLine($line);
        };
        while (true) {
            $chunk = fread($stream, 8192);
            if ($chunk !== false && $chunk !== '') {
                $buffer .= $chunk;
                $lastActivity = time();
                while (($pos = strpos($buffer, "\n")) !== false) {
                    $emit(substr($buffer, 0, $pos));
                    $buffer = substr($buffer, $pos + 1);
                }
                continue;
            }
            if (feof($stream)) {
                break;
            }
            if (time() > $deadline) {
                fclose($stream);
                throw new RuntimeException('Tempo limite excedido no comando remoto');
            }
            if ($onIdle !== null && time() - $lastActivity >= 10) {
                $onIdle();
                $lastActivity = time();
            }
            usleep(50000);
        }
        if ($buffer !== '') {
            $emit($buffer);
        }
        fclose($stream);
        return $exit ?? 255;
    }

    /** Executa e devolve [exit, saída] (para comandos curtos). */
    public function exec(string $command, int $timeout = 120, bool $sanitize = true): array
    {
        $lines = [];
        $exit = $this->execStream($command, static function (string $l) use (&$lines): void {
            $lines[] = $l;
        }, $timeout, [], null, $sanitize);
        return [$exit, implode("\n", $lines)];
    }

    /** Envia um arquivo via SFTP (modo octal, ex.: 0700). */
    public function upload(string $content, string $remotePath, int $mode = 0600): void
    {
        $this->assertRemotePath($remotePath);
        $sftp = @ssh2_sftp($this->requireConnection());
        if ($sftp === false) {
            throw new RuntimeException('Subsistema SFTP indisponível');
        }
        $dir = dirname($remotePath);
        @ssh2_sftp_mkdir($sftp, $dir, 0700, true);
        $fh = @fopen('ssh2.sftp://' . intval($sftp) . $remotePath, 'w');
        if ($fh === false) {
            throw new RuntimeException("Falha ao gravar {$remotePath}");
        }
        $written = fwrite($fh, $content);
        fclose($fh);
        if ($written !== strlen($content)) {
            throw new RuntimeException("Gravação incompleta de {$remotePath}");
        }
        @ssh2_sftp_chmod($sftp, $remotePath, $mode);
    }

    /** Baixa um arquivo remoto via SFTP (limite de 1 MiB). */
    public function download(string $remotePath): string
    {
        $this->assertRemotePath($remotePath);
        $sftp = @ssh2_sftp($this->requireConnection());
        if ($sftp === false) {
            throw new RuntimeException('Subsistema SFTP indisponível');
        }
        $fh = @fopen('ssh2.sftp://' . intval($sftp) . $remotePath, 'r');
        if ($fh === false) {
            throw new RuntimeException("Falha ao ler {$remotePath}");
        }
        $data = (string) stream_get_contents($fh, 1048576);
        fclose($fh);
        return $data;
    }

    /** Esquece a chave de host registrada (após reinstalação do servidor). */
    public function forgetHost(string $host, int $port): void
    {
        $known = $this->loadKnownHosts();
        unset($known["{$host}:{$port}"]);
        $this->saveKnownHosts($known);
    }

    // ------------------------------------------------------------------
    // Sanitização de saída
    // ------------------------------------------------------------------

    /** @param list<string> $secrets */
    public static function sanitize(string $line, array $secrets = []): string
    {
        $line = (string) preg_replace('/\x1B\[[0-9;?]*[ -\/]*[@-~]|\x1B[@-Z\\\\-_]/', '', $line);
        $line = str_replace("\r", '', $line);
        $line = (string) preg_replace('/[\x00-\x08\x0B-\x1F\x7F]/', '', $line);
        foreach ($secrets as $s) {
            if ($s !== '') {
                $line = str_replace($s, '********', $line);
            }
        }
        // Mascara atribuições sensíveis (PASSWORD=..., MP_*_KEY='...').
        $line = (string) preg_replace("/((?:PASSWORD|SECRET|_KEY|PEM_B64)[A-Z_]*\\s*[=:]\\s*)('?)[^'\\s]+\\2/i", '$1$2********$2', $line);
        if (!mb_check_encoding($line, 'UTF-8')) {
            $line = mb_convert_encoding($line, 'UTF-8', 'UTF-8');
        }
        return mb_substr($line, 0, 4000);
    }

    // ------------------------------------------------------------------
    // Internos
    // ------------------------------------------------------------------

    /** @return resource */
    private function requireConnection()
    {
        if ($this->connection === null) {
            throw new RuntimeException('Sessão SSH não conectada');
        }
        return $this->connection;
    }

    private function verifyHostKey(string $host, int $port, string $fingerprint): bool
    {
        $known = $this->loadKnownHosts();
        $key = "{$host}:{$port}";
        if (isset($known[$key])) {
            if (!hash_equals((string) $known[$key]['fingerprint'], $fingerprint)) {
                throw new RuntimeException(
                    "A chave do host {$key} mudou (esperado {$known[$key]['fingerprint']}, recebido {$fingerprint}). "
                    . 'Possível ataque man-in-the-middle; se o servidor foi reinstalado, remova o registro no painel.'
                );
            }
            return false;
        }
        $known[$key] = ['fingerprint' => $fingerprint, 'first_seen' => gmdate('c')];
        $this->saveKnownHosts($known);
        return true;
    }

    /** @return array<string,array{fingerprint:string,first_seen:string}> */
    private function loadKnownHosts(): array
    {
        if (!is_file($this->knownHostsFile)) {
            return [];
        }
        $data = json_decode((string) file_get_contents($this->knownHostsFile), true);
        return is_array($data) ? $data : [];
    }

    /** @param array<string,mixed> $known */
    private function saveKnownHosts(array $known): void
    {
        $dir = dirname($this->knownHostsFile);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            throw new RuntimeException('Não foi possível criar ' . $dir);
        }
        $tmp = $this->knownHostsFile . '.' . bin2hex(random_bytes(4));
        file_put_contents($tmp, json_encode($known, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
        chmod($tmp, 0600);
        rename($tmp, $this->knownHostsFile);
    }

    /** @return array{0:string,1:string} [arquivo público, arquivo privado] */
    private function writeKeyFiles(string $privateKey): array
    {
        $privateKey = str_replace("\r\n", "\n", trim($privateKey)) . "\n";
        $publicLine = self::derivePublicKey($privateKey);
        if (!is_dir($this->tmpDir) && !@mkdir($this->tmpDir, 0700, true)) {
            throw new RuntimeException('Diretório temporário indisponível');
        }
        $old = umask(0077);
        try {
            $base = $this->tmpDir . '/sshkey-' . bin2hex(random_bytes(8));
            if (file_put_contents($base, $privateKey, LOCK_EX) === false
                || file_put_contents($base . '.pub', $publicLine . "\n", LOCK_EX) === false) {
                throw new RuntimeException('Falha ao preparar a chave SSH');
            }
        } finally {
            umask($old);
        }
        return [$base . '.pub', $base];
    }

    private function shred(string $file): void
    {
        if (is_file($file)) {
            $size = filesize($file) ?: 0;
            @file_put_contents($file, random_bytes(max(1, $size)));
            @unlink($file);
        }
    }

    /**
     * Deriva a linha "tipo base64" da chave pública a partir da privada.
     * Suporta OpenSSH (ed25519/rsa/ecdsa, sem passphrase) e PEM RSA/EC.
     */
    public static function derivePublicKey(string $privateKey): string
    {
        if (str_contains($privateKey, 'BEGIN OPENSSH PRIVATE KEY')) {
            $b64 = preg_replace('/-----[^-]+-----|\s+/', '', $privateKey) ?? '';
            $bin = base64_decode($b64, true);
            if ($bin === false || !str_starts_with($bin, "openssh-key-v1\0")) {
                throw new RuntimeException('Chave OpenSSH inválida');
            }
            $off = 15;
            $cipher = self::readString($bin, $off);
            self::readString($bin, $off); // kdfname
            self::readString($bin, $off); // kdfoptions
            if ($cipher !== 'none') {
                throw new RuntimeException('Chaves com passphrase não são suportadas; use uma chave sem passphrase dedicada ao deploy');
            }
            $n = unpack('N', substr($bin, $off, 4))[1] ?? 0;
            $off += 4;
            if ($n < 1) {
                throw new RuntimeException('Chave OpenSSH sem chave pública');
            }
            $blob = self::readString($bin, $off);
            $tmp = 0;
            $type = self::readString($blob, $tmp);
            return $type . ' ' . base64_encode($blob);
        }

        $key = openssl_pkey_get_private($privateKey);
        if ($key === false) {
            throw new RuntimeException('Formato de chave privada não reconhecido');
        }
        $details = openssl_pkey_get_details($key);
        if (($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA) {
            $blob = self::sshString('ssh-rsa') . self::sshMpint($details['rsa']['e']) . self::sshMpint($details['rsa']['n']);
            return 'ssh-rsa ' . base64_encode($blob);
        }
        if (($details['type'] ?? null) === OPENSSL_KEYTYPE_EC) {
            $curve = ['prime256v1' => 'nistp256', 'secp384r1' => 'nistp384', 'secp521r1' => 'nistp521'][$details['ec']['curve_name']] ?? null;
            if ($curve === null) {
                throw new RuntimeException('Curva EC não suportada');
            }
            $len = ['nistp256' => 32, 'nistp384' => 48, 'nistp521' => 66][$curve];
            $point = "\x04" . str_pad($details['ec']['x'], $len, "\0", STR_PAD_LEFT) . str_pad($details['ec']['y'], $len, "\0", STR_PAD_LEFT);
            $type = 'ecdsa-sha2-' . $curve;
            return $type . ' ' . base64_encode(self::sshString($type) . self::sshString($curve) . self::sshString($point));
        }
        throw new RuntimeException('Tipo de chave não suportado (use Ed25519, RSA ou ECDSA)');
    }

    private static function readString(string $bin, int &$off): string
    {
        if (strlen($bin) < $off + 4) {
            throw new RuntimeException('Chave truncada');
        }
        $len = unpack('N', substr($bin, $off, 4))[1];
        $off += 4;
        if ($len > strlen($bin) - $off) {
            throw new RuntimeException('Chave truncada');
        }
        $s = substr($bin, $off, $len);
        $off += $len;
        return $s;
    }

    private static function sshString(string $s): string
    {
        return pack('N', strlen($s)) . $s;
    }

    private static function sshMpint(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes !== '' && (ord($bytes[0]) & 0x80)) {
            $bytes = "\0" . $bytes;
        }
        return self::sshString($bytes);
    }

    private function assertRemotePath(string $path): void
    {
        if (!preg_match('#^/[A-Za-z0-9._/-]{1,255}$#', $path) || str_contains($path, '..')) {
            throw new RuntimeException('Caminho remoto inválido');
        }
    }
}
