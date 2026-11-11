<?php

declare(strict_types=1);

namespace MailPlatform\Services;

use MailPlatform\Config\Binary;
use MailPlatform\Config\Database;
use MailPlatform\Crypto\ZeroKnowledgeVault;
use MailPlatform\Http\HttpException;
use RuntimeException;

/**
 * Envio de e-mails pelo Webmail.
 *
 *  1. Monta a mensagem MIME (text/plain + text/html opcional + anexos).
 *  2. Entrega ao Postfix pela submission local (127.0.0.1:587), onde o
 *     OpenDKIM assina obrigatoriamente (milter_default_action=tempfail).
 *  3. Grava uma cópia na pasta SENT, selada com a public_key do PRÓPRIO
 *     remetente (crypto_box_seal), contabilizando a cota.
 *
 * Também salva rascunhos (pasta DRAFTS) com o mesmo formato cifrado.
 */
final class MailSender
{
    public const MAX_RECIPIENTS = 100;
    public const MAX_MESSAGE_BYTES = 52428800;
    private const THREAD_WINDOW_DAYS = 90;

    public function __construct(
        private readonly Database $db,
        private readonly ZeroKnowledgeVault $vault,
        private readonly string $mailHostname,
        private readonly string $smtpHost = '127.0.0.1',
        private readonly int $smtpPort = 587,
    ) {
    }

    /**
     * @param array{id:string,email:string,full_name:string,public_key:string} $account
     * @param array{to:list<string>,cc?:list<string>,bcc?:list<string>,subject:string,body_plain:string,body_html?:?string,
     *              attachments?:list<array{name:string,mime:string,content:string}>,
     *              reply?:?array{message_id_header:?string,references:?string,thread_id:?string}} $msg
     * @return array{message_id:string,rfc_message_id:string,thread_id:string,size:int,copy_saved:bool}
     */
    public function send(array $account, array $msg): array
    {
        $to = $this->cleanAddresses($msg['to'] ?? []);
        $cc = $this->cleanAddresses($msg['cc'] ?? []);
        $bcc = $this->cleanAddresses($msg['bcc'] ?? []);
        $all = array_values(array_unique(array_merge($to, $cc, $bcc)));
        if ($to === [] && $cc === [] && $bcc === []) {
            throw HttpException::badRequest('Informe ao menos um destinatário', 'no_recipients');
        }
        if (count($all) > self::MAX_RECIPIENTS) {
            throw HttpException::badRequest('Destinatários demais (máx. ' . self::MAX_RECIPIENTS . ')', 'too_many_recipients');
        }

        $rfcId = '<' . bin2hex(random_bytes(16)) . '@' . $this->mailHostname . '>';
        $built = $this->buildMime($account, $to, $cc, $msg, $rfcId);
        $size = strlen($built['raw']);
        if ($size > self::MAX_MESSAGE_BYTES) {
            throw HttpException::badRequest('Mensagem maior que 50 MiB', 'too_large');
        }
        $this->assertQuota((string) $account['id'], $size);

        $this->smtpSend((string) $account['email'], $all, $built['raw']);

        // A cópia em SENT inclui o Bcc (visível apenas para o próprio remetente).
        $storedHeaders = $built['headers'] . ($bcc !== [] ? "\r\nBcc: " . implode(', ', $bcc) : '');
        $copySaved = true;
        try {
            $ids = $this->storeCopy($account, 'SENT', $msg, $storedHeaders, $to !== [] ? $to : array_merge($cc, $bcc), $size, true);
        } catch (\Throwable $e) {
            // A mensagem JÁ foi enviada; não pode virar erro para o usuário reenviar.
            error_log('mail-platform: mensagem enviada mas cópia em SENT falhou: ' . $e->getMessage());
            $copySaved = false;
            $ids = ['message_id' => '', 'thread_id' => (string) ($msg['reply']['thread_id'] ?? '')];
        }
        return $ids + ['rfc_message_id' => $rfcId, 'size' => $size, 'copy_saved' => $copySaved];
    }

    /**
     * Salva (ou substitui) um rascunho cifrado.
     *
     * @param array{id:string,email:string,full_name:string,public_key:string} $account
     * @param array<string,mixed> $msg mesmo formato de send()
     * @return array{message_id:string,thread_id:string}
     */
    public function saveDraft(array $account, array $msg, ?string $replaceDraftId = null): array
    {
        $to = $this->cleanAddresses($msg['to'] ?? [], false);
        $cc = $this->cleanAddresses($msg['cc'] ?? [], false);
        $bcc = $this->cleanAddresses($msg['bcc'] ?? [], false);
        $rfcId = '<' . bin2hex(random_bytes(16)) . '@' . $this->mailHostname . '>';
        $built = $this->buildMime($account, $to, $cc, $msg, $rfcId);
        $headers = $built['headers'] . ($bcc !== [] ? "\r\nBcc: " . implode(', ', $bcc) : '');
        $size = strlen($built['raw']);

        return $this->db->transaction(function () use ($account, $msg, $headers, $to, $cc, $bcc, $size, $replaceDraftId): array {
            if ($replaceDraftId !== null) {
                $this->deleteMessage((string) $account['id'], $replaceDraftId, 'DRAFTS');
            }
            $this->assertQuota((string) $account['id'], $size);
            return $this->storeCopy($account, 'DRAFTS', $msg, $headers, array_merge($to, $cc, $bcc), $size, true, false);
        });
    }

    /** Remove definitivamente uma mensagem (e anexos), devolvendo a cota. */
    public function deleteMessage(string $accountId, string $messageId, ?string $onlyFolder = null): bool
    {
        $row = $this->db->one(
            'SELECT received_at, size_bytes FROM messages WHERE account_id = ? AND message_id = ?'
            . ($onlyFolder !== null ? ' AND folder = ?' : ''),
            $onlyFolder !== null ? [$accountId, $messageId, $onlyFolder] : [$accountId, $messageId],
        );
        if ($row === null) {
            return false;
        }
        $this->db->run('DELETE FROM message_attachments WHERE account_id = ? AND message_id = ?', [$accountId, $messageId]);
        $this->db->run('DELETE FROM messages WHERE account_id = ? AND message_id = ? AND received_at = ?', [$accountId, $messageId, $row['received_at']]);
        $this->db->run(
            'UPDATE mail_accounts SET used_bytes = GREATEST(0, used_bytes - ?) WHERE id = ?',
            [(int) $row['size_bytes'], $accountId],
        );
        return true;
    }

    // ------------------------------------------------------------------
    // Persistência cifrada
    // ------------------------------------------------------------------

    /**
     * @param array{id:string,email:string,full_name:string,public_key:string} $account
     * @param array<string,mixed> $msg
     * @param list<string> $recipients
     * @return array{message_id:string,thread_id:string}
     */
    private function storeCopy(array $account, string $folder, array $msg, string $headers, array $recipients, int $size, bool $isRead, bool $ownTransaction = true): array
    {
        $store = function () use ($account, $folder, $msg, $headers, $recipients, $size, $isRead): array {
            $accountId = (string) $account['id'];
            $pk = (string) $account['public_key'];
            $subject = (string) ($msg['subject'] ?? '');
            $hash = $this->vault->subjectHash($subject, $accountId);
            $threadId = $msg['reply']['thread_id'] ?? null;
            if (!is_string($threadId) || !preg_match('/^[0-9a-f-]{36}$/i', $threadId)) {
                $threadId = $this->db->scalar(
                    "SELECT thread_id FROM messages WHERE account_id = ? AND subject_hash = ? AND received_at > NOW() - make_interval(days => ?) ORDER BY received_at DESC LIMIT 1",
                    [$accountId, new Binary($hash), self::THREAD_WINDOW_DAYS],
                ) ?? self::uuid4();
            }
            $messageId = self::uuid4();
            $receivedAt = gmdate('Y-m-d H:i:s.') . sprintf('%06d', (int) (fmod(microtime(true), 1) * 1e6)) . '+00';
            $sealed = ZeroKnowledgeVault::sealMessage([
                'subject' => $subject,
                'headers' => $headers,
                'body_plain' => $msg['body_plain'] ?? '',
                'body_html' => $msg['body_html'] ?? null,
            ], $pk);
            $attachments = $msg['attachments'] ?? [];

            $this->db->run(
                'UPDATE mail_accounts SET used_bytes = used_bytes + ? WHERE id = ?',
                [$size, $accountId],
            );
            $this->db->run(
                'INSERT INTO messages (received_at, message_id, account_id, thread_id, folder, sender_address, recipient_address,
                    subject_hash, encrypted_subject, encrypted_snippet, encrypted_headers, encrypted_body_plain, encrypted_body_html,
                    spf_pass, dkim_pass, dmarc_pass, spam_score, is_read, is_starred, has_attachments, size_bytes)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, TRUE, TRUE, 0, ?, FALSE, ?, ?)',
                [
                    $receivedAt, $messageId, $accountId, $threadId, $folder,
                    substr((string) $account['email'], 0, 255),
                    mb_substr(implode(', ', $recipients), 0, 255),
                    new Binary($hash),
                    new Binary($sealed['encrypted_subject']),
                    new Binary($sealed['encrypted_snippet']),
                    new Binary($sealed['encrypted_headers']),
                    Binary::orNull($sealed['encrypted_body_plain']),
                    Binary::orNull($sealed['encrypted_body_html']),
                    $isRead,
                    $attachments !== [],
                    min($size, 2147483647),
                ],
            );
            foreach ($attachments as $att) {
                $a = ZeroKnowledgeVault::sealAttachment((string) $att['name'], (string) $att['mime'], (string) $att['content'], $pk);
                $this->db->run(
                    'INSERT INTO message_attachments (received_at, attachment_id, account_id, message_id, encrypted_filename,
                        encrypted_mime_type, encrypted_content, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [$receivedAt, self::uuid4(), $accountId, $messageId, new Binary($a['encrypted_filename']),
                        new Binary($a['encrypted_mime_type']), new Binary($a['encrypted_content']), $a['size_bytes']],
                );
            }
            return ['message_id' => $messageId, 'thread_id' => (string) $threadId];
        };
        return $ownTransaction ? $this->db->transaction($store) : $store();
    }

    private function assertQuota(string $accountId, int $size): void
    {
        $ok = $this->db->scalar('SELECT (used_bytes + ?) <= quota_bytes FROM mail_accounts WHERE id = ?', [$size, $accountId]);
        if ($ok !== true) {
            throw new HttpException(507, 'quota_exceeded', 'Cota da caixa postal excedida');
        }
    }

    // ------------------------------------------------------------------
    // MIME
    // ------------------------------------------------------------------

    /**
     * @param array{email:string,full_name:string} $account
     * @param list<string> $to
     * @param list<string> $cc
     * @param array<string,mixed> $msg
     * @return array{raw:string,headers:string}
     */
    private function buildMime(array $account, array $to, array $cc, array $msg, string $rfcId): array
    {
        $subject = self::headerSafe((string) ($msg['subject'] ?? ''));
        $plain = str_replace(["\r\n", "\r"], "\n", (string) ($msg['body_plain'] ?? ''));
        $html = isset($msg['body_html']) && $msg['body_html'] !== '' ? (string) $msg['body_html'] : null;
        $attachments = $msg['attachments'] ?? [];

        $h = [];
        $h[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' +0000';
        $h[] = 'From: ' . self::formatAddress((string) $account['email'], (string) $account['full_name']);
        if ($to !== []) {
            $h[] = 'To: ' . implode(', ', $to);
        }
        if ($cc !== []) {
            $h[] = 'Cc: ' . implode(', ', $cc);
        }
        $h[] = 'Subject: ' . self::encodeHeader($subject);
        $h[] = 'Message-ID: ' . $rfcId;
        $reply = $msg['reply'] ?? null;
        if (is_array($reply) && !empty($reply['message_id_header']) && preg_match('/^<[^<>\s]{1,250}>$/', (string) $reply['message_id_header'])) {
            $inReplyTo = (string) $reply['message_id_header'];
            $refs = trim(self::headerSafe((string) ($reply['references'] ?? '')) . ' ' . $inReplyTo);
            $h[] = 'In-Reply-To: ' . $inReplyTo;
            $h[] = 'References: ' . self::fold(mb_substr($refs, -900));
        }
        $h[] = 'MIME-Version: 1.0';

        $textPart = "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
            . self::qp($plain);
        $body = $textPart;
        if ($html !== null) {
            $b = self::boundary('alt');
            $body = "Content-Type: multipart/alternative; boundary=\"{$b}\"\r\n\r\n"
                . "--{$b}\r\n" . $textPart . "\r\n"
                . "--{$b}\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
                . self::qp($html) . "\r\n--{$b}--";
        }
        if ($attachments !== []) {
            $b = self::boundary('mix');
            $mixed = "Content-Type: multipart/mixed; boundary=\"{$b}\"\r\n\r\n--{$b}\r\n" . $body . "\r\n";
            foreach ($attachments as $att) {
                $name = self::headerSafe((string) $att['name']);
                $mime = preg_match('#^[a-z0-9.+-]+/[a-z0-9.+-]+$#i', (string) $att['mime']) ? (string) $att['mime'] : 'application/octet-stream';
                $ascii = preg_replace('/[^A-Za-z0-9._-]+/', '_', $name) ?: 'anexo';
                $mixed .= "--{$b}\r\nContent-Type: {$mime}; name=\"{$ascii}\"\r\n"
                    . "Content-Disposition: attachment; filename=\"{$ascii}\"; filename*=UTF-8''" . rawurlencode($name) . "\r\n"
                    . "Content-Transfer-Encoding: base64\r\n\r\n"
                    . rtrim(chunk_split(base64_encode((string) $att['content']), 76, "\r\n")) . "\r\n";
            }
            $body = $mixed . "--{$b}--";
        }

        // Separa os headers do "body" MIME (o primeiro bloco de headers do corpo
        // pertence ao topo da mensagem).
        [$partHeaders, $partBody] = explode("\r\n\r\n", $body, 2);
        $headers = implode("\r\n", $h) . "\r\n" . $partHeaders;
        return ['raw' => $headers . "\r\n\r\n" . $partBody . "\r\n", 'headers' => $headers];
    }

    private static function formatAddress(string $email, string $name): string
    {
        $name = self::headerSafe($name);
        if ($name === '') {
            return $email;
        }
        if (preg_match('/^[\x20-\x7E]*$/', $name)) {
            return '"' . addcslashes($name, '"\\') . '" <' . $email . '>';
        }
        return self::encodeHeader($name) . ' <' . $email . '>';
    }

    private static function encodeHeader(string $value): string
    {
        if (preg_match('/^[\x20-\x7E]*$/', $value)) {
            return self::fold($value);
        }
        return mb_encode_mimeheader($value, 'UTF-8', 'B', "\r\n", 9);
    }

    private static function fold(string $value): string
    {
        return wordwrap($value, 900, "\r\n ", true);
    }

    private static function headerSafe(string $v): string
    {
        return trim((string) preg_replace('/[\r\n\x00]+/', ' ', $v));
    }

    private static function qp(string $text): string
    {
        return str_replace(["\r\n", "\n"], ["\n", "\r\n"], quoted_printable_encode(str_replace("\n", "\r\n", $text)));
    }

    private static function boundary(string $tag): string
    {
        return '=_mp_' . $tag . '_' . bin2hex(random_bytes(12));
    }

    /** @return list<string> */
    private function cleanAddresses(mixed $list, bool $strict = true): array
    {
        if (is_string($list)) {
            $list = preg_split('/[,;]+/', $list) ?: [];
        }
        if (!is_array($list)) {
            throw HttpException::badRequest('Lista de destinatários inválida', 'invalid_recipients');
        }
        $out = [];
        foreach ($list as $addr) {
            if (!is_string($addr)) {
                continue;
            }
            $addr = trim($addr);
            if (preg_match('/<([^<>]+)>\s*$/', $addr, $m)) {
                $addr = trim($m[1]);
            }
            if ($addr === '') {
                continue;
            }
            $addr = strtolower($addr);
            if (strlen($addr) > 254 || !filter_var($addr, FILTER_VALIDATE_EMAIL)) {
                if ($strict) {
                    throw HttpException::badRequest("Endereço inválido: {$addr}", 'invalid_recipient');
                }
                continue;
            }
            $out[$addr] = $addr;
        }
        return array_values($out);
    }

    // ------------------------------------------------------------------
    // SMTP (submission local)
    // ------------------------------------------------------------------

    /** @param list<string> $recipients */
    private function smtpSend(string $from, array $recipients, string $raw): void
    {
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client("tcp://{$this->smtpHost}:{$this->smtpPort}", $errno, $errstr, 15);
        if ($sock === false) {
            throw new HttpException(503, 'smtp_unavailable', 'Servidor SMTP local indisponível');
        }
        stream_set_timeout($sock, 120);
        try {
            $this->expect($sock, [220]);
            $this->command($sock, 'EHLO ' . $this->mailHostname, [250]);
            $this->command($sock, 'MAIL FROM:<' . $from . '> SIZE=' . strlen($raw), [250]);
            $accepted = 0;
            $rejected = [];
            foreach ($recipients as $rcpt) {
                [$code, $text] = $this->command($sock, 'RCPT TO:<' . $rcpt . '>', null);
                if ($code === 250 || $code === 251) {
                    $accepted++;
                } else {
                    $rejected[] = "{$rcpt}: {$code} {$text}";
                }
            }
            if ($accepted === 0 || $rejected !== []) {
                $this->command($sock, 'RSET', null);
                throw new HttpException(422, 'recipient_rejected', 'Destinatário recusado pelo servidor', ['rejected' => $rejected]);
            }
            $this->command($sock, 'DATA', [354]);
            $data = (string) preg_replace('/^\./m', '..', str_replace(["\r\n", "\r", "\n"], ["\n", "\n", "\r\n"], $raw));
            if (!str_ends_with($data, "\r\n")) {
                $data .= "\r\n";
            }
            $this->write($sock, $data . ".\r\n");
            [$code, $text] = $this->expect($sock, null);
            if ($code !== 250) {
                throw new HttpException(502, 'smtp_rejected', "Envio recusado: {$code} {$text}");
            }
            @fwrite($sock, "QUIT\r\n");
        } finally {
            fclose($sock);
        }
    }

    /**
     * @param resource $sock
     * @param list<int>|null $expected
     * @return array{0:int,1:string}
     */
    private function command($sock, string $line, ?array $expected): array
    {
        $this->write($sock, $line . "\r\n");
        return $this->expect($sock, $expected);
    }

    /** @param resource $sock */
    private function write($sock, string $data): void
    {
        $len = strlen($data);
        for ($off = 0; $off < $len;) {
            $n = fwrite($sock, substr($data, $off, 65536));
            if ($n === false || $n === 0) {
                throw new HttpException(502, 'smtp_io', 'Falha de comunicação com o SMTP');
            }
            $off += $n;
        }
    }

    /**
     * @param resource $sock
     * @param list<int>|null $expected
     * @return array{0:int,1:string}
     */
    private function expect($sock, ?array $expected): array
    {
        $text = '';
        $code = 0;
        while (($line = fgets($sock, 2048)) !== false) {
            $code = (int) substr($line, 0, 3);
            $text .= trim(substr($line, 4)) . ' ';
            if (strlen($line) < 4 || $line[3] !== '-') {
                break;
            }
        }
        if ($code === 0) {
            throw new HttpException(502, 'smtp_io', 'SMTP não respondeu');
        }
        if ($expected !== null && !in_array($code, $expected, true)) {
            throw new HttpException(502, 'smtp_error', "SMTP: {$code} " . trim($text));
        }
        return [$code, trim($text)];
    }

    public static function uuid4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }
}
