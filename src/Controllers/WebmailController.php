<?php

declare(strict_types=1);

namespace MailPlatform\Controllers;

use MailPlatform\Config\Binary;
use MailPlatform\Config\Config;
use MailPlatform\Config\Database;
use MailPlatform\Crypto\VaultAuthenticationException;
use MailPlatform\Crypto\ZeroKnowledgeVault;
use MailPlatform\Http\HttpException;
use MailPlatform\Http\Request;
use MailPlatform\Http\Response;
use MailPlatform\Http\Router;
use MailPlatform\Http\Session;
use MailPlatform\Services\MailSender;
use MailPlatform\Services\SecurityLog;

/**
 * APIs do Webmail (zero-knowledge).
 *
 * A chave privada X25519 da conta só existe em claro durante a requisição:
 * no login ela é desbloqueada com a senha (Argon2id) e re-cifrada com uma
 * chave efêmera que viaja APENAS no cookie MPKEY (HttpOnly, path /api/webmail).
 * A sessão no servidor guarda só o blob cifrado; sem o cookie, nada é legível.
 *
 * Todas as rotas exigem sessão de webmail (exceto GET /session e POST /login);
 * métodos que alteram estado exigem o cabeçalho X-CSRF-Token.
 */
final class WebmailController
{
    public const FOLDERS = ['INBOX', 'SENT', 'DRAFTS', 'SPAM', 'TRASH', 'ARCHIVE'];
    private const VIRTUAL_FOLDERS = ['STARRED'];
    private const KEY_COOKIE = 'MPKEY';
    private const KEY_COOKIE_PATH = '/api/webmail';
    private const SEARCH_SCAN_LIMIT = 1000;
    private const MAX_INLINE_DATA_URI_BYTES = 5242880;   // por imagem embutida (cid:)
    private const MAX_INLINE_TOTAL_BYTES = 20971520;     // total por mensagem renderizada
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$bXl3N0w1VnVNYjUyNXQwdw$jauTCN7ZD/Br+qbSYCa20p4uDGw9iHgazatpwQz0znE';
    private const UUID_RE = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/';

    private ?Database $db = null;
    private ?ZeroKnowledgeVault $vault = null;
    /** @var array<string,mixed>|null */
    private ?array $account = null;
    private ?string $privateKey = null;

    public function __construct(
        private readonly Config $config,
        private readonly Session $session,
    ) {
    }

    public function __destruct()
    {
        if ($this->privateKey !== null) {
            sodium_memzero($this->privateKey);
        }
    }

    public function register(Router $r): void
    {
        $p = '/api/webmail';
        $r->add('GET', "{$p}/session", fn (Request $q) => $this->sessionInfo());
        $r->add('POST', "{$p}/login", fn (Request $q) => $this->login($q));
        $r->add('POST', "{$p}/logout", fn (Request $q) => $this->guard($q, fn () => $this->logout(), false));
        $r->add('POST', "{$p}/password", fn (Request $q) => $this->guard($q, fn () => $this->changePassword($q)));

        $r->add('GET', "{$p}/folders", fn (Request $q) => $this->guard($q, fn () => $this->folders()));
        $r->add('POST', "{$p}/folders/{folder}/empty", fn (Request $q) => $this->guard($q, fn () => $this->emptyFolder($q)));
        $r->add('GET', "{$p}/messages", fn (Request $q) => $this->guard($q, fn () => $this->listThreads($q)));
        $r->add('GET', "{$p}/threads/{id}", fn (Request $q) => $this->guard($q, fn () => $this->getThread($q)));
        $r->add('PATCH', "{$p}/threads/{id}", fn (Request $q) => $this->guard($q, fn () => $this->updateThread($q)));
        $r->add('DELETE', "{$p}/threads/{id}", fn (Request $q) => $this->guard($q, fn () => $this->deleteThread($q)));
        $r->add('GET', "{$p}/messages/{id}", fn (Request $q) => $this->guard($q, fn () => $this->getMessage($q)));
        $r->add('PATCH', "{$p}/messages/{id}", fn (Request $q) => $this->guard($q, fn () => $this->updateMessage($q)));
        $r->add('DELETE', "{$p}/messages/{id}", fn (Request $q) => $this->guard($q, fn () => $this->deleteMessageRoute($q)));
        $r->add('GET', "{$p}/render/{id}", fn (Request $q) => $this->guard($q, fn () => $this->render($q)));
        $r->add('GET', "{$p}/attachments/{id}", fn (Request $q) => $this->guard($q, fn () => $this->downloadAttachment($q)));

        $r->add('POST', "{$p}/send", fn (Request $q) => $this->guard($q, fn () => $this->send($q)));
        $r->add('POST', "{$p}/drafts", fn (Request $q) => $this->guard($q, fn () => $this->saveDraft($q)));
        $r->add('GET', "{$p}/contacts", fn (Request $q) => $this->guard($q, fn () => $this->contacts($q)));
    }

    // =====================================================================
    // Sessão / autenticação
    // =====================================================================

    private function guard(Request $request, callable $fn, bool $needKey = true): Response
    {
        $area = $this->session->area('webmail');
        if ($area === null) {
            throw HttpException::unauthorized();
        }
        if ($request->method !== 'GET' && $request->method !== 'HEAD') {
            $this->session->verifyCsrf($request);
        }
        if ($needKey) {
            $this->loadAccount($request, $area);
        }
        return $fn();
    }

    /** @param array<string,mixed> $area */
    private function loadAccount(Request $request, array $area): void
    {
        $row = $this->db()->one(
            'SELECT a.id, a.email, a.full_name, a.public_key, a.quota_bytes, a.used_bytes
               FROM mail_accounts a JOIN mail_domains d ON d.id = a.domain_id
              WHERE a.id = ? AND a.active AND d.active',
            [(string) $area['account_id']],
        );
        if ($row === null) {
            $this->session->logout('webmail');
            $this->clearKeyCookie();
            throw new HttpException(401, 'account_disabled', 'Conta desativada ou removida');
        }
        $row['public_key'] = ZeroKnowledgeVault::bin($row['public_key'], 32, 'public_key');
        $token = $request->cookies[self::KEY_COOKIE] ?? '';
        try {
            $this->privateKey = $this->vault()->openPrivateKeyFromSession(
                (string) $area['blob'],
                $token,
                $this->binding($area),
            );
        } catch (VaultAuthenticationException) {
            $this->session->logout('webmail');
            $this->clearKeyCookie();
            throw new HttpException(401, 'session_key', 'Sessão expirada. Entre novamente.');
        }
        $this->account = $row;
    }

    /** @param array<string,mixed> $area */
    private function binding(array $area): string
    {
        return 'webmail|' . (string) $area['binding'] . '|' . (string) $area['account_id'];
    }

    private function sessionInfo(): Response
    {
        $area = $this->session->area('webmail');
        $out = ['authenticated' => false, 'csrf' => $this->session->csrfToken()];
        if ($area !== null) {
            $q = $this->db()->one(
                'SELECT a.email, a.full_name, a.quota_bytes, a.used_bytes FROM mail_accounts a
                   JOIN mail_domains d ON d.id = a.domain_id WHERE a.id = ? AND a.active AND d.active',
                [(string) $area['account_id']],
            );
            if ($q !== null) {
                $out = [
                    'authenticated' => true,
                    'email' => $q['email'],
                    'full_name' => $q['full_name'],
                    'quota_bytes' => (int) $q['quota_bytes'],
                    'used_bytes' => (int) $q['used_bytes'],
                    'csrf' => $this->session->csrfToken(),
                ];
            }
        }
        return Response::json($out);
    }

    private function login(Request $request): Response
    {
        $this->session->verifyCsrf($request);
        $email = strtolower((string) $request->string('email', 254));
        $password = (string) $request->string('password', 1024);

        $row = $this->db()->one(
            'SELECT a.id, a.email, a.full_name, a.password_hash, a.kdf_salt, a.public_key, a.encrypted_private_key,
                    a.private_key_nonce
               FROM mail_accounts a JOIN mail_domains d ON d.id = a.domain_id
              WHERE a.email = ? AND a.active AND d.active',
            [$email],
        );
        $log = new SecurityLog($this->config, $this->db());
        if ($row === null) {
            password_verify($password, self::DUMMY_HASH); // tempo constante
            $log->authFailure('webmail', $request->clientIp, $email);
            usleep(random_int(200000, 400000));
            throw new HttpException(401, 'invalid_credentials', 'E-mail ou senha inválidos');
        }
        try {
            $sk = $this->vault()->unlockPrivateKey($password, $row);
        } catch (VaultAuthenticationException) {
            $log->authFailure('webmail', $request->clientIp, $email);
            usleep(random_int(200000, 400000));
            throw new HttpException(401, 'invalid_credentials', 'E-mail ou senha inválidos');
        }

        if (ZeroKnowledgeVault::loginHashNeedsRehash((string) $row['password_hash'])) {
            $this->db()->run('UPDATE mail_accounts SET password_hash = ? WHERE id = ?', [
                ZeroKnowledgeVault::hashLoginPassword($password), $row['id'],
            ]);
        }

        $area = ['account_id' => (string) $row['id'], 'email' => (string) $row['email'], 'binding' => bin2hex(random_bytes(16))];
        try {
            $sealed = $this->vault()->sealPrivateKeyForSession($sk, $this->binding($area));
        } finally {
            sodium_memzero($sk);
        }
        $this->session->login('webmail', $area + ['blob' => $sealed['blob']]);
        $this->setKeyCookie($sealed['token']);
        $log->event('webmail_auth', 'LOGIN_OK', $request->clientIp, 'user=' . $row['email']);

        return Response::json([
            'authenticated' => true,
            'email' => $row['email'],
            'full_name' => $row['full_name'],
            'csrf' => $this->session->csrfToken(),
        ]);
    }

    private function logout(): Response
    {
        $this->session->logout('webmail');
        $this->clearKeyCookie();
        return Response::json(['authenticated' => false, 'csrf' => $this->session->csrfToken()]);
    }

    private function changePassword(Request $request): Response
    {
        $current = (string) $request->string('current_password', 1024);
        $new = (string) $request->string('new_password', 1024);
        $acc = $this->db()->one(
            'SELECT password_hash, kdf_salt, public_key, encrypted_private_key, private_key_nonce FROM mail_accounts WHERE id = ?',
            [$this->accountId()],
        ) ?? throw HttpException::notFound();
        // BYTEA chega como stream (lido uma única vez): materializa antes de usar.
        foreach (['kdf_salt', 'public_key', 'encrypted_private_key', 'private_key_nonce'] as $k) {
            $acc[$k] = ZeroKnowledgeVault::bin($acc[$k], null, $k);
        }
        try {
            $fields = $this->vault()->changePassword($current, $new, $acc);
        } catch (VaultAuthenticationException) {
            (new SecurityLog($this->config, $this->db()))->authFailure('webmail', $request->clientIp, (string) $this->account['email'], 'password_change');
            throw new HttpException(403, 'invalid_password', 'Senha atual incorreta');
        } catch (\InvalidArgumentException $e) {
            throw HttpException::badRequest($e->getMessage(), 'weak_password');
        }
        $this->db()->run(
            'UPDATE mail_accounts SET password_hash = ?, kdf_salt = ?, encrypted_private_key = ?, private_key_nonce = ? WHERE id = ?',
            [$fields['password_hash'], new Binary($fields['kdf_salt']), new Binary($fields['encrypted_private_key']),
                new Binary($fields['private_key_nonce']), $this->accountId()],
        );
        return Response::json(['ok' => true]);
    }

    private function setKeyCookie(string $token): void
    {
        setcookie(self::KEY_COOKIE, $token, [
            'expires' => 0,
            'path' => self::KEY_COOKIE_PATH,
            'secure' => $this->session->isSecure(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    private function clearKeyCookie(): void
    {
        setcookie(self::KEY_COOKIE, '', [
            'expires' => time() - 86400,
            'path' => self::KEY_COOKIE_PATH,
            'secure' => $this->session->isSecure(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    // =====================================================================
    // Pastas e listagem
    // =====================================================================

    private function folders(): Response
    {
        $rows = $this->db()->all(
            "SELECT folder, COUNT(*) AS total, COUNT(*) FILTER (WHERE NOT is_read) AS unread,
                    COUNT(DISTINCT thread_id) AS threads
               FROM messages WHERE account_id = ? GROUP BY folder",
            [$this->accountId()],
        );
        $by = [];
        foreach ($rows as $r) {
            $by[(string) $r['folder']] = $r;
        }
        $out = [];
        foreach (self::FOLDERS as $f) {
            $out[] = [
                'id' => $f,
                'total' => (int) ($by[$f]['total'] ?? 0),
                'unread' => (int) ($by[$f]['unread'] ?? 0),
                'threads' => (int) ($by[$f]['threads'] ?? 0),
            ];
        }
        $starred = $this->db()->one(
            "SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE NOT is_read) AS unread FROM messages
              WHERE account_id = ? AND is_starred AND folder NOT IN ('TRASH','SPAM')",
            [$this->accountId()],
        );
        $out[] = ['id' => 'STARRED', 'total' => (int) ($starred['total'] ?? 0), 'unread' => (int) ($starred['unread'] ?? 0), 'threads' => null];
        $quota = $this->db()->one('SELECT quota_bytes, used_bytes FROM mail_accounts WHERE id = ?', [$this->accountId()]);
        return Response::json([
            'folders' => $out,
            'quota_bytes' => (int) ($quota['quota_bytes'] ?? 0),
            'used_bytes' => (int) ($quota['used_bytes'] ?? 0),
        ]);
    }

    /**
     * GET /messages?folder=INBOX&filter=unread|attachments|starred&q=texto&limit=50&before=ISO8601
     * Lista conversas (threads), com a mensagem mais recente de cada uma.
     */
    private function listThreads(Request $request): Response
    {
        $folder = $this->folderParam($request->queryString('folder', 'INBOX', 16) ?? 'INBOX', true);
        $filter = $request->queryString('filter', null, 16);
        $q = trim((string) $request->queryString('q', '', 200));
        $limit = $request->queryInt('limit', 50, 1, 200);
        $before = $request->queryString('before', null, 40);
        if ($before !== null && strtotime($before) === false) {
            throw HttpException::badRequest('Parâmetro "before" inválido', 'invalid_query');
        }

        [$scopeSql, $scopeParams] = $this->folderScope($folder);
        $having = [];
        if ($filter === 'unread') {
            $having[] = 'bool_or(NOT is_read)';
        } elseif ($filter === 'attachments') {
            $having[] = 'bool_or(has_attachments)';
        } elseif ($filter === 'starred') {
            $having[] = 'bool_or(is_starred)';
        } elseif ($filter !== null) {
            throw HttpException::badRequest('Filtro inválido', 'invalid_query');
        }
        $params = array_merge([$this->accountId()], $scopeParams);

        if ($q !== '') {
            $threadIds = $this->searchThreadIds($scopeSql, $scopeParams, $q, $before, $limit + 1);
            if ($threadIds === []) {
                return Response::json(['threads' => [], 'has_more' => false, 'next_before' => null]);
            }
            $scopeSql .= ' AND thread_id = ANY(?::uuid[])';
            $params[] = '{' . implode(',', $threadIds) . '}';
        }
        if ($before !== null) {
            $having[] = 'max(received_at) < ?::timestamptz';
            $params[] = $before;
        }
        $params[] = $limit + 1;

        $groups = $this->db()->all(
            "SELECT thread_id, max(received_at) AS last_at, COUNT(*) AS cnt, bool_or(NOT is_read) AS unread,
                    bool_or(has_attachments) AS attachments, bool_or(is_starred) AS starred
               FROM messages WHERE account_id = ? AND {$scopeSql}
              GROUP BY thread_id" . ($having !== [] ? ' HAVING ' . implode(' AND ', $having) : '') . '
              ORDER BY last_at DESC LIMIT ?',
            $params,
        );
        $hasMore = count($groups) > $limit;
        $groups = array_slice($groups, 0, $limit);
        if ($groups === []) {
            return Response::json(['threads' => [], 'has_more' => false, 'next_before' => null]);
        }

        $ids = array_map(static fn (array $g): string => (string) $g['thread_id'], $groups);
        $latest = $this->db()->all(
            "SELECT DISTINCT ON (thread_id) thread_id, message_id, received_at, folder, sender_address, recipient_address,
                    encrypted_subject, encrypted_snippet, encrypted_headers, spam_score
               FROM messages WHERE account_id = ? AND {$this->folderScope($folder)[0]} AND thread_id = ANY(?::uuid[])
              ORDER BY thread_id, received_at DESC",
            array_merge([$this->accountId()], $this->folderScope($folder)[1], ['{' . implode(',', $ids) . '}']),
        );
        $byThread = [];
        foreach ($latest as $m) {
            $byThread[(string) $m['thread_id']] = $m;
        }

        $threads = [];
        foreach ($groups as $g) {
            $m = $byThread[(string) $g['thread_id']] ?? null;
            if ($m === null) {
                continue;
            }
            $headers = $this->parseHeaders($this->open($m['encrypted_headers']));
            $from = self::parseAddressList($headers['from'] ?? '')[0] ?? ['name' => '', 'email' => (string) $m['sender_address']];
            $threads[] = [
                'thread_id' => (string) $g['thread_id'],
                'message_id' => (string) $m['message_id'],
                'folder' => (string) $m['folder'],
                'last_at' => self::iso((string) $g['last_at']),
                'count' => (int) $g['cnt'],
                'unread' => self::pgBool($g['unread']),
                'starred' => self::pgBool($g['starred']),
                'has_attachments' => self::pgBool($g['attachments']),
                'subject' => $this->open($m['encrypted_subject']),
                'snippet' => $this->open($m['encrypted_snippet']),
                'from' => $from,
                'to' => self::parseAddressList($headers['to'] ?? (string) $m['recipient_address']),
                'spam_score' => (float) $m['spam_score'],
            ];
        }
        $last = end($groups);
        return Response::json([
            'threads' => $threads,
            'has_more' => $hasMore,
            'next_before' => $hasMore && $last !== false ? self::iso((string) $last['last_at']) : null,
        ]);
    }

    /**
     * Busca sem índice em claro: decifra assunto/snippet/remetente das mensagens
     * mais recentes do escopo e compara no servidor, só durante a requisição.
     *
     * @param list<mixed> $scopeParams
     * @return list<string>
     */
    private function searchThreadIds(string $scopeSql, array $scopeParams, string $q, ?string $before, int $max): array
    {
        $params = array_merge([$this->accountId()], $scopeParams);
        $extra = '';
        if ($before !== null) {
            $extra = ' AND received_at < ?::timestamptz';
            $params[] = $before;
        }
        $params[] = self::SEARCH_SCAN_LIMIT;
        $rows = $this->db()->all(
            "SELECT thread_id, sender_address, recipient_address, encrypted_subject, encrypted_snippet
               FROM messages WHERE account_id = ? AND {$scopeSql}{$extra}
              ORDER BY received_at DESC LIMIT ?",
            $params,
        );
        $needle = mb_strtolower($q, 'UTF-8');
        $found = [];
        foreach ($rows as $r) {
            $tid = (string) $r['thread_id'];
            if (isset($found[$tid])) {
                continue;
            }
            $hay = mb_strtolower(
                $r['sender_address'] . ' ' . $r['recipient_address'] . ' '
                . $this->open($r['encrypted_subject']) . ' ' . $this->open($r['encrypted_snippet']),
                'UTF-8',
            );
            if (str_contains($hay, $needle)) {
                $found[$tid] = true;
                if (count($found) >= $max) {
                    break;
                }
            }
        }
        return array_keys($found);
    }

    // =====================================================================
    // Conversas e mensagens
    // =====================================================================

    /** GET /threads/{id}?folder=INBOX  — mensagens completas, marca como lidas. */
    private function getThread(Request $request): Response
    {
        $threadId = $this->uuidParam($request, 'id');
        $folder = $this->folderParam($request->queryString('folder', 'INBOX', 16) ?? 'INBOX', true);
        [$scopeSql, $scopeParams] = $this->threadScope($folder);
        $rows = $this->db()->all(
            "SELECT * FROM messages WHERE account_id = ? AND thread_id = ? AND {$scopeSql} ORDER BY received_at ASC",
            array_merge([$this->accountId(), $threadId], $scopeParams),
        );
        if ($rows === []) {
            throw HttpException::notFound('Conversa não encontrada');
        }
        $attachments = $this->attachmentsFor(array_map(static fn (array $r): string => (string) $r['message_id'], $rows));
        $messages = array_map(fn (array $r): array => $this->messageView($r, $attachments[(string) $r['message_id']] ?? []), $rows);

        $this->db()->run(
            "UPDATE messages SET is_read = TRUE WHERE account_id = ? AND thread_id = ? AND NOT is_read AND {$scopeSql}",
            array_merge([$this->accountId(), $threadId], $scopeParams),
        );
        return Response::json([
            'thread_id' => $threadId,
            'subject' => $messages[count($messages) - 1]['subject'] ?? '',
            'messages' => $messages,
        ]);
    }

    private function getMessage(Request $request): Response
    {
        $row = $this->messageRow($this->uuidParam($request, 'id'));
        $atts = $this->attachmentsFor([(string) $row['message_id']]);
        if (!self::pgBool($row['is_read'])) {
            $this->db()->run('UPDATE messages SET is_read = TRUE WHERE account_id = ? AND message_id = ?', [$this->accountId(), $row['message_id']]);
        }
        return Response::json($this->messageView($row, $atts[(string) $row['message_id']] ?? []));
    }

    /** PATCH /threads/{id} {folder?, is_read?, is_starred?, from_folder?} */
    private function updateThread(Request $request): Response
    {
        $threadId = $this->uuidParam($request, 'id');
        $from = $this->folderParam((string) ($request->string('from_folder', 16, false) ?? 'INBOX'), true);
        [$scopeSql, $scopeParams] = $this->threadScope($from);
        $updated = $this->applyUpdate($request, "thread_id = ? AND {$scopeSql}", array_merge([$threadId], $scopeParams));
        return Response::json(['updated' => $updated]);
    }

    private function updateMessage(Request $request): Response
    {
        $id = $this->uuidParam($request, 'id');
        $this->messageRow($id);
        return Response::json(['updated' => $this->applyUpdate($request, 'message_id = ?', [$id])]);
    }

    /** @param list<mixed> $whereParams */
    private function applyUpdate(Request $request, string $where, array $whereParams): int
    {
        $set = [];
        $params = [];
        $folder = $request->string('folder', 16, false);
        $isRead = $request->bool('is_read');
        $isStarred = $request->bool('is_starred');
        if ($isRead !== null) {
            $set[] = 'is_read = ?';
            $params[] = $isRead;
        }
        if ($isStarred !== null) {
            $set[] = 'is_starred = ?';
            $params[] = $isStarred;
        }
        if ($folder !== null) {
            $folder = $this->folderParam($folder, false);
            if ($folder === 'DRAFTS' || $folder === 'SENT') {
                throw HttpException::badRequest('Não é possível mover para esta pasta', 'invalid_folder');
            }
            // Restaurar para a Caixa de Entrada devolve as próprias mensagens para "Enviados".
            if ($folder === 'INBOX') {
                $set[] = "folder = CASE WHEN lower(sender_address) = ? THEN 'SENT' ELSE 'INBOX' END";
                $params[] = strtolower((string) $this->account['email']);
            } else {
                $set[] = 'folder = ?';
                $params[] = $folder;
            }
        }
        if ($set === []) {
            throw HttpException::badRequest('Nada para atualizar', 'empty_update');
        }
        // Rascunhos nunca saem de DRAFTS por movimentação (só são enviados ou excluídos).
        $draftGuard = $folder !== null ? " AND folder <> 'DRAFTS'" : '';
        $stmt = $this->db()->run(
            'UPDATE messages SET ' . implode(', ', $set) . " WHERE account_id = ? AND {$where}{$draftGuard}",
            array_merge($params, [$this->accountId()], $whereParams),
        );
        return $stmt->rowCount();
    }

    /** DELETE /threads/{id}?folder=X — move para a Lixeira; na Lixeira/Spam exclui de vez. */
    private function deleteThread(Request $request): Response
    {
        $threadId = $this->uuidParam($request, 'id');
        $folder = $this->folderParam($request->queryString('folder', 'INBOX', 16) ?? 'INBOX', true);
        [$scopeSql, $scopeParams] = $this->threadScope($folder);
        $rows = $this->db()->all(
            "SELECT message_id, folder FROM messages WHERE account_id = ? AND thread_id = ? AND {$scopeSql}",
            array_merge([$this->accountId(), $threadId], $scopeParams),
        );
        if ($rows === []) {
            throw HttpException::notFound('Conversa não encontrada');
        }
        return Response::json($this->trashOrPurge($rows));
    }

    private function deleteMessageRoute(Request $request): Response
    {
        $row = $this->messageRow($this->uuidParam($request, 'id'));
        return Response::json($this->trashOrPurge([$row]));
    }

    /**
     * @param list<array<string,mixed>> $rows
     * @return array{trashed:int,purged:int,used_bytes:int}
     */
    private function trashOrPurge(array $rows): array
    {
        $sender = $this->sender();
        $trashed = 0;
        $purged = 0;
        $this->db()->transaction(function () use ($rows, $sender, &$trashed, &$purged): void {
            foreach ($rows as $r) {
                $f = (string) $r['folder'];
                if (in_array($f, ['TRASH', 'SPAM', 'DRAFTS'], true)) {
                    $purged += $sender->deleteMessage($this->accountId(), (string) $r['message_id']) ? 1 : 0;
                } else {
                    $trashed += $this->db()->run(
                        "UPDATE messages SET folder = 'TRASH' WHERE account_id = ? AND message_id = ?",
                        [$this->accountId(), $r['message_id']],
                    )->rowCount();
                }
            }
        });
        return ['trashed' => $trashed, 'purged' => $purged, 'used_bytes' => $this->usedBytes()];
    }

    /** POST /folders/{folder}/empty — esvazia Lixeira ou Spam. */
    private function emptyFolder(Request $request): Response
    {
        $folder = strtoupper($request->param('folder'));
        if (!in_array($folder, ['TRASH', 'SPAM'], true)) {
            throw HttpException::badRequest('Só é possível esvaziar Lixeira ou Spam', 'invalid_folder');
        }
        $deleted = $this->db()->transaction(function (Database $db) use ($folder): int {
            $acc = $this->accountId();
            $size = (int) $db->scalar('SELECT COALESCE(SUM(size_bytes), 0) FROM messages WHERE account_id = ? AND folder = ?', [$acc, $folder]);
            $db->run(
                'DELETE FROM message_attachments WHERE account_id = ? AND message_id IN (SELECT message_id FROM messages WHERE account_id = ? AND folder = ?)',
                [$acc, $acc, $folder],
            );
            $n = $db->run('DELETE FROM messages WHERE account_id = ? AND folder = ?', [$acc, $folder])->rowCount();
            $db->run('UPDATE mail_accounts SET used_bytes = GREATEST(0, used_bytes - ?) WHERE id = ?', [$size, $acc]);
            return $n;
        });
        return Response::json(['purged' => $deleted, 'used_bytes' => $this->usedBytes()]);
    }

    // =====================================================================
    // Renderização segura de HTML
    // =====================================================================

    /**
     * GET /render/{id}?images=1 — documento HTML sanitizado para um <iframe sandbox>.
     * O CSP desta rota é próprio (o vhost não aplica o CSP global aqui).
     */
    private function render(Request $request): Response
    {
        $row = $this->messageRow($this->uuidParam($request, 'id'));
        $allowRemote = ($request->query['images'] ?? '0') === '1';
        $html = $this->openNullable($row['encrypted_body_html']);
        $blocked = 0;
        if ($html !== null && trim($html) !== '') {
            $inline = $this->inlineImages((string) $row['message_id']);
            $content = self::sanitizeHtml(self::toUtf8($html), $allowRemote, $inline, $blocked);
        } else {
            $plain = (string) ($this->openNullable($row['encrypted_body_plain']) ?? '');
            $content = '<pre class="mp-plain">' . self::linkify(htmlspecialchars(self::toUtf8($plain), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')) . '</pre>';
        }
        $doc = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\">"
            . '<style>html,body{margin:0;padding:0}body{padding:16px;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;'
            . 'color:#1f2328;background:#fff;word-wrap:break-word;overflow-wrap:anywhere}img{max-width:100%;height:auto}'
            . 'pre.mp-plain{white-space:pre-wrap;font:inherit;margin:0}blockquote{margin:0 0 0 .8ex;border-left:2px solid #ccc;padding-left:1ex}'
            . "table{max-width:100%}</style></head><body>{$content}</body></html>";

        $img = $allowRemote ? "'self' data: https: http:" : "'self' data:";
        $csp = "default-src 'none'; img-src {$img}; style-src 'unsafe-inline'; font-src data:; media-src 'none'; "
            . "base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox allow-popups allow-popups-to-escape-sandbox";
        return new Response(200, $doc, [
            'Content-Type' => 'text/html; charset=utf-8',
            'Content-Security-Policy' => $csp,
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'no-referrer',
            'Cache-Control' => 'private, no-store',
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-MP-Blocked-Images' => (string) $blocked,
        ]);
    }

    /**
     * Sanitização por lista de permissões (DOMDocument).
     *
     * @param array<string,string> $inline cid (minúsculo) => data URI
     */
    public static function sanitizeHtml(string $html, bool $allowRemote, array $inline, int &$blocked): string
    {
        $blocked = 0;
        $dom = new \DOMDocument('1.0', 'UTF-8');
        $prev = libxml_use_internal_errors(true);
        $dom->loadHTML('<?xml encoding="utf-8"?><!doctype html><html><body>' . $html . '</body></html>', LIBXML_NONET | LIBXML_COMPACT | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);

        $drop = ['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'link', 'meta', 'base', 'svg',
            'math', 'noscript', 'template', 'audio', 'video', 'source', 'track', 'canvas', 'portal', 'input', 'button',
            'select', 'textarea', 'option', 'title', 'xml', 'param', 'dialog', 'slot'];
        $unwrap = ['form', 'font-face', 'label', 'fieldset', 'legend', 'details', 'summary'];
        $allowedAttrs = ['href', 'src', 'alt', 'title', 'width', 'height', 'style', 'class', 'align', 'valign', 'border',
            'cellpadding', 'cellspacing', 'colspan', 'rowspan', 'bgcolor', 'color', 'face', 'size', 'dir', 'lang', 'name',
            'id', 'start', 'type', 'span', 'scope', 'headers', 'abbr', 'nowrap', 'hspace', 'vspace', 'background', 'cite',
            'datetime', 'reversed', 'value'];

        $xpath = new \DOMXPath($dom);
        /** @var list<\DOMElement> $elements */
        $elements = iterator_to_array($xpath->query('//*') ?: [], false);
        foreach ($elements as $el) {
            if ($el->parentNode === null) {
                continue;
            }
            $tag = strtolower($el->tagName);
            if (in_array($tag, $drop, true) || str_contains($tag, ':')) {
                $el->parentNode->removeChild($el);
                continue;
            }
            if (in_array($tag, ['html', 'head', 'body'], true)) {
                foreach (iterator_to_array($el->attributes ?? [], false) as $attr) {
                    $el->removeAttribute($attr->name);
                }
                continue;
            }
            if ($tag === 'style') {
                // CSS permitido (o CSP bloqueia url() remotos); remove @import e comportamentos legados.
                $css = (string) preg_replace('/@import[^;]*;?|expression\s*\(|behavior\s*:|-moz-binding/i', '', $el->textContent);
                $el->textContent = $css;
                continue;
            }
            foreach (iterator_to_array($el->attributes ?? [], false) as $attr) {
                /** @var \DOMAttr $attr */
                $name = strtolower($attr->name);
                $value = trim($attr->value);
                if (!in_array($name, $allowedAttrs, true)) {
                    $el->removeAttribute($attr->name);
                    continue;
                }
                if ($name === 'style' && preg_match('/expression\s*\(|behavior\s*:|-moz-binding|javascript:/i', $value)) {
                    $el->removeAttribute($attr->name);
                    continue;
                }
                if ($name === 'href' || $name === 'cite') {
                    if (!preg_match('#^(https?:|mailto:|tel:|\#)#i', $value)) {
                        $el->removeAttribute($attr->name);
                    }
                    continue;
                }
                if ($name === 'src' || $name === 'background') {
                    $lower = strtolower($value);
                    if (str_starts_with($lower, 'cid:')) {
                        $cid = trim(rawurldecode(substr($value, 4)), '<> ');
                        $data = $inline[strtolower($cid)] ?? null;
                        if ($data !== null) {
                            $el->setAttribute($attr->name, $data);
                        } else {
                            $el->removeAttribute($attr->name);
                        }
                    } elseif (preg_match('#^data:image/(png|jpe?g|gif|webp|bmp);base64,#i', $value)) {
                        // ok
                    } elseif (preg_match('#^https?://#i', $value)) {
                        if (!$allowRemote) {
                            $el->removeAttribute($attr->name);
                            $el->setAttribute('data-mp-blocked', '1');
                            $blocked++;
                        }
                    } else {
                        $el->removeAttribute($attr->name);
                    }
                }
            }
            if ($tag === 'a' && $el->hasAttribute('href') && !str_starts_with($el->getAttribute('href'), '#')) {
                $el->setAttribute('target', '_blank');
                $el->setAttribute('rel', 'noopener noreferrer nofollow');
            }
            if (in_array($tag, $unwrap, true)) {
                while ($el->firstChild !== null) {
                    $el->parentNode->insertBefore($el->firstChild, $el);
                }
                $el->parentNode->removeChild($el);
            }
        }
        // Comentários condicionais/processing instructions
        foreach (iterator_to_array($xpath->query('//comment() | //processing-instruction()') ?: [], false) as $node) {
            $node->parentNode?->removeChild($node);
        }

        // Saída: folhas de estilo (de <head> ou <body>) + conteúdo do <body>.
        $out = '';
        foreach (iterator_to_array($dom->getElementsByTagName('style'), false) as $style) {
            $out .= (string) $dom->saveHTML($style);
            $style->parentNode?->removeChild($style);
        }
        $body = $dom->getElementsByTagName('body')->item(0);
        if ($body !== null) {
            foreach ($body->childNodes as $child) {
                $out .= (string) $dom->saveHTML($child);
            }
        }
        return $out;
    }

    /** @return array<string,string> cid => data URI (apenas imagens rasterizadas) */
    private function inlineImages(string $messageId): array
    {
        $rows = $this->db()->all(
            'SELECT encrypted_filename, encrypted_mime_type, encrypted_content, size_bytes FROM message_attachments
              WHERE account_id = ? AND message_id = ? ORDER BY size_bytes ASC',
            [$this->accountId(), $messageId],
        );
        $out = [];
        $total = 0;
        foreach ($rows as $r) {
            $meta = ZeroKnowledgeVault::decodeAttachmentMeta($this->open($r['encrypted_filename']));
            if ($meta['cid'] === null) {
                continue;
            }
            $mime = strtolower($this->open($r['encrypted_mime_type']));
            $size = (int) $r['size_bytes'];
            if (!preg_match('#^image/(png|jpe?g|gif|webp|bmp)$#', $mime) || $size > self::MAX_INLINE_DATA_URI_BYTES
                || $total + $size > self::MAX_INLINE_TOTAL_BYTES) {
                continue;
            }
            $total += $size;
            $out[strtolower(trim($meta['cid'], '<> '))] = 'data:' . $mime . ';base64,' . base64_encode($this->open($r['encrypted_content']));
        }
        return $out;
    }

    private static function linkify(string $escaped): string
    {
        return (string) preg_replace_callback(
            '#\bhttps?://[^\s<>"\']+#i',
            static function (array $m): string {
                $url = rtrim($m[0], '.,;:!?)');
                $tail = substr($m[0], strlen($url));
                return '<a href="' . $url . '" target="_blank" rel="noopener noreferrer nofollow">' . $url . '</a>' . $tail;
            },
            $escaped,
        );
    }

    // =====================================================================
    // Anexos
    // =====================================================================

    private function downloadAttachment(Request $request): Response
    {
        $id = $this->uuidParam($request, 'id');
        $row = $this->db()->one(
            'SELECT encrypted_filename, encrypted_mime_type, encrypted_content FROM message_attachments
              WHERE account_id = ? AND attachment_id = ? LIMIT 1',
            [$this->accountId(), $id],
        ) ?? throw HttpException::notFound('Anexo não encontrado');
        $meta = ZeroKnowledgeVault::decodeAttachmentMeta($this->open($row['encrypted_filename']));
        $mime = $this->open($row['encrypted_mime_type']);
        $content = $this->open($row['encrypted_content']);
        return Response::download($content, $meta['name'], $mime, ($request->query['inline'] ?? '0') === '1');
    }

    /**
     * @param list<string> $messageIds
     * @return array<string,list<array{id:string,name:string,mime:string,size:int,inline:bool,cid:?string}>>
     */
    private function attachmentsFor(array $messageIds): array
    {
        if ($messageIds === []) {
            return [];
        }
        $rows = $this->db()->all(
            'SELECT attachment_id, message_id, encrypted_filename, encrypted_mime_type, size_bytes FROM message_attachments
              WHERE account_id = ? AND message_id = ANY(?::uuid[]) ORDER BY received_at, attachment_id',
            [$this->accountId(), '{' . implode(',', $messageIds) . '}'],
        );
        $out = [];
        foreach ($rows as $r) {
            $meta = ZeroKnowledgeVault::decodeAttachmentMeta($this->open($r['encrypted_filename']));
            $out[(string) $r['message_id']][] = [
                'id' => (string) $r['attachment_id'],
                'name' => $meta['name'],
                'mime' => $this->open($r['encrypted_mime_type']),
                'size' => (int) $r['size_bytes'],
                'inline' => $meta['inline'],
                'cid' => $meta['cid'],
            ];
        }
        return $out;
    }

    // =====================================================================
    // Envio e rascunhos
    // =====================================================================

    /**
     * POST /send — JSON {to, cc, bcc, subject, body_plain, body_html, reply_to, forward_of, draft_id,
     * attachments:[{name,mime,content_b64}]} ou multipart com attachments[] (arquivos).
     */
    private function send(Request $request): Response
    {
        $msg = $this->composeFromRequest($request, true);
        $draftId = $this->optionalUuid($request, 'draft_id');
        $result = $this->sender()->send($this->accountForSender(), $msg);
        if ($draftId !== null) {
            $this->sender()->deleteMessage($this->accountId(), $draftId, 'DRAFTS');
        }
        return Response::json($result + ['used_bytes' => $this->usedBytes()]);
    }

    private function saveDraft(Request $request): Response
    {
        $msg = $this->composeFromRequest($request, false);
        $draftId = $this->optionalUuid($request, 'draft_id');
        $result = $this->sender()->saveDraft($this->accountForSender(), $msg, $draftId);
        return Response::json($result + ['used_bytes' => $this->usedBytes()]);
    }

    /** @return array<string,mixed> */
    private function composeFromRequest(Request $request, bool $sending): array
    {
        $subject = (string) ($request->string('subject', 998, false) ?? '');
        $bodyPlain = $this->rawText($request, 'body_plain');
        $bodyHtml = $this->rawText($request, 'body_html');
        if ($bodyHtml !== null && trim($bodyHtml) === '') {
            $bodyHtml = null;
        }
        if (($bodyPlain === null || trim($bodyPlain) === '') && $bodyHtml !== null) {
            $bodyPlain = self::htmlToPlain($bodyHtml);
        }
        $msg = [
            'to' => $this->addressInput($request, 'to', $sending),
            'cc' => $this->addressInput($request, 'cc', $sending),
            'bcc' => $this->addressInput($request, 'bcc', $sending),
            'subject' => $subject,
            'body_plain' => (string) ($bodyPlain ?? ''),
            'body_html' => $bodyHtml,
            'attachments' => $this->attachmentsInput($request),
            'reply' => null,
        ];

        $replyTo = $this->optionalUuid($request, 'reply_to');
        if ($replyTo !== null) {
            $orig = $this->messageRow($replyTo);
            $h = $this->parseHeaders($this->open($orig['encrypted_headers']));
            $mid = trim((string) ($h['message-id'] ?? ''));
            $refs = trim((string) ($h['references'] ?? ($h['in-reply-to'] ?? '')));
            $msg['reply'] = [
                'message_id_header' => preg_match('/^<[^<>\s]+>$/', $mid) ? $mid : null,
                'references' => $refs, // o MailSender acrescenta o Message-ID do original
                'thread_id' => (string) $orig['thread_id'],
            ];
        }

        $forwardOf = $this->optionalUuid($request, 'forward_of');
        if ($forwardOf !== null) {
            $this->messageRow($forwardOf);
            $keep = $request->input('forward_attachment_ids');
            $keep = is_array($keep) ? array_values(array_filter($keep, static fn ($v) => is_string($v) && preg_match(self::UUID_RE, $v))) : null;
            $rows = $this->db()->all(
                'SELECT attachment_id, encrypted_filename, encrypted_mime_type, encrypted_content FROM message_attachments
                  WHERE account_id = ? AND message_id = ?',
                [$this->accountId(), $forwardOf],
            );
            foreach ($rows as $r) {
                if ($keep !== null && !in_array((string) $r['attachment_id'], $keep, true)) {
                    continue;
                }
                $meta = ZeroKnowledgeVault::decodeAttachmentMeta($this->open($r['encrypted_filename']));
                $msg['attachments'][] = [
                    'name' => $meta['name'],
                    'mime' => $this->open($r['encrypted_mime_type']),
                    'content' => $this->open($r['encrypted_content']),
                ];
            }
        }

        $total = array_sum(array_map(static fn (array $a): int => strlen($a['content']), $msg['attachments']));
        if ($total > MailSender::MAX_MESSAGE_BYTES) {
            throw HttpException::badRequest('Anexos maiores que 50 MiB', 'too_large');
        }
        if ($sending && $msg['to'] === [] && $msg['cc'] === [] && $msg['bcc'] === []) {
            throw HttpException::badRequest('Informe ao menos um destinatário', 'no_recipients');
        }
        return $msg;
    }

    private function rawText(Request $request, string $key): ?string
    {
        $v = $request->input($key);
        if ($v === null) {
            return null;
        }
        if (!is_string($v) || !mb_check_encoding($v, 'UTF-8') || strlen($v) > 20971520) {
            throw HttpException::badRequest("Campo inválido: {$key}", 'invalid_field');
        }
        return str_replace("\0", '', $v);
    }

    /** @return list<string> */
    private function addressInput(Request $request, string $key, bool $strict = true): array
    {
        $v = $request->input($key, []);
        if (is_string($v)) {
            $v = [$v];
        }
        if (!is_array($v)) {
            throw HttpException::badRequest("Campo inválido: {$key}", 'invalid_field');
        }
        $out = [];
        foreach ($v as $item) {
            if (!is_string($item)) {
                throw HttpException::badRequest("Campo inválido: {$key}", 'invalid_field');
            }
            foreach (self::splitAddressTokens($item) as $token) {
                $a = self::parseAddress($token);
                if ($a === null) {
                    if ($strict) {
                        throw HttpException::badRequest('Endereço inválido: ' . mb_substr($token, 0, 100), 'invalid_recipient');
                    }
                    continue; // rascunho: endereço incompleto é descartado
                }
                $out[] = $a['email'];
            }
        }
        return array_values(array_unique($out));
    }

    /** @return list<array{name:string,mime:string,content:string}> */
    private function attachmentsInput(Request $request): array
    {
        $out = [];
        // multipart/form-data: attachments[]
        $files = $request->files['attachments'] ?? null;
        if (is_array($files) && isset($files['tmp_name'])) {
            $names = (array) $files['name'];
            foreach ((array) $files['tmp_name'] as $i => $tmp) {
                $err = (int) (((array) $files['error'])[$i] ?? UPLOAD_ERR_NO_FILE);
                if ($err === UPLOAD_ERR_NO_FILE) {
                    continue;
                }
                if ($err !== UPLOAD_ERR_OK || !is_uploaded_file((string) $tmp)) {
                    throw HttpException::badRequest('Falha no upload do anexo', 'upload_failed');
                }
                $content = (string) file_get_contents((string) $tmp);
                $out[] = [
                    'name' => self::safeFilename((string) ($names[$i] ?? 'anexo')),
                    'mime' => self::detectMime($content, (string) (((array) $files['type'])[$i] ?? '')),
                    'content' => $content,
                ];
            }
        }
        // JSON: [{name, mime, content_b64}]
        $json = $request->isJson() ? $request->input('attachments', []) : [];
        if (is_array($json)) {
            foreach ($json as $a) {
                if (!is_array($a) || !is_string($a['content_b64'] ?? null)) {
                    throw HttpException::badRequest('Anexo inválido', 'invalid_attachment');
                }
                $content = base64_decode($a['content_b64'], true);
                if ($content === false) {
                    throw HttpException::badRequest('Anexo com base64 inválido', 'invalid_attachment');
                }
                $out[] = [
                    'name' => self::safeFilename((string) ($a['name'] ?? 'anexo')),
                    'mime' => self::detectMime($content, (string) ($a['mime'] ?? '')),
                    'content' => $content,
                ];
            }
        }
        if (count($out) > 50) {
            throw HttpException::badRequest('Anexos demais (máx. 50)', 'too_many_attachments');
        }
        return $out;
    }

    private static function safeFilename(string $name): string
    {
        $name = basename(str_replace('\\', '/', $name));
        $name = (string) preg_replace('/[\x00-\x1f\x7f"]+/u', '', $name);
        if (!mb_check_encoding($name, 'UTF-8')) {
            $name = (string) mb_convert_encoding($name, 'UTF-8', 'ISO-8859-1');
        }
        $name = mb_substr(trim($name), 0, 200);
        return $name !== '' && $name !== '.' && $name !== '..' ? $name : 'anexo';
    }

    private static function detectMime(string $content, string $declared): string
    {
        $declared = strtolower(trim($declared));
        if (preg_match('#^[a-z0-9][a-z0-9!\#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!\#$&^_.+-]{0,126}$#', $declared)
            && $declared !== 'application/octet-stream') {
            return $declared;
        }
        if (class_exists(\finfo::class)) {
            $m = (new \finfo(FILEINFO_MIME_TYPE))->buffer($content);
            if (is_string($m) && $m !== '') {
                return $m;
            }
        }
        return 'application/octet-stream';
    }

    private static function htmlToPlain(string $html): string
    {
        $html = (string) preg_replace('#<(script|style)\b[^>]*>.*?</\1>#is', '', $html);
        $html = (string) preg_replace('#<br\s*/?>#i', "\n", $html);
        $html = (string) preg_replace('#</(p|div|li|tr|h[1-6]|blockquote)>#i', "\n", $html);
        $text = html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = (string) preg_replace("/[ \t]+/u", ' ', $text);
        return trim((string) preg_replace("/\n{3,}/", "\n\n", $text));
    }

    /** GET /contacts?q= — endereços já usados em Enviados (sugestões do campo Para). */
    private function contacts(Request $request): Response
    {
        $q = mb_strtolower(trim((string) $request->queryString('q', '', 100)), 'UTF-8');
        $rows = $this->db()->all(
            "SELECT recipient_address, COUNT(*) AS n FROM messages WHERE account_id = ? AND folder = 'SENT'
              GROUP BY recipient_address ORDER BY n DESC LIMIT 500",
            [$this->accountId()],
        );
        $score = [];
        foreach ($rows as $r) {
            foreach (preg_split('/\s*,\s*/', (string) $r['recipient_address']) ?: [] as $addr) {
                $addr = strtolower(trim($addr));
                if ($addr === '' || !filter_var($addr, FILTER_VALIDATE_EMAIL) || ($q !== '' && !str_contains($addr, $q))) {
                    continue;
                }
                $score[$addr] = ($score[$addr] ?? 0) + (int) $r['n'];
            }
        }
        arsort($score);
        return Response::json(['contacts' => array_slice(array_keys($score), 0, 20)]);
    }

    // =====================================================================
    // Auxiliares
    // =====================================================================

    /**
     * @param array<string,mixed> $r
     * @param list<array<string,mixed>> $attachments
     * @return array<string,mixed>
     */
    private function messageView(array $r, array $attachments): array
    {
        $rawHeaders = $this->open($r['encrypted_headers']);
        $h = $this->parseHeaders($rawHeaders);
        $html = $this->openNullable($r['encrypted_body_html']);
        $plain = $this->openNullable($r['encrypted_body_plain']);
        $folder = (string) $r['folder'];
        $view = [
            'message_id' => (string) $r['message_id'],
            'thread_id' => (string) $r['thread_id'],
            'folder' => $folder,
            'received_at' => self::iso((string) $r['received_at']),
            'subject' => $this->open($r['encrypted_subject']),
            'snippet' => $this->open($r['encrypted_snippet']),
            'from' => self::parseAddressList($h['from'] ?? '')[0] ?? ['name' => '', 'email' => (string) $r['sender_address']],
            'reply_to' => self::parseAddressList($h['reply-to'] ?? ''),
            'to' => self::parseAddressList($h['to'] ?? ''),
            'cc' => self::parseAddressList($h['cc'] ?? ''),
            'bcc' => in_array($folder, ['SENT', 'DRAFTS'], true) ? self::parseAddressList($h['bcc'] ?? '') : [],
            'date' => isset($h['date']) && strtotime($h['date']) !== false ? gmdate('c', (int) strtotime($h['date'])) : null,
            'rfc_message_id' => $h['message-id'] ?? null,
            'body_plain' => $plain !== null ? self::toUtf8($plain) : null,
            'has_html' => $html !== null && trim($html) !== '',
            'is_read' => self::pgBool($r['is_read']),
            'is_starred' => self::pgBool($r['is_starred']),
            'auth' => [
                'spf' => self::pgBool($r['spf_pass']),
                'dkim' => self::pgBool($r['dkim_pass']),
                'dmarc' => self::pgBool($r['dmarc_pass']),
                'spam_score' => (float) $r['spam_score'],
            ],
            'size' => (int) $r['size_bytes'],
            'attachments' => array_values(array_filter($attachments, static fn (array $a): bool => !($a['inline'] && $a['cid'] !== null && str_starts_with((string) $a['mime'], 'image/')))),
            'inline_count' => count(array_filter($attachments, static fn (array $a): bool => $a['inline'] && $a['cid'] !== null)),
            'raw_headers' => self::toUtf8($rawHeaders),
        ];
        // Rascunhos reabrem no editor: HTML já sanitizado (sem imagens remotas bloqueadas).
        if ($folder === 'DRAFTS' && $view['has_html']) {
            $blocked = 0;
            $view['draft_html'] = self::sanitizeHtml(self::toUtf8((string) $html), true, [], $blocked);
        }
        return $view;
    }

    /** @return array<string,mixed> */
    private function messageRow(string $messageId): array
    {
        return $this->db()->one(
            'SELECT * FROM messages WHERE account_id = ? AND message_id = ? LIMIT 1',
            [$this->accountId(), $messageId],
        ) ?? throw HttpException::notFound('Mensagem não encontrada');
    }

    /**
     * Escopo de listagem de uma pasta (STARRED é virtual).
     *
     * @return array{0:string,1:list<mixed>}
     */
    private function folderScope(string $folder): array
    {
        if ($folder === 'STARRED') {
            return ["is_starred AND folder NOT IN ('TRASH','SPAM')", []];
        }
        return ['folder = ?', [$folder]];
    }

    /**
     * Escopo de uma conversa aberta a partir de uma pasta: na Lixeira/Spam só
     * as mensagens daquela pasta; nas demais, toda a conversa fora de Lixeira/Spam.
     *
     * @return array{0:string,1:list<mixed>}
     */
    private function threadScope(string $folder): array
    {
        if ($folder === 'TRASH' || $folder === 'SPAM') {
            return ['folder = ?', [$folder]];
        }
        return ["folder NOT IN ('TRASH','SPAM')", []];
    }

    private function folderParam(string $folder, bool $allowVirtual): string
    {
        $folder = strtoupper(trim($folder));
        if (in_array($folder, self::FOLDERS, true) || ($allowVirtual && in_array($folder, self::VIRTUAL_FOLDERS, true))) {
            return $folder;
        }
        throw HttpException::badRequest('Pasta inválida', 'invalid_folder');
    }

    private function uuidParam(Request $request, string $name): string
    {
        $v = strtolower($request->param($name));
        if (!preg_match(self::UUID_RE, $v)) {
            throw HttpException::notFound();
        }
        return $v;
    }

    private function optionalUuid(Request $request, string $key): ?string
    {
        $v = $request->input($key);
        if ($v === null || $v === '') {
            return null;
        }
        if (!is_string($v) || !preg_match(self::UUID_RE, strtolower($v))) {
            throw HttpException::badRequest("Identificador inválido: {$key}", 'invalid_field');
        }
        return strtolower($v);
    }

    /**
     * Cabeçalhos decodificados (RFC 2047), chaves em minúsculo, último valor vence
     * exceto para os que se acumulam.
     *
     * @return array<string,string>
     */
    private function parseHeaders(string $raw): array
    {
        $raw = str_replace(["\r\n", "\r"], "\n", $raw);
        $raw = (string) preg_replace("/\n[ \t]+/", ' ', $raw); // desdobra linhas continuadas
        $out = [];
        foreach (explode("\n", $raw) as $line) {
            $pos = strpos($line, ':');
            if ($pos === false || $pos === 0) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $pos)));
            if (!preg_match('/^[a-z0-9-]+$/', $name)) {
                continue;
            }
            $value = trim(substr($line, $pos + 1));
            $decoded = @iconv_mime_decode($value, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
            $value = self::toUtf8($decoded !== false ? $decoded : $value);
            if (in_array($name, ['to', 'cc', 'bcc', 'references'], true) && isset($out[$name])) {
                $out[$name] .= ($name === 'references' ? ' ' : ', ') . $value;
            } elseif (!isset($out[$name])) {
                $out[$name] = $value; // primeiro valor (cabeçalhos adicionados por relays vêm depois)
            }
        }
        return $out;
    }

    /**
     * "Nome" <a@b>, c@d, Outro <e@f>  =>  [{name,email}]
     *
     * @return list<array{name:string,email:string}>
     */
    public static function parseAddressList(string $value): array
    {
        $out = [];
        foreach (self::splitAddressTokens($value) as $p) {
            $a = self::parseAddress($p);
            if ($a !== null) {
                $out[] = $a;
            }
        }
        return $out;
    }

    /** @return list<string> tokens não vazios, respeitando aspas e <...> */
    private static function splitAddressTokens(string $value): array
    {
        $parts = [];
        $buf = '';
        $quoted = false;
        $angle = 0;
        $len = strlen($value);
        for ($i = 0; $i < $len; $i++) {
            $c = $value[$i];
            if ($c === '\\' && $quoted && $i + 1 < $len) {
                $buf .= $c . $value[++$i];
                continue;
            }
            if ($c === '"') {
                $quoted = !$quoted;
            } elseif (!$quoted && $c === '<') {
                $angle++;
            } elseif (!$quoted && $c === '>') {
                $angle = max(0, $angle - 1);
            } elseif (!$quoted && $angle === 0 && ($c === ',' || $c === ';')) {
                $parts[] = $buf;
                $buf = '';
                continue;
            }
            $buf .= $c;
        }
        $parts[] = $buf;
        return array_values(array_filter(array_map('trim', $parts), static fn (string $p): bool => $p !== ''));
    }

    /** @return array{name:string,email:string}|null */
    private static function parseAddress(string $p): ?array
    {
        if (preg_match('/^(.*)<([^<>]+)>\s*$/s', $p, $m)) {
            $name = trim(trim($m[1]), '"');
            $email = trim($m[2]);
        } else {
            $name = '';
            $email = trim($p, '<> ');
        }
        $email = strtolower($email);
        if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return null;
        }
        return ['name' => mb_substr(stripcslashes($name), 0, 200), 'email' => $email];
    }

    private static function toUtf8(string $s): string
    {
        if (mb_check_encoding($s, 'UTF-8')) {
            return $s;
        }
        return (string) mb_convert_encoding($s, 'UTF-8', 'Windows-1252');
    }

    private static function iso(string $ts): string
    {
        $t = strtotime($ts);
        return $t === false ? $ts : (new \DateTimeImmutable($ts))->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.uP');
    }

    private static function pgBool(mixed $v): bool
    {
        return $v === true || $v === 't' || $v === 1 || $v === '1' || $v === 'true';
    }

    private function open(mixed $sealed): string
    {
        return ZeroKnowledgeVault::open(
            ZeroKnowledgeVault::bin($sealed, null, 'sealed'),
            (string) $this->account['public_key'],
            (string) $this->privateKey,
        );
    }

    private function openNullable(mixed $sealed): ?string
    {
        return $sealed === null ? null : $this->open($sealed);
    }

    private function accountId(): string
    {
        return (string) ($this->account['id'] ?? throw HttpException::unauthorized());
    }

    /** @return array{id:string,email:string,full_name:string,public_key:string} */
    private function accountForSender(): array
    {
        return [
            'id' => $this->accountId(),
            'email' => (string) $this->account['email'],
            'full_name' => (string) $this->account['full_name'],
            'public_key' => (string) $this->account['public_key'],
        ];
    }

    private function usedBytes(): int
    {
        return (int) $this->db()->scalar('SELECT used_bytes FROM mail_accounts WHERE id = ?', [$this->accountId()]);
    }

    private function db(): Database
    {
        return $this->db ??= Database::get($this->config);
    }

    private function vault(): ZeroKnowledgeVault
    {
        return $this->vault ??= new ZeroKnowledgeVault(
            $this->config->get('MP_APP_MASTER_KEY'),
            $this->config->require('MP_SUBJECT_HMAC_KEY'),
        );
    }

    private function sender(): MailSender
    {
        return new MailSender(
            $this->db(),
            $this->vault(),
            (string) ($this->config->get('MP_HOSTNAME', 'localhost') ?? 'localhost'),
            (string) ($this->config->get('MP_SMTP_HOST', '127.0.0.1') ?? '127.0.0.1'),
            $this->config->int('MP_SMTP_PORT', 587),
        );
    }
}
