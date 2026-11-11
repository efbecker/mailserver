<?php

declare(strict_types=1);

namespace MailPlatform\Crypto;

use InvalidArgumentException;
use Normalizer;
use RuntimeException;

/**
 * Mail Platform :: ZeroKnowledgeVault
 *
 * Motor criptográfico da plataforma (Libsodium / ext-sodium do PHP 8.4).
 *
 *  - Conta:     Argon2id (crypto_pwhash, OPSLIMIT/MEMLIMIT_MODERATE) deriva uma
 *               Master Key de 256 bits a partir da senha + kdf_salt (16 bytes).
 *               A chave privada X25519 da conta é cifrada com
 *               XChaCha20-Poly1305-IETF usando essa Master Key (nonce de 24 bytes).
 *               A senha de login é guardada separadamente em password_hash()
 *               Argon2id.
 *  - Mensagens: crypto_box_seal (X25519 + XSalsa20-Poly1305) com a public_key do
 *               destinatário. Compatível byte a byte com PyNaCl SealedBox usado
 *               por bin/mail-ingest.py.
 *  - Sessão:    a chave privada aberta no login nunca fica em claro no
 *               armazenamento da sessão: é cifrada com uma chave efêmera de
 *               sessão que só existe num cookie HttpOnly do navegador.
 *  - Índice:    subject_hash = HMAC-SHA256 "blind index" por conta, para agrupar
 *               threads sem revelar o assunto.
 *  - Servidor:  segredos operacionais (chaves SSH dos nós, chaves privadas DKIM)
 *               cifrados com MP_APP_MASTER_KEY (XChaCha20-Poly1305 + contexto AAD).
 *
 * Formato de todo ciphertext gravado no banco: 1 byte de versão + payload.
 *   0x01 || crypto_box_seal(plaintext, public_key)                  (mensagens)
 *   0x01 || nonce(24) || xchacha20poly1305(plaintext, aad, key)     (segredos)
 * O mesmo formato é implementado em Python por bin/mail-ingest.py.
 */
final class ZeroKnowledgeVault
{
    public const FORMAT_VERSION = "\x01";

    public const KDF_SALT_BYTES = SODIUM_CRYPTO_PWHASH_SALTBYTES;            // 16
    public const MASTER_KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES; // 32
    public const AEAD_NONCE_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24
    public const X25519_KEY_BYTES = SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;        // 32
    public const SEAL_OVERHEAD = SODIUM_CRYPTO_BOX_SEALBYTES;                // 48

    /** Tamanho do snippet (preview) em caracteres. */
    public const SNIPPET_CHARS = 120;

    private const AAD_PRIVATE_KEY = 'mail-platform/private-key/v1|';
    private const AAD_SESSION = 'mail-platform/session/v1|';
    private const AAD_SERVER_SECRET = 'mail-platform/server-secret/v1|';
    private const SUBJECT_INDEX_LABEL = 'mp-subject-v1|';

    private const SUBJECT_PREFIX_RE = '/^(?:re|res|fw|fwd|enc|aw|sv|antw|tr)\s*(?:\[\d+\])?\s*:\s*/iu';

    private ?string $appMasterKey;
    private ?string $subjectHmacKey;
    private int $opsLimit;
    private int $memLimit;

    /**
     * @param string|null $appMasterKeyB64   MP_APP_MASTER_KEY (base64, 32 bytes)
     * @param string|null $subjectHmacKeyB64 MP_SUBJECT_HMAC_KEY (base64, 32 bytes)
     * @param int|null    $opsLimit          Sobrescreve OPSLIMIT_MODERATE (apenas testes)
     * @param int|null    $memLimit          Sobrescreve MEMLIMIT_MODERATE (apenas testes)
     */
    public function __construct(
        ?string $appMasterKeyB64 = null,
        ?string $subjectHmacKeyB64 = null,
        ?int $opsLimit = null,
        ?int $memLimit = null,
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('ext-sodium é obrigatória');
        }
        $this->appMasterKey = $appMasterKeyB64 !== null ? self::decodeKey($appMasterKeyB64, 'MP_APP_MASTER_KEY') : null;
        $this->subjectHmacKey = $subjectHmacKeyB64 !== null ? self::decodeKey($subjectHmacKeyB64, 'MP_SUBJECT_HMAC_KEY') : null;
        $this->opsLimit = $opsLimit ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
        $this->memLimit = $memLimit ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
    }

    public function __destruct()
    {
        if ($this->appMasterKey !== null) {
            sodium_memzero($this->appMasterKey);
        }
        if ($this->subjectHmacKey !== null) {
            sodium_memzero($this->subjectHmacKey);
        }
    }

    // =====================================================================
    // 1. Criação de conta e chaves
    // =====================================================================

    /**
     * Gera todo o material criptográfico de uma nova conta.
     *
     * @return array{password_hash:string,kdf_salt:string,public_key:string,encrypted_private_key:string,private_key_nonce:string}
     *         Valores binários (bytea) prontos para INSERT em mail_accounts.
     */
    public function createAccountKeys(string $password): array
    {
        self::assertPassword($password);

        $salt = random_bytes(self::KDF_SALT_BYTES);
        $masterKey = $this->deriveMasterKey($password, $salt);

        $keypair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keypair);
        $privateKey = sodium_crypto_box_secretkey($keypair);
        sodium_memzero($keypair);

        [$encrypted, $nonce] = $this->wrapPrivateKey($privateKey, $publicKey, $masterKey);
        sodium_memzero($privateKey);
        sodium_memzero($masterKey);

        return [
            'password_hash' => self::hashLoginPassword($password),
            'kdf_salt' => $salt,
            'public_key' => $publicKey,
            'encrypted_private_key' => $encrypted,
            'private_key_nonce' => $nonce,
        ];
    }

    /** Hash de login (Argon2id) — independente da chave de cifragem. */
    public static function hashLoginPassword(string $password): string
    {
        self::assertPassword($password);
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,  // 64 MiB
            'time_cost' => 4,
            'threads' => 1,
        ]);
    }

    /**
     * Valida a senha de login e devolve a chave privada X25519 em claro
     * (32 bytes). O chamador DEVE chamar sodium_memzero() após o uso, ou
     * guardá-la apenas via sealPrivateKeyForSession().
     *
     * @param array{password_hash:string,kdf_salt:string,public_key:string,encrypted_private_key:string,private_key_nonce:string} $account
     * @throws VaultAuthenticationException senha incorreta ou chave adulterada
     */
    public function unlockPrivateKey(string $password, array $account): string
    {
        if (!password_verify($password, (string) $account['password_hash'])) {
            throw new VaultAuthenticationException('Credenciais inválidas');
        }
        $masterKey = $this->deriveMasterKey($password, self::bin($account['kdf_salt'], self::KDF_SALT_BYTES, 'kdf_salt'));
        try {
            return $this->unwrapPrivateKey(
                self::bin($account['encrypted_private_key'], null, 'encrypted_private_key'),
                self::bin($account['private_key_nonce'], self::AEAD_NONCE_BYTES, 'private_key_nonce'),
                self::bin($account['public_key'], self::X25519_KEY_BYTES, 'public_key'),
                $masterKey,
            );
        } finally {
            sodium_memzero($masterKey);
        }
    }

    /** Indica se o hash de login deve ser recalculado (parâmetros mudaram). */
    public static function loginHashNeedsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);
    }

    /**
     * Troca de senha: re-cifra a MESMA chave privada com nova Master Key.
     * Mensagens existentes continuam legíveis (a public_key não muda).
     *
     * @param array{password_hash:string,kdf_salt:string,public_key:string,encrypted_private_key:string,private_key_nonce:string} $account
     * @return array{password_hash:string,kdf_salt:string,encrypted_private_key:string,private_key_nonce:string}
     */
    public function changePassword(string $currentPassword, string $newPassword, array $account): array
    {
        self::assertPassword($newPassword);
        $privateKey = $this->unlockPrivateKey($currentPassword, $account);
        $publicKey = self::bin($account['public_key'], self::X25519_KEY_BYTES, 'public_key');

        $salt = random_bytes(self::KDF_SALT_BYTES);
        $masterKey = $this->deriveMasterKey($newPassword, $salt);
        try {
            [$encrypted, $nonce] = $this->wrapPrivateKey($privateKey, $publicKey, $masterKey);
        } finally {
            sodium_memzero($privateKey);
            sodium_memzero($masterKey);
        }
        return [
            'password_hash' => self::hashLoginPassword($newPassword),
            'kdf_salt' => $salt,
            'encrypted_private_key' => $encrypted,
            'private_key_nonce' => $nonce,
        ];
    }

    private function deriveMasterKey(string $password, string $salt): string
    {
        return sodium_crypto_pwhash(
            self::MASTER_KEY_BYTES,
            $password,
            $salt,
            $this->opsLimit,
            $this->memLimit,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );
    }

    /** @return array{0:string,1:string} [ciphertext, nonce] */
    private function wrapPrivateKey(string $privateKey, string $publicKey, string $masterKey): array
    {
        $nonce = random_bytes(self::AEAD_NONCE_BYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $privateKey,
            self::AAD_PRIVATE_KEY . $publicKey,   // amarra a chave privada à sua public_key
            $nonce,
            $masterKey,
        );
        return [$ciphertext, $nonce];
    }

    private function unwrapPrivateKey(string $ciphertext, string $nonce, string $publicKey, string $masterKey): string
    {
        $privateKey = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            self::AAD_PRIVATE_KEY . $publicKey,
            $nonce,
            $masterKey,
        );
        if ($privateKey === false || strlen($privateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new VaultAuthenticationException('Não foi possível abrir a chave privada');
        }
        $derivedPublic = sodium_crypto_box_publickey_from_secretkey($privateKey);
        if (!hash_equals($publicKey, $derivedPublic)) {
            sodium_memzero($privateKey);
            throw new VaultAuthenticationException('Par de chaves inconsistente');
        }
        return $privateKey;
    }

    // =====================================================================
    // 2. Sessão volátil (chave privada cifrada com chave efêmera)
    // =====================================================================

    /**
     * Cifra a chave privada para guardar na sessão do servidor.
     * Devolve o blob (vai para $_SESSION) e o token (chave efêmera, base64url,
     * vai para um cookie HttpOnly/Secure/SameSite=Strict). Sem o cookie, o blob
     * armazenado no servidor é inútil; sem o blob, o cookie é inútil.
     *
     * @param string $sessionBinding identificador estável da sessão (ex.: id
     *        de sessão + id da conta) usado como AAD, impedindo transplante.
     * @return array{blob:string,token:string}
     */
    public function sealPrivateKeyForSession(string $privateKey, string $sessionBinding): array
    {
        self::assertLength($privateKey, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'private_key');
        $ephemeral = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
        $nonce = random_bytes(self::AEAD_NONCE_BYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $privateKey,
            self::AAD_SESSION . $sessionBinding,
            $nonce,
            $ephemeral,
        );
        $token = sodium_bin2base64($ephemeral, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        sodium_memzero($ephemeral);
        return [
            'blob' => sodium_bin2base64(self::FORMAT_VERSION . $nonce . $ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL),
            'token' => $token,
        ];
    }

    /**
     * Recupera a chave privada da sessão. Chame sodium_memzero() após o uso.
     *
     * @throws VaultAuthenticationException token/blob inválidos ou sessão adulterada
     */
    public function openPrivateKeyFromSession(string $blob, string $token, string $sessionBinding): string
    {
        try {
            $raw = sodium_base642bin($blob, SODIUM_BASE64_VARIANT_ORIGINAL);
            $ephemeral = sodium_base642bin($token, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new VaultAuthenticationException('Sessão inválida');
        }
        if (strlen($ephemeral) !== self::MASTER_KEY_BYTES
            || strlen($raw) < 1 + self::AEAD_NONCE_BYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
            || $raw[0] !== self::FORMAT_VERSION) {
            throw new VaultAuthenticationException('Sessão inválida');
        }
        $nonce = substr($raw, 1, self::AEAD_NONCE_BYTES);
        $ciphertext = substr($raw, 1 + self::AEAD_NONCE_BYTES);
        $privateKey = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            self::AAD_SESSION . $sessionBinding,
            $nonce,
            $ephemeral,
        );
        sodium_memzero($ephemeral);
        if ($privateKey === false) {
            throw new VaultAuthenticationException('Sessão inválida');
        }
        return $privateKey;
    }

    // =====================================================================
    // 3. Sealed Box (mensagens, anexos, cópias na pasta Sent)
    // =====================================================================

    /** Sela um conteúdo para a public_key do destinatário (0x01 || crypto_box_seal). */
    public static function seal(string $plaintext, string $publicKey): string
    {
        self::assertLength($publicKey, self::X25519_KEY_BYTES, 'public_key');
        return self::FORMAT_VERSION . sodium_crypto_box_seal($plaintext, $publicKey);
    }

    /** Sela um valor opcional (null permanece null). */
    public static function sealNullable(?string $plaintext, string $publicKey): ?string
    {
        return $plaintext === null ? null : self::seal($plaintext, $publicKey);
    }

    /**
     * Abre uma Sealed Box com o par de chaves da conta.
     *
     * @throws VaultAuthenticationException conteúdo adulterado ou de outra conta
     */
    public static function open(string $sealed, string $publicKey, string $privateKey): string
    {
        self::assertLength($publicKey, self::X25519_KEY_BYTES, 'public_key');
        self::assertLength($privateKey, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'private_key');
        if (strlen($sealed) < 1 + self::SEAL_OVERHEAD || $sealed[0] !== self::FORMAT_VERSION) {
            throw new VaultAuthenticationException('Formato de Sealed Box desconhecido');
        }
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($privateKey, $publicKey);
        $plaintext = sodium_crypto_box_seal_open(substr($sealed, 1), $keypair);
        sodium_memzero($keypair);
        if ($plaintext === false) {
            throw new VaultAuthenticationException('Falha ao abrir Sealed Box');
        }
        return $plaintext;
    }

    public static function openNullable(?string $sealed, string $publicKey, string $privateKey): ?string
    {
        return $sealed === null ? null : self::open($sealed, $publicKey, $privateKey);
    }

    /**
     * Sela todos os campos de uma mensagem (usado pelo MailSender para a cópia
     * em SENT/DRAFTS). Mesmo formato produzido por bin/mail-ingest.py.
     *
     * @param array{subject:string,snippet?:?string,headers:string,body_plain:?string,body_html:?string} $message
     * @return array{encrypted_subject:string,encrypted_snippet:string,encrypted_headers:string,encrypted_body_plain:?string,encrypted_body_html:?string}
     */
    public static function sealMessage(array $message, string $publicKey): array
    {
        $snippet = $message['snippet'] ?? self::makeSnippet($message['body_plain'] ?? null, $message['body_html'] ?? null);
        return [
            'encrypted_subject' => self::seal($message['subject'], $publicKey),
            'encrypted_snippet' => self::seal($snippet, $publicKey),
            'encrypted_headers' => self::seal($message['headers'], $publicKey),
            'encrypted_body_plain' => self::sealNullable($message['body_plain'] ?? null, $publicKey),
            'encrypted_body_html' => self::sealNullable($message['body_html'] ?? null, $publicKey),
        ];
    }

    /**
     * Metadados de anexo selados em encrypted_filename (JSON versionado):
     * {"v":1,"name":"arquivo.pdf","cid":null,"inline":false}
     *
     * @return array{encrypted_filename:string,encrypted_mime_type:string,encrypted_content:string,size_bytes:int}
     */
    public static function sealAttachment(string $filename, string $mimeType, string $content, string $publicKey, ?string $contentId = null, bool $inline = false): array
    {
        $meta = json_encode(
            ['v' => 1, 'name' => $filename, 'cid' => $contentId, 'inline' => $inline],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
        return [
            'encrypted_filename' => self::seal($meta, $publicKey),
            'encrypted_mime_type' => self::seal($mimeType, $publicKey),
            'encrypted_content' => self::seal($content, $publicKey),
            'size_bytes' => strlen($content),
        ];
    }

    /** @return array{name:string,cid:?string,inline:bool} */
    public static function decodeAttachmentMeta(string $plaintextFilename): array
    {
        $meta = json_decode($plaintextFilename, true);
        if (!is_array($meta) || ($meta['v'] ?? null) !== 1 || !is_string($meta['name'] ?? null)) {
            // Compatibilidade: nome simples sem JSON
            return ['name' => $plaintextFilename, 'cid' => null, 'inline' => false];
        }
        return [
            'name' => $meta['name'],
            'cid' => is_string($meta['cid'] ?? null) ? $meta['cid'] : null,
            'inline' => (bool) ($meta['inline'] ?? false),
        ];
    }

    /** Preview de até 120 caracteres (texto puro, espaços colapsados). */
    public static function makeSnippet(?string $bodyPlain, ?string $bodyHtml): string
    {
        $text = $bodyPlain;
        if ($text === null || trim($text) === '') {
            $text = $bodyHtml !== null ? self::htmlToText($bodyHtml) : '';
        }
        $text = trim((string) preg_replace('/\s+/u', ' ', $text));
        return mb_substr($text, 0, self::SNIPPET_CHARS, 'UTF-8');
    }

    private static function htmlToText(string $html): string
    {
        $html = (string) preg_replace('#<(script|style|head)\b[^>]*>.*?</\1>#isu', ' ', $html);
        $html = (string) preg_replace('#<br\s*/?>|</p>|</div>|</li>|</tr>#iu', ' ', $html);
        return html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    // =====================================================================
    // 4. Blind index do assunto (agrupamento de threads)
    // =====================================================================

    /** Normalização idêntica à de bin/mail-ingest.py (normalize_subject). */
    public static function normalizeSubject(string $subject): string
    {
        $s = class_exists(Normalizer::class) ? (Normalizer::normalize($subject, Normalizer::FORM_KC) ?: $subject) : $subject;
        $s = trim((string) preg_replace('/\s+/u', ' ', $s));
        do {
            $previous = $s;
            $s = (string) preg_replace(self::SUBJECT_PREFIX_RE, '', $s);
            $s = trim($s);
        } while ($s !== $previous);
        return mb_strtolower($s, 'UTF-8');
    }

    /** subject_hash (32 bytes) = HMAC(HMAC(K, label||account_id), assunto_normalizado). */
    public function subjectHash(string $subject, string $accountId): string
    {
        if ($this->subjectHmacKey === null) {
            throw new RuntimeException('MP_SUBJECT_HMAC_KEY não configurada');
        }
        $accountKey = hash_hmac('sha256', self::SUBJECT_INDEX_LABEL . strtolower($accountId), $this->subjectHmacKey, true);
        $hash = hash_hmac('sha256', self::normalizeSubject($subject), $accountKey, true);
        sodium_memzero($accountKey);
        return $hash;
    }

    // =====================================================================
    // 5. Segredos do servidor (chaves SSH dos nós, chaves DKIM)
    // =====================================================================

    /**
     * Cifra um segredo operacional com MP_APP_MASTER_KEY.
     * $context identifica o uso (ex.: "infra_nodes.ssh_private_key:3").
     */
    public function encryptServerSecret(string $plaintext, string $context): string
    {
        $key = $this->requireAppKey();
        $nonce = random_bytes(self::AEAD_NONCE_BYTES);
        return self::FORMAT_VERSION . $nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            self::AAD_SERVER_SECRET . $context,
            $nonce,
            $key,
        );
    }

    /** @throws VaultAuthenticationException */
    public function decryptServerSecret(string $ciphertext, string $context): string
    {
        $key = $this->requireAppKey();
        if (strlen($ciphertext) < 1 + self::AEAD_NONCE_BYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
            || $ciphertext[0] !== self::FORMAT_VERSION) {
            throw new VaultAuthenticationException('Formato de segredo desconhecido');
        }
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($ciphertext, 1 + self::AEAD_NONCE_BYTES),
            self::AAD_SERVER_SECRET . $context,
            substr($ciphertext, 1, self::AEAD_NONCE_BYTES),
            $key,
        );
        if ($plaintext === false) {
            throw new VaultAuthenticationException('Falha ao decifrar segredo do servidor');
        }
        return $plaintext;
    }

    private function requireAppKey(): string
    {
        if ($this->appMasterKey === null) {
            throw new RuntimeException('MP_APP_MASTER_KEY não configurada');
        }
        return $this->appMasterKey;
    }

    // =====================================================================
    // Utilitários
    // =====================================================================

    /** Converte valores vindos do PDO/pgsql (bytea pode vir como stream ou "\x..."). */
    public static function bin(mixed $value, ?int $expectedLength, string $name): string
    {
        if (is_resource($value)) {
            $value = stream_get_contents($value);
        }
        if (!is_string($value)) {
            throw new InvalidArgumentException("{$name}: valor binário ausente");
        }
        if (str_starts_with($value, '\\x') && ctype_xdigit(substr($value, 2)) && strlen($value) % 2 === 0) {
            $value = (string) hex2bin(substr($value, 2));
        }
        if ($expectedLength !== null) {
            self::assertLength($value, $expectedLength, $name);
        }
        return $value;
    }

    private static function decodeKey(string $b64, string $name): string
    {
        try {
            $key = sodium_base642bin(trim($b64), SODIUM_BASE64_VARIANT_ORIGINAL);
        } catch (\SodiumException) {
            throw new InvalidArgumentException("{$name} não é base64 válido");
        }
        self::assertLength($key, 32, $name);
        return $key;
    }

    private static function assertLength(string $value, int $length, string $name): void
    {
        if (strlen($value) !== $length) {
            throw new InvalidArgumentException("{$name} deve ter {$length} bytes");
        }
    }

    private static function assertPassword(string $password): void
    {
        $len = mb_strlen($password, 'UTF-8');
        if ($len < 10) {
            throw new InvalidArgumentException('A senha deve ter pelo menos 10 caracteres');
        }
        if ($len > 1024) {
            throw new InvalidArgumentException('Senha longa demais');
        }
    }
}
