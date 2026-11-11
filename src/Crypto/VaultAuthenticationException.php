<?php

declare(strict_types=1);

namespace MailPlatform\Crypto;

use RuntimeException;

/**
 * Falha de autenticação criptográfica: senha incorreta, sessão inválida ou
 * ciphertext adulterado. A mensagem é genérica de propósito (não vaza qual
 * etapa falhou para o cliente).
 */
final class VaultAuthenticationException extends RuntimeException
{
}
