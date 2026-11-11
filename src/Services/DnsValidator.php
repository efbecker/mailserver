<?php

declare(strict_types=1);

namespace MailPlatform\Services;

use RuntimeException;

/**
 * Geração de chaves DKIM, montagem dos registros DNS recomendados e
 * verificação de propagação (MX, SPF, DKIM, DMARC e PTR/FCrDNS) usando apenas
 * o resolvedor do sistema (dns_get_record / gethostbyaddr).
 */
final class DnsValidator
{
    public const DKIM_BITS = 2048;

    /** @var callable(string,int):array<int,array<string,mixed>>|null */
    private $resolver;
    /** @var callable(string):string|false|null */
    private $reverseResolver;

    /**
     * @param callable|null $resolver        substitui dns_get_record (testes)
     * @param callable|null $reverseResolver substitui gethostbyaddr (testes)
     */
    public function __construct(
        private readonly string $mailHostname,
        private readonly ?string $publicIp,
        ?callable $resolver = null,
        ?callable $reverseResolver = null,
    ) {
        $this->resolver = $resolver;
        $this->reverseResolver = $reverseResolver;
    }

    public static function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain, " .\t\n\r"));
        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($domain, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
            if ($ascii !== false) {
                $domain = $ascii;
            }
        }
        if (strlen($domain) > 253 || !preg_match('/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/', $domain)) {
            throw new \InvalidArgumentException('Nome de domínio inválido');
        }
        return $domain;
    }

    public static function validSelector(string $selector): bool
    {
        return (bool) preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/', $selector);
    }

    /**
     * Gera um par de chaves DKIM RSA-2048.
     *
     * @return array{private_pem:string,public_b64:string}
     */
    public static function generateDkimKeyPair(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => self::DKIM_BITS,
        ]);
        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new RuntimeException('Falha ao gerar chave DKIM: ' . (openssl_error_string() ?: 'openssl'));
        }
        $details = openssl_pkey_get_details($key);
        $publicPem = (string) ($details['key'] ?? '');
        $publicB64 = (string) preg_replace('/-----[^-]+-----|\s+/', '', $publicPem);
        if ($publicB64 === '') {
            throw new RuntimeException('Falha ao extrair chave pública DKIM');
        }
        return ['private_pem' => (string) $pem, 'public_b64' => $publicB64];
    }

    public static function dkimRecordValue(string $publicB64): string
    {
        return 'v=DKIM1; k=rsa; p=' . $publicB64;
    }

    public function spfRecordValue(): string
    {
        $parts = ['v=spf1', 'mx', 'a:' . $this->mailHostname];
        if ($this->publicIp !== null && filter_var($this->publicIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts[] = 'ip4:' . $this->publicIp;
        }
        $parts[] = '-all';
        return implode(' ', $parts);
    }

    public static function dmarcRecordValue(string $domain): string
    {
        return "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=100; rua=mailto:postmaster@{$domain}; fo=1";
    }

    /**
     * Registros a publicar no DNS do domínio.
     *
     * @return list<array{key:string,type:string,name:string,value:string,priority:?int,note:string}>
     */
    public function recommendedRecords(string $domain, string $selector, string $dkimPublicB64, string $spf, string $dmarc): array
    {
        $records = [
            ['key' => 'mx', 'type' => 'MX', 'name' => $domain, 'value' => $this->mailHostname, 'priority' => 10,
                'note' => 'Entrega de e-mails para este servidor.'],
            ['key' => 'spf', 'type' => 'TXT', 'name' => $domain, 'value' => $spf, 'priority' => null,
                'note' => 'Autoriza este servidor a enviar pelo domínio. Mantenha apenas UM registro v=spf1.'],
            ['key' => 'dkim', 'type' => 'TXT', 'name' => "{$selector}._domainkey.{$domain}", 'value' => self::dkimRecordValue($dkimPublicB64), 'priority' => null,
                'note' => 'Assinatura DKIM (RSA-2048). Painéis como a Cloudflare dividem o valor longo automaticamente.'],
            ['key' => 'dmarc', 'type' => 'TXT', 'name' => "_dmarc.{$domain}", 'value' => $dmarc, 'priority' => null,
                'note' => 'Política DMARC (quarentena para falhas, alinhamento estrito).'],
        ];
        $records[] = [
            'key' => 'ptr', 'type' => 'PTR',
            'name' => $this->publicIp !== null ? self::reverseName($this->publicIp) : '<IP público>',
            'value' => $this->mailHostname, 'priority' => null,
            'note' => 'DNS reverso (rDNS): solicite ao provedor/operadora do IP ' . ($this->publicIp ?? '') . '. Também crie o registro A de '
                . $this->mailHostname . ' apontando para esse IP (sem proxy).',
        ];
        return $records;
    }

    /**
     * Consulta o DNS e compara com o esperado.
     *
     * @return array{mx:array{ok:bool,found:list<string>},spf:array{ok:bool,found:list<string>},dkim:array{ok:bool,found:list<string>},dmarc:array{ok:bool,found:list<string>},ptr:array{ok:bool,found:list<string>}}
     */
    public function verify(string $domain, string $selector, string $dkimPublicB64): array
    {
        $host = strtolower(rtrim($this->mailHostname, '.'));

        // MX
        $mx = array_map(
            static fn (array $r): string => strtolower(rtrim((string) ($r['target'] ?? ''), '.')),
            $this->lookup($domain, DNS_MX),
        );
        $mxOk = in_array($host, $mx, true);

        // SPF
        $spfs = array_values(array_filter(
            array_map(fn (array $r): string => $this->txt($r), $this->lookup($domain, DNS_TXT)),
            static fn (string $t): bool => stripos($t, 'v=spf1') === 0,
        ));
        $spfOk = count($spfs) === 1 && $this->spfAuthorizes($spfs[0], $host);

        // DKIM
        $dkims = array_map(fn (array $r): string => $this->txt($r), $this->lookup("{$selector}._domainkey.{$domain}", DNS_TXT));
        $dkimOk = false;
        foreach ($dkims as $t) {
            if (preg_match('/(?:^|;)\s*p=([A-Za-z0-9+\/=\s]+)/', $t, $m) && preg_replace('/\s+/', '', $m[1]) === $dkimPublicB64) {
                $dkimOk = true;
            }
        }

        // DMARC
        $dmarcs = array_values(array_filter(
            array_map(fn (array $r): string => $this->txt($r), $this->lookup("_dmarc.{$domain}", DNS_TXT)),
            static fn (string $t): bool => stripos($t, 'v=DMARC1') === 0,
        ));
        $dmarcOk = count($dmarcs) === 1 && preg_match('/;\s*p=(quarantine|reject|none)\b/i', $dmarcs[0]) === 1;

        // PTR + FCrDNS (o nome reverso precisa resolver de volta para o IP)
        $ptrFound = [];
        $ptrOk = false;
        if ($this->publicIp !== null && filter_var($this->publicIp, FILTER_VALIDATE_IP)) {
            $rev = $this->reverse($this->publicIp);
            if ($rev !== false && $rev !== $this->publicIp) {
                $rev = strtolower(rtrim($rev, '.'));
                $ptrFound[] = $rev;
                $forward = array_map(
                    static fn (array $r): string => (string) ($r['ip'] ?? $r['ipv6'] ?? ''),
                    $this->lookup($rev, filter_var($this->publicIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? DNS_AAAA : DNS_A),
                );
                $ptrOk = $rev === $host && in_array($this->publicIp, $forward, true);
            }
        }

        return [
            'mx' => ['ok' => $mxOk, 'found' => $mx],
            'spf' => ['ok' => $spfOk, 'found' => $spfs],
            'dkim' => ['ok' => $dkimOk, 'found' => array_map(static fn (string $t): string => mb_substr($t, 0, 80) . (strlen($t) > 80 ? '…' : ''), $dkims)],
            'dmarc' => ['ok' => $dmarcOk, 'found' => $dmarcs],
            'ptr' => ['ok' => $ptrOk, 'found' => $ptrFound],
        ];
    }

    private function spfAuthorizes(string $spf, string $host): bool
    {
        $spf = strtolower($spf);
        if (preg_match('/(^|\s)[+]?mx(\s|$)/', $spf) || str_contains($spf, 'a:' . $host)) {
            return true;
        }
        return $this->publicIp !== null && str_contains($spf, 'ip4:' . $this->publicIp);
    }

    /** @return list<array<string,mixed>> */
    private function lookup(string $name, int $type): array
    {
        if ($this->resolver !== null) {
            return array_values(($this->resolver)($name, $type));
        }
        $r = @dns_get_record($name, $type);
        return is_array($r) ? array_values($r) : [];
    }

    private function reverse(string $ip): string|false
    {
        return $this->reverseResolver !== null ? ($this->reverseResolver)($ip) : @gethostbyaddr($ip);
    }

    /** TXT longos chegam divididos em "entries" (strings de até 255 bytes). */
    private function txt(array $record): string
    {
        if (isset($record['entries']) && is_array($record['entries'])) {
            return implode('', array_map('strval', $record['entries']));
        }
        return (string) ($record['txt'] ?? '');
    }

    private static function reverseName(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        }
        $hex = bin2hex((string) inet_pton($ip));
        return implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
    }
}
