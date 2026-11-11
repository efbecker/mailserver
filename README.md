# Mail Platform — Mail Server & Webmail com criptografia Zero-Knowledge (Debian 13)

Plataforma 100% open-source composta por um **Painel Admin** (deploy via SSH, DNS,
domínios, contas e Fail2ban) e um **Webmail** moderno. Nenhum e-mail é gravado em
texto plano: o Postfix entrega cada mensagem a um pipe que a sela com
`crypto_box_seal` (X25519) usando a chave pública do destinatário e grava o
resultado em hypertables do TimescaleDB.

| Nó | Função | Software |
|----|--------|----------|
| Servidor 1 | Web, orquestrador SSH, MTA | Apache2 (mpm_event, TLS 1.3), PHP 8.4-FPM, Postfix + postfix-pgsql, OpenDKIM, Rspamd, Fail2ban, Python 3 (PyNaCl) |
| Servidor 2 | Storage cifrado + telemetria | PostgreSQL 17 + TimescaleDB, TLS 1.3 obrigatório, `hostssl` restrito ao Servidor 1 |

## Deploy via curl

Os comandos abaixo funcionam em um Debian 13 (trixie) recém-instalado, como root
(ou com `sudo`). Reexecutar o mesmo comando atualiza o código e reaplica o deploy;
os scripts são idempotentes e preservam chaves e senhas já geradas.

**1. Servidor 2 (banco):**

```bash
curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
  | sudo bash -s -- --role db --allowed-ip <IP_DO_SERVIDOR_1>
```

Ao final é gerado `/root/mail-platform-db-credentials.env` (0600) com as senhas das
roles e a CA privada do PostgreSQL.

**2. Servidor 1 (mail + web):**

```bash
scp root@<IP_DO_SERVIDOR_2>:/root/mail-platform-db-credentials.env /root/
curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
  | sudo bash -s -- --role mail \
      --hostname mail.empresa.com.br \
      --db-env /root/mail-platform-db-credentials.env \
      --acme-email admin@empresa.com.br \
      --admin-allow 203.0.113.10
```

A senha inicial do painel fica em `/root/mail-platform-admin.txt` (0600).
Sem `--admin-allow`, o painel admin só responde via loopback (use um túnel SSH).

**Tudo em um host só (laboratório ou pequeno porte):**

```bash
curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
  | sudo bash -s -- --role all --hostname mail.empresa.com.br --acme-email admin@empresa.com.br
```

Opções do instalador: `--ref <branch|tag>` (padrão `main`), `--repo <url>`,
`--dir <destino>` (padrão `/var/www/mail-platform`; papel `db`: `/opt/mail-platform`)
e `--no-update`. As demais opções vão para o script de deploy correspondente
(`--role db --help` e `--role mail --help` listam todas).

Também é possível rodar os scripts diretamente a partir de um clone:
`bin/deploy-db-node.sh --allowed-ip …` e `bin/deploy-mail-node.sh --hostname … --db-env …`.

## O que cada deploy configura

**`bin/deploy-db-node.sh` (Servidor 2)**
- Repositório oficial TimescaleDB para `trixie`, `postgresql-17`,
  `timescaledb-2-postgresql-17` (ou `--timescale-edition oss` para a edição Apache-2.0)
  e `timescaledb-tune --quiet --yes`. Telemetria do TimescaleDB desligada.
- CA privada ECDSA + certificado do servidor com SAN, `ssl = on`,
  `ssl_min_protocol_version = TLSv1.3`, `pg_hba.conf` com uma única linha `hostssl`
  (IP do Servidor 1, `scram-sha-256`) e `reject` para todo o resto.
- Firewall nftables isolado permitindo a porta do PostgreSQL apenas ao Servidor 1.
- Schema `sql/schema_timescaledb.sql` e roles de menor privilégio:
  `mailplatform_app` (PHP), `mailplatform_ingest` (pipe do Postfix, só lê chaves
  públicas e insere mensagens), `mailplatform_postfix` (lookups) e
  `mailplatform_telemetry` (só `INSERT` em `security_events`).

**`bin/deploy-mail-node.sh` (Servidor 1)**
- Apache2 com `mpm_event`, `mod_ssl`, `mod_headers`, `mod_rewrite`, HTTP/2,
  TLS 1.3 estrito, HSTS, CSP sem scripts inline e painel admin restrito por IP.
- PHP 8.4-FPM em pool dedicado (`mailplatform`), com `open_basedir` e cookies seguros.
- Postfix: domínios e contas virtuais no PostgreSQL (TLS `verify-full`), entrega via
  pipe `mailingest` -> `/usr/local/bin/mail-ingest.py`, submission só em
  `127.0.0.1:587` com assinatura OpenDKIM obrigatória, RBL opcional.
- OpenDKIM (assinatura) e Rspamd em modo milter (antispam, SPF/DKIM/DMARC em
  `Authentication-Results`), Redis local.
- Fail2ban com as jails `sshd`, `postfix`, `postfix-sasl`, `postfix-rbl`,
  `apache-auth`, `mail-platform-auth` e `recidive`; cada BAN/UNBAN é gravado em
  `security_events` pela action `mail-platform-timescale` (com spool local se o banco
  estiver fora do ar).
- Wrappers validados para o PHP via sudo: `mp-f2b-ctl` (ban/unban/mailq) e
  `mp-dkim-ctl` (instalação de chaves DKIM).

## DNS necessário

Para o servidor: registro `A`/`AAAA` de `mail.seudominio` e PTR (rDNS) do IP
apontando para ele, com as portas 25, 80 e 443 abertas. MX, SPF, DKIM e DMARC de
cada domínio são gerados pelo painel admin.

## API (Entrega 3)

Todas as respostas são JSON. Métodos que alteram estado exigem o cabeçalho
`X-CSRF-Token` (obtido em `GET .../session`). Sessões: cookie `MPSESSID`
(Secure, HttpOnly, SameSite=Strict, 30 min ociosa / 12 h absoluta).

**Painel Admin** (`/api/admin/*`, restrito por IP no Apache): `session`, `login`,
`logout`, `overview`; `nodes` (chave SSH cifrada no banco, TOFU de host key),
`nodes/{id}/test`, `deploy` + `deploy/{job}/stream` (logs em tempo real via SSE);
`domains` (gera DKIM RSA-2048 e instala no OpenDKIM), `domains/{id}/verify`
(MX, SPF, DKIM, DMARC, PTR/FCrDNS); `accounts` (cria par X25519, cota,
`reset-password`); `fail2ban`, `fail2ban/ban|unban`, `queue`, `queue/flush`,
`security-events`.

**Webmail** (`/api/webmail/*`): no login a chave privada é desbloqueada com a senha
(Argon2id) e re-cifrada com uma chave efêmera que fica **apenas** no cookie
`MPKEY` (HttpOnly, path `/api/webmail`); o servidor guarda só o blob cifrado.
Rotas: `folders`, `messages` (conversas, filtros `unread|attachments|starred`,
busca `q=` decifrando em memória), `threads/{id}`, `messages/{id}`, `render/{id}`
(HTML sanitizado por lista de permissões, imagens remotas bloqueadas por padrão,
CSP própria com `sandbox`), `attachments/{id}`, `send`, `drafts`, `contacts`,
`password`, `folders/{TRASH|SPAM}/empty`.

## Estrutura

```
/var/www/mail-platform/
├── install.sh                     # Instalador via curl
├── apache-vhost.conf              # VirtualHost hardened (TLS 1.3, CSP, HSTS)
├── bin/
│   ├── deploy-db-node.sh          # Servidor 2: PostgreSQL 17 + TimescaleDB
│   ├── deploy-mail-node.sh        # Servidor 1: Apache, PHP, Postfix, OpenDKIM, Rspamd, Fail2ban
│   ├── mail-ingest.py             # (Entrega 2) pipe criptográfico do Postfix
│   └── helpers/                   # mp-security-event, mp-f2b-ctl, mp-dkim-ctl, mp-tls-deploy-hook
├── config/                        # Templates: postfix/, fail2ban/, opendkim/, rspamd/, php/, apache/
├── sql/schema_timescaledb.sql     # DDL com hypertables e índices
├── src/
│   ├── Config/                    # Config (app.env), Database (PDO + TLS verify-full)
│   ├── Crypto/                    # ZeroKnowledgeVault
│   ├── Http/                      # Request, Response, Session, Router
│   ├── Services/                  # SshOrchestrator, DnsValidator, MailSender, SecurityLog
│   └── Controllers/               # AdminController, WebmailController
└── public/                        # (Entrega 4) admin.html, webmail.html, assets/
```

## Status das entregas

- [x] **Entrega 1**: schema SQL, `apache-vhost.conf`, `deploy-db-node.sh`,
  `deploy-mail-node.sh` (Postfix, OpenDKIM, Rspamd, Fail2ban) e instalador via curl.
- [x] **Entrega 2**: `src/Crypto/ZeroKnowledgeVault.php` (Argon2id, X25519, Sealed Box,
  XChaCha20-Poly1305, sessão com chave efêmera, blind index HMAC) e `bin/mail-ingest.py`
  (pipe do Postfix: sela e grava no TimescaleDB). Formato compartilhado:
  `0x01 || crypto_box_seal(...)`.
- [x] **Entrega 3**: backend PHP (`Database`, `SshOrchestrator`, `DnsValidator`,
  `MailSender`, `AdminController`, `WebmailController` e `public/index.php`).
- [ ] **Entrega 4**: frontend do Painel Admin e do Webmail.
