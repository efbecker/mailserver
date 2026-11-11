-- =============================================================================
-- Mail Platform :: Schema PostgreSQL 17 + TimescaleDB (Servidor 2)
-- -----------------------------------------------------------------------------
-- Aplicado automaticamente por bin/deploy-db-node.sh (como superusuário
-- "postgres", dentro do banco da plataforma). O arquivo é idempotente: pode
-- ser reexecutado em cada deploy sem perda de dados.
--
-- Nenhum conteúdo de e-mail é armazenado em texto plano: assunto, snippet,
-- headers, corpos e anexos são Sealed Boxes (X25519 + XSalsa20-Poly1305)
-- geradas com a public_key do destinatário.
-- =============================================================================

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -----------------------------------------------------------------------------
-- 1. Tabela de Nós da Infraestrutura (Para gerência SSH)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS infra_nodes (
    id SERIAL PRIMARY KEY,
    node_role VARCHAR(30) NOT NULL CHECK (node_role IN ('mail_frontend', 'db_timescale')),
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    ssh_port INTEGER DEFAULT 22,
    ssh_user VARCHAR(64) DEFAULT 'root',
    ssh_private_key_enc BYTEA NOT NULL,
    deploy_status VARCHAR(30) DEFAULT 'pending',
    last_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 2. Domínios Virtuais e Chaves DKIM
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mail_domains (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    dkim_selector VARCHAR(64) DEFAULT 'mail',
    dkim_private_key_enc BYTEA NOT NULL,
    dkim_public_key TEXT NOT NULL,
    spf_record TEXT NOT NULL,
    dmarc_record TEXT NOT NULL,
    mx_verified BOOLEAN DEFAULT FALSE,
    spf_verified BOOLEAN DEFAULT FALSE,
    dkim_verified BOOLEAN DEFAULT FALSE,
    dmarc_verified BOOLEAN DEFAULT FALSE,
    ptr_verified BOOLEAN DEFAULT FALSE,
    quota_mb INTEGER DEFAULT 10240,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 3. Contas de Clientes com Isolamento Criptográfico
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mail_accounts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    domain_id INTEGER REFERENCES mail_domains(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    password_hash TEXT NOT NULL,               -- Argon2id hash para login
    kdf_salt BYTEA NOT NULL,                   -- Salt de 16 bytes para derivar a chave da private_key
    public_key BYTEA NOT NULL,                 -- Chave pública X25519 (32 bytes)
    encrypted_private_key BYTEA NOT NULL,      -- Chave privada criptografada com XChaCha20-Poly1305
    private_key_nonce BYTEA NOT NULL,          -- Nonce de 24 bytes da chave privada
    quota_bytes BIGINT DEFAULT 5368709120,     -- 5 GB padrão
    used_bytes BIGINT DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 4. Hypertable de Mensagens Criptografadas (TimescaleDB)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message_id UUID NOT NULL DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    thread_id UUID NOT NULL,
    folder VARCHAR(32) NOT NULL DEFAULT 'INBOX', -- INBOX, SENT, DRAFTS, SPAM, TRASH, ARCHIVE
    sender_address VARCHAR(255) NOT NULL,
    recipient_address VARCHAR(255) NOT NULL,
    subject_hash BYTEA NOT NULL,                 -- HMAC blind index para agrupar threads sem revelar assunto
    encrypted_subject BYTEA NOT NULL,            -- Sealed Box
    encrypted_snippet BYTEA NOT NULL,            -- Sealed Box (preview de 120 chars)
    encrypted_headers BYTEA NOT NULL,            -- Sealed Box
    encrypted_body_plain BYTEA,                  -- Sealed Box
    encrypted_body_html BYTEA,                   -- Sealed Box
    spf_pass BOOLEAN DEFAULT FALSE,
    dkim_pass BOOLEAN DEFAULT FALSE,
    dmarc_pass BOOLEAN DEFAULT FALSE,
    spam_score NUMERIC(5,2) DEFAULT 0.00,
    is_read BOOLEAN DEFAULT FALSE,
    is_starred BOOLEAN DEFAULT FALSE,
    has_attachments BOOLEAN DEFAULT FALSE,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (received_at, account_id, message_id)
);

-- Conversão em Hypertable particionada por tempo (chunks de 7 dias)
SELECT create_hypertable('messages', 'received_at', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_messages_account_folder ON messages (account_id, folder, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages (account_id, thread_id, received_at ASC);

-- -----------------------------------------------------------------------------
-- 5. Tabela de Anexos Criptografados
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS message_attachments (
    received_at TIMESTAMPTZ NOT NULL,
    attachment_id UUID DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    message_id UUID NOT NULL,
    encrypted_filename BYTEA NOT NULL,
    encrypted_mime_type BYTEA NOT NULL,
    encrypted_content BYTEA NOT NULL,
    size_bytes INTEGER NOT NULL,
    PRIMARY KEY (received_at, account_id, attachment_id)
);

SELECT create_hypertable('message_attachments', 'received_at', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);

-- -----------------------------------------------------------------------------
-- 6. Hypertable de Telemetria de Segurança e Eventos do Fail2ban
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service VARCHAR(50) NOT NULL,   -- postfix, fail2ban, webmail_auth, ssh_deploy
    jail_name VARCHAR(50),
    source_ip INET,
    action VARCHAR(32) NOT NULL,    -- BAN, UNBAN, AUTH_FAIL, DEPLOY_OK
    details TEXT
);

SELECT create_hypertable('security_events', 'event_time', chunk_time_interval => INTERVAL '30 days', if_not_exists => TRUE);

-- -----------------------------------------------------------------------------
-- Índices complementares (não alteram o modelo; aceleram consultas do painel
-- e do webmail).
-- -----------------------------------------------------------------------------
-- Anexos de uma mensagem específica (abertura do painel de leitura).
CREATE INDEX IF NOT EXISTS idx_attachments_message
    ON message_attachments (account_id, message_id, received_at DESC);
-- Agrupamento de threads pelo blind index do assunto (worker de ingestão).
CREATE INDEX IF NOT EXISTS idx_messages_subject_hash
    ON messages (account_id, subject_hash, received_at DESC);
-- Filtro "Não lidos" do webmail.
CREATE INDEX IF NOT EXISTS idx_messages_unread
    ON messages (account_id, folder, received_at DESC) WHERE is_read = FALSE;
-- Contas por domínio (painel admin) e lookups do Postfix.
CREATE INDEX IF NOT EXISTS idx_mail_accounts_domain ON mail_accounts (domain_id);
CREATE INDEX IF NOT EXISTS idx_mail_accounts_email_lower ON mail_accounts (lower(email));
CREATE INDEX IF NOT EXISTS idx_mail_domains_name_lower ON mail_domains (lower(domain_name));
-- Telemetria: tela do Fail2ban (por IP e por serviço).
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events (source_ip, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_service ON security_events (service, event_time DESC);

COMMENT ON TABLE messages IS 'Mensagens cifradas com crypto_box_seal (X25519) usando a public_key da conta.';
COMMENT ON COLUMN mail_accounts.encrypted_private_key IS 'Chave privada X25519 cifrada com XChaCha20-Poly1305 (chave derivada da senha via Argon2id).';
COMMENT ON TABLE security_events IS 'Telemetria de segurança: BAN/UNBAN do Fail2ban, falhas de login do webmail, deploys SSH.';
