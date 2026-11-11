#!/usr/bin/env bash
# =============================================================================
# Mail Platform :: deploy-db-node.sh
# Provisiona o Servidor 2 (Debian 13 "trixie"): PostgreSQL 17 + TimescaleDB,
# TLS obrigatório, pg_hba restrito ao IP do Servidor 1, roles de menor
# privilégio e o schema completo (sql/schema_timescaledb.sql).
#
# Idempotente: pode ser reexecutado quantas vezes for preciso. Senhas, CA e
# certificados existentes são reaproveitados (use --rotate-tls para renovar).
#
# Uso:
#   deploy-db-node.sh --allowed-ip <IP do Servidor 1> [opções]
#
# Opções:
#   --allowed-ip IP          IP do Servidor 1 (obrigatório). Único cliente aceito.
#   --advertise-host HOST    IP/hostname pelo qual o Servidor 1 alcança este nó
#                            (vai no SAN do certificado). Padrão: IP principal.
#   --db-name NOME           Nome do banco (padrão: mailplatform)
#   --db-port PORTA          Porta do PostgreSQL (padrão: 5432)
#   --schema ARQUIVO         DDL a aplicar (padrão: ../sql/schema_timescaledb.sql)
#   --output ARQUIVO         Arquivo de credenciais gerado
#                            (padrão: /root/mail-platform-db-credentials.env)
#   --timescale-edition E    "tsl" (timescaledb-2-postgresql-17, padrão) ou
#                            "oss" (timescaledb-2-oss-postgresql-17, Apache-2.0)
#   --rotate-tls             Regenera CA e certificado do servidor
#   --no-firewall            Não cria a regra nftables da porta do PostgreSQL
#   -h | --help              Mostra esta ajuda
#
# Saída: cada etapa é impressa com o prefixo "[deploy-db]" (o painel admin faz
# streaming dessas linhas via SSE). Código de saída != 0 em qualquer falha.
# =============================================================================
set -Eeuo pipefail
umask 022

readonly SCRIPT_NAME="deploy-db-node"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; readonly SCRIPT_DIR
readonly PG_MAJOR=17
readonly PG_CLUSTER=main
readonly PG_ETC="/etc/postgresql/${PG_MAJOR}/${PG_CLUSTER}"
readonly PG_BIN="/usr/lib/postgresql/${PG_MAJOR}/bin"
readonly PG_TLS_DIR="${PG_ETC}/tls"
readonly TS_KEYRING="/usr/share/keyrings/timescaledb.gpg"
readonly TS_SOURCES="/etc/apt/sources.list.d/timescaledb.sources"
readonly NFT_FILE="/etc/mail-platform/nftables-db.nft"
readonly NFT_UNIT="/etc/systemd/system/mail-platform-db-firewall.service"

ALLOWED_IP="${MP_ALLOWED_IP:-}"
ADVERTISE_HOST="${MP_ADVERTISE_HOST:-}"
DB_NAME="${MP_DB_NAME:-mailplatform}"
DB_PORT="${MP_DB_PORT:-5432}"
SCHEMA_FILE="${MP_SCHEMA_FILE:-${SCRIPT_DIR}/../sql/schema_timescaledb.sql}"
OUTPUT_FILE="${MP_DB_CREDENTIALS_FILE:-/root/mail-platform-db-credentials.env}"
TS_EDITION="${MP_TIMESCALE_EDITION:-tsl}"
ROTATE_TLS=0
FIREWALL=1

# Roles de menor privilégio usadas pelo Servidor 1
readonly ROLE_APP="mailplatform_app"             # PHP (painel + webmail)
readonly ROLE_INGEST="mailplatform_ingest"       # mail-ingest.py (pipe do Postfix)
readonly ROLE_POSTFIX="mailplatform_postfix"     # lookups de domínios/contas
readonly ROLE_TELEMETRY="mailplatform_telemetry" # action do Fail2ban

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8

# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
log()  { printf '[deploy-db] %s\n' "$*"; }
step() { printf '[deploy-db] ==> %s\n' "$*"; }
warn() { printf '[deploy-db] AVISO: %s\n' "$*" >&2; }
die()  { printf '[deploy-db] ERRO: %s\n' "$*" >&2; exit 1; }
trap 'printf "[deploy-db] ERRO: falha na linha %s (comando: %s)\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

usage() { sed -n '3,/^# =====/{s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" | sed '$d'; }

is_ipv4() {
    local ip=$1 o
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
is_ipv6() { [[ $1 =~ ^[0-9A-Fa-f:.]+$ && $1 == *:* && ${#1} -le 45 ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
is_hostname() { [[ $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ && ${#1} -le 253 ]]; }

rand_hex() { openssl rand -hex "${1:-32}"; }

# Lê KEY='valor' de um arquivo de credenciais sem executá-lo.
read_kv() {
    local file=$1 key=$2 line
    [[ -r $file ]] || return 0
    line=$(grep -E "^${key}='[^']*'$" "$file" | tail -n1 || true)
    [[ -n $line ]] || return 0
    line=${line#*=\'}
    printf '%s' "${line%\'}"
}

psql_postgres() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 "$@"; }

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------
parse_args() {
    while (($#)); do
        case $1 in
            --allowed-ip)        ALLOWED_IP=${2:?}; shift 2 ;;
            --advertise-host)    ADVERTISE_HOST=${2:?}; shift 2 ;;
            --db-name)           DB_NAME=${2:?}; shift 2 ;;
            --db-port)           DB_PORT=${2:?}; shift 2 ;;
            --schema)            SCHEMA_FILE=${2:?}; shift 2 ;;
            --output)            OUTPUT_FILE=${2:?}; shift 2 ;;
            --timescale-edition) TS_EDITION=${2:?}; shift 2 ;;
            --rotate-tls)        ROTATE_TLS=1; shift ;;
            --no-firewall)       FIREWALL=0; shift ;;
            -h|--help)           usage; exit 0 ;;
            *) die "opção desconhecida: $1 (use --help)" ;;
        esac
    done
}

preflight() {
    step "Verificações iniciais"
    [[ $EUID -eq 0 ]] || die "execute como root"
    [[ -r /etc/os-release ]] || die "/etc/os-release ausente"
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ ${ID:-} == debian && ${VERSION_CODENAME:-} == trixie ]] \
        || die "este script exige Debian 13 (trixie); detectado: ${PRETTY_NAME:-desconhecido}"

    [[ -n $ALLOWED_IP ]] || die "--allowed-ip é obrigatório (IP do Servidor 1)"
    is_ip "$ALLOWED_IP" || die "--allowed-ip inválido: $ALLOWED_IP"
    [[ $DB_NAME =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "--db-name inválido: $DB_NAME"
    [[ $DB_PORT =~ ^[0-9]{2,5}$ ]] && (( DB_PORT <= 65535 )) || die "--db-port inválida: $DB_PORT"
    [[ $TS_EDITION == tsl || $TS_EDITION == oss ]] || die "--timescale-edition deve ser tsl ou oss"
    [[ -r $SCHEMA_FILE ]] || die "schema não encontrado: $SCHEMA_FILE"
    SCHEMA_FILE=$(readlink -f "$SCHEMA_FILE")

    if [[ -z $ADVERTISE_HOST ]]; then
        ADVERTISE_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)
        [[ -n $ADVERTISE_HOST ]] || ADVERTISE_HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
        [[ -n $ADVERTISE_HOST ]] || die "não foi possível detectar o IP; use --advertise-host"
    fi
    is_ip "$ADVERTISE_HOST" || is_hostname "$ADVERTISE_HOST" || die "--advertise-host inválido: $ADVERTISE_HOST"

    log "Servidor 1 autorizado : $ALLOWED_IP"
    log "Endereço anunciado    : $ADVERTISE_HOST:$DB_PORT"
    log "Banco                 : $DB_NAME"
    log "Edição TimescaleDB    : $TS_EDITION"
}

# ---------------------------------------------------------------------------
# Pacotes
# ---------------------------------------------------------------------------
install_base_packages() {
    step "Instalando pacotes base"
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl gnupg openssl iproute2 nftables locales >/dev/null
}

configure_timescale_repo() {
    step "Configurando repositório oficial TimescaleDB (Debian trixie)"
    local tmp
    tmp=$(mktemp)
    curl -fsSL --proto '=https' --tlsv1.2 https://packagecloud.io/timescale/timescaledb/gpgkey -o "$tmp"
    gpg --batch --yes --dearmor -o "${TS_KEYRING}.new" "$tmp"
    rm -f "$tmp"
    install -m 0644 "${TS_KEYRING}.new" "$TS_KEYRING"
    rm -f "${TS_KEYRING}.new"
    cat > "$TS_SOURCES" <<EOF
Types: deb
URIs: https://packagecloud.io/timescale/timescaledb/debian/
Suites: trixie
Components: main
Signed-By: ${TS_KEYRING}
EOF
    chmod 0644 "$TS_SOURCES"
    apt-get update -qq
}

install_postgres() {
    step "Instalando PostgreSQL ${PG_MAJOR} + TimescaleDB"
    local ts_pkg="timescaledb-2-postgresql-${PG_MAJOR}"
    [[ $TS_EDITION == oss ]] && ts_pkg="timescaledb-2-oss-postgresql-${PG_MAJOR}"
    apt-get install -y -qq \
        "postgresql-${PG_MAJOR}" "postgresql-client-${PG_MAJOR}" postgresql-common \
        "$ts_pkg" timescaledb-tools >/dev/null

    if ! pg_lsclusters -h 2>/dev/null | awk -v v="$PG_MAJOR" -v c="$PG_CLUSTER" '$1==v && $2==c {f=1} END {exit !f}'; then
        log "Criando cluster ${PG_MAJOR}/${PG_CLUSTER}"
        pg_createcluster "$PG_MAJOR" "$PG_CLUSTER" --start >/dev/null
    fi
    [[ -f ${PG_ETC}/postgresql.conf ]] || die "postgresql.conf não encontrado em ${PG_ETC}"
}

tune_timescale() {
    step "Executando timescaledb-tune"
    timescaledb-tune --quiet --yes \
        --conf-path="${PG_ETC}/postgresql.conf" \
        --pg-config="${PG_BIN}/pg_config" >/dev/null
    grep -Eq "^[[:space:]]*shared_preload_libraries[[:space:]]*=.*timescaledb" "${PG_ETC}/postgresql.conf" \
        || die "timescaledb-tune não configurou shared_preload_libraries"
}

# ---------------------------------------------------------------------------
# TLS (CA privada + certificado do servidor com SAN)
# ---------------------------------------------------------------------------
setup_tls() {
    step "Configurando TLS do PostgreSQL"
    install -d -m 0700 -o postgres -g postgres "$PG_TLS_DIR"

    local san="DNS:localhost,IP:127.0.0.1,IP:::1"
    case $ADVERTISE_HOST in
        127.0.0.1|::1|localhost) ;;
        *) if is_ip "$ADVERTISE_HOST"; then san+=",IP:${ADVERTISE_HOST}"; else san+=",DNS:${ADVERTISE_HOST}"; fi ;;
    esac
    local fqdn
    fqdn=$(hostname -f 2>/dev/null || hostname)
    if is_hostname "$fqdn" && [[ $fqdn != "$ADVERTISE_HOST" && $fqdn != localhost ]]; then san+=",DNS:${fqdn}"; fi

    # Certificado existente cobre o endereço anunciado?
    if (( ! ROTATE_TLS )) && [[ -s ${PG_TLS_DIR}/server.crt && -s ${PG_TLS_DIR}/ca.crt ]]; then
        local want=$ADVERTISE_HOST
        is_ip "$want" && want="IP Address:${want}" || want="DNS:${want}"
        if openssl x509 -in "${PG_TLS_DIR}/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -qF "$want" \
           && openssl x509 -in "${PG_TLS_DIR}/server.crt" -noout -checkend $((30*86400)) >/dev/null; then
            log "Certificado existente válido e cobre ${ADVERTISE_HOST}; mantendo"
            return 0
        fi
        log "Certificado existente não cobre ${ADVERTISE_HOST} ou expira em < 30 dias; regenerando"
    fi

    local cnf
    cnf=$(mktemp)
    cat > "$cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = ${ADVERTISE_HOST}
O = Mail Platform
[srv]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${san}
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
    if (( ROTATE_TLS )) || [[ ! -s ${PG_TLS_DIR}/ca.key || ! -s ${PG_TLS_DIR}/ca.crt ]]; then
        log "Gerando CA privada (ECDSA P-384, 10 anos)"
        openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \
            -keyout "${PG_TLS_DIR}/ca.key" -out "${PG_TLS_DIR}/ca.crt" -days 3650 \
            -subj "/CN=Mail Platform DB CA/O=Mail Platform" -extensions ca -config "$cnf" 2>/dev/null
    fi
    log "Emitindo certificado do servidor (SAN: ${san})"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "${PG_TLS_DIR}/server.key" -out "${PG_TLS_DIR}/server.csr" -config "$cnf" 2>/dev/null
    openssl x509 -req -in "${PG_TLS_DIR}/server.csr" -CA "${PG_TLS_DIR}/ca.crt" -CAkey "${PG_TLS_DIR}/ca.key" \
        -CAcreateserial -out "${PG_TLS_DIR}/server.crt" -days 825 -sha384 -extfile "$cnf" -extensions srv 2>/dev/null
    rm -f "$cnf" "${PG_TLS_DIR}/server.csr"
    chown postgres:postgres "${PG_TLS_DIR}"/*
    chmod 0600 "${PG_TLS_DIR}/server.key" "${PG_TLS_DIR}/ca.key"
    chmod 0644 "${PG_TLS_DIR}/server.crt" "${PG_TLS_DIR}/ca.crt"
    openssl verify -CAfile "${PG_TLS_DIR}/ca.crt" "${PG_TLS_DIR}/server.crt" >/dev/null || die "certificado inválido"
}

# ---------------------------------------------------------------------------
# postgresql.conf / pg_hba.conf
# ---------------------------------------------------------------------------
configure_postgres() {
    step "Configurando postgresql.conf (ssl = on, TLS 1.3)"
    local conf="${PG_ETC}/postgresql.conf"
    [[ -f ${conf}.mp-orig ]] || cp -p "$conf" "${conf}.mp-orig"

    # Força ssl = on diretamente no postgresql.conf ...
    if grep -Eq '^[#[:space:]]*ssl[[:space:]]*=' "$conf"; then
        sed -i -E "s|^[#[:space:]]*ssl[[:space:]]*=.*|ssl = on|" "$conf"
    else
        printf '\nssl = on\n' >> "$conf"
    fi
    grep -Eq "^[[:space:]]*include_dir[[:space:]]*=[[:space:]]*'conf\.d'" "$conf" \
        || printf "\ninclude_dir = 'conf.d'\n" >> "$conf"

    # ... e as demais diretivas num drop-in gerenciado (lido por último).
    install -d -m 0755 -o postgres -g postgres "${PG_ETC}/conf.d"
    cat > "${PG_ETC}/conf.d/90-mail-platform.conf" <<EOF
# Gerado por ${SCRIPT_NAME} — não edite manualmente.
listen_addresses = '*'
port = ${DB_PORT}

ssl = on
ssl_cert_file = '${PG_TLS_DIR}/server.crt'
ssl_key_file = '${PG_TLS_DIR}/server.key'
ssl_min_protocol_version = 'TLSv1.3'
ssl_prefer_server_ciphers = on

password_encryption = 'scram-sha-256'
authentication_timeout = '20s'

log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d from %h '

# TimescaleDB: sem telemetria externa (nenhum dado sai do servidor).
timescaledb.telemetry_level = 'off'
EOF
    chown postgres:postgres "${PG_ETC}/conf.d/90-mail-platform.conf"
    chmod 0644 "${PG_ETC}/conf.d/90-mail-platform.conf"

    step "Configurando pg_hba.conf (hostssl exclusivo para ${ALLOWED_IP})"
    local hba="${PG_ETC}/pg_hba.conf" cidr
    [[ -f ${hba}.mp-orig ]] || cp -p "$hba" "${hba}.mp-orig"
    if is_ipv4 "$ALLOWED_IP"; then cidr="${ALLOWED_IP}/32"; else cidr="${ALLOWED_IP}/128"; fi

    local block tmp
    block=$(cat <<EOF
# BEGIN mail-platform (gerenciado por ${SCRIPT_NAME})
# Acesso administrativo local apenas via socket Unix (peer).
local   all             postgres                                peer
# Servidor 1: somente TLS, somente as roles da plataforma, somente este IP.
hostssl ${DB_NAME}  ${ROLE_APP},${ROLE_INGEST},${ROLE_POSTFIX},${ROLE_TELEMETRY}  ${cidr}  scram-sha-256
# Qualquer outra conexão TCP (com ou sem TLS) é recusada.
host    all             all             0.0.0.0/0               reject
host    all             all             ::/0                    reject
# END mail-platform
EOF
)
    tmp=$(mktemp)
    # Remove bloco anterior e linhas de rede do arquivo original (o bloco
    # gerenciado passa a ser a única política TCP), preservando o restante.
    awk '
        /^# BEGIN mail-platform/ {skip=1; next}
        /^# END mail-platform/   {skip=0; next}
        skip {next}
        /^[[:space:]]*(host|hostssl|hostnossl|hostgssenc|hostnogssenc)[[:space:]]/ {print "# [mail-platform desativado] " $0; next}
        {print}
    ' "$hba" > "${tmp}.body"
    { printf '%s\n' "$block"; cat "${tmp}.body"; } > "$tmp"
    rm -f "${tmp}.body"
    install -m 0640 -o postgres -g postgres "$tmp" "$hba"
    rm -f "$tmp"
}

restart_postgres() {
    step "Reiniciando PostgreSQL"
    systemctl enable --quiet "postgresql@${PG_MAJOR}-${PG_CLUSTER}" 2>/dev/null || true
    systemctl restart "postgresql@${PG_MAJOR}-${PG_CLUSTER}"
    local _
    for _ in $(seq 1 30); do
        if runuser -u postgres -- "${PG_BIN}/pg_isready" -q -p "$DB_PORT"; then
            log "PostgreSQL pronto"
            return 0
        fi
        sleep 1
    done
    journalctl -u "postgresql@${PG_MAJOR}-${PG_CLUSTER}" -n 40 --no-pager >&2 || true
    die "PostgreSQL não ficou pronto em 30s"
}

# ---------------------------------------------------------------------------
# Roles, banco, schema e privilégios
# ---------------------------------------------------------------------------
load_or_generate_secrets() {
    PW_APP=$(read_kv "$OUTPUT_FILE" MP_DB_APP_PASSWORD)
    PW_INGEST=$(read_kv "$OUTPUT_FILE" MP_DB_INGEST_PASSWORD)
    PW_POSTFIX=$(read_kv "$OUTPUT_FILE" MP_DB_POSTFIX_PASSWORD)
    PW_TELEMETRY=$(read_kv "$OUTPUT_FILE" MP_DB_TELEMETRY_PASSWORD)
    [[ $PW_APP =~ ^[0-9a-f]{48}$ ]]       || PW_APP=$(rand_hex 24)
    [[ $PW_INGEST =~ ^[0-9a-f]{48}$ ]]    || PW_INGEST=$(rand_hex 24)
    [[ $PW_POSTFIX =~ ^[0-9a-f]{48}$ ]]   || PW_POSTFIX=$(rand_hex 24)
    [[ $PW_TELEMETRY =~ ^[0-9a-f]{48}$ ]] || PW_TELEMETRY=$(rand_hex 24)
}

create_roles_and_db() {
    step "Criando roles e banco ${DB_NAME}"
    # Senhas entram via \set no stdin (nunca na linha de comando / ps).
    psql_postgres -d postgres <<EOF
\\set db '${DB_NAME}'
\\set r_app '${ROLE_APP}'
\\set r_ingest '${ROLE_INGEST}'
\\set r_postfix '${ROLE_POSTFIX}'
\\set r_tel '${ROLE_TELEMETRY}'
\\set pw_app '${PW_APP}'
\\set pw_ingest '${PW_INGEST}'
\\set pw_postfix '${PW_POSTFIX}'
\\set pw_tel '${PW_TELEMETRY}'
SELECT format('CREATE ROLE %I', r) FROM unnest(ARRAY[:'r_app', :'r_ingest', :'r_postfix', :'r_tel']) AS r
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) \\gexec
SELECT format('ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s PASSWORD %L', r, lim, pw)
  FROM (VALUES (:'r_app', 100, :'pw_app'), (:'r_ingest', 40, :'pw_ingest'),
               (:'r_postfix', 40, :'pw_postfix'), (:'r_tel', 10, :'pw_tel')) AS t(r, lim, pw) \\gexec
SELECT format('CREATE DATABASE %I WITH ENCODING ''UTF8'' LC_COLLATE ''C.UTF-8'' LC_CTYPE ''C.UTF-8'' TEMPLATE template0', :'db')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \\gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I, %I, %I, %I', :'db', :'r_app', :'r_ingest', :'r_postfix', :'r_tel') \\gexec
EOF
}

apply_schema() {
    step "Aplicando schema DDL ($(basename "$SCHEMA_FILE"))"
    # O arquivo pode estar num diretório que o usuário postgres não lê.
    local tmp
    tmp=$(mktemp)
    cat "$SCHEMA_FILE" > "$tmp"
    chmod 0644 "$tmp"
    PGOPTIONS='-c client_min_messages=error' psql_postgres -d "$DB_NAME" -f "$tmp" >/dev/null
    rm -f "$tmp"
    local hypertables
    hypertables=$(psql_postgres -d "$DB_NAME" -At -c \
        "SELECT string_agg(hypertable_name, ',' ORDER BY hypertable_name) FROM timescaledb_information.hypertables")
    log "Hypertables ativas: ${hypertables}"
    [[ $hypertables == *messages* && $hypertables == *message_attachments* && $hypertables == *security_events* ]] \
        || die "hypertables esperadas não encontradas"
}

apply_grants() {
    step "Aplicando privilégios de menor privilégio"
    psql_postgres -d "$DB_NAME" <<EOF
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ${ROLE_APP}, ${ROLE_INGEST}, ${ROLE_POSTFIX}, ${ROLE_TELEMETRY};

-- Aplicação PHP (painel admin + webmail): CRUD completo, sem DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    infra_nodes, mail_domains, mail_accounts, messages, message_attachments, security_events
    TO ${ROLE_APP};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${ROLE_APP};

-- Worker de ingestão (Postfix pipe): lê chaves públicas, grava mensagens cifradas.
REVOKE ALL ON mail_accounts, mail_domains, messages, message_attachments, security_events FROM ${ROLE_INGEST};
GRANT SELECT (id, domain_id, email, public_key, quota_bytes, used_bytes, active) ON mail_accounts TO ${ROLE_INGEST};
GRANT UPDATE (used_bytes) ON mail_accounts TO ${ROLE_INGEST};
GRANT SELECT (id, domain_name, active) ON mail_domains TO ${ROLE_INGEST};
GRANT SELECT (received_at, account_id, message_id, thread_id, subject_hash) ON messages TO ${ROLE_INGEST};
GRANT INSERT ON messages, message_attachments TO ${ROLE_INGEST};
GRANT INSERT ON security_events TO ${ROLE_INGEST};

-- Postfix (virtual_mailbox_domains / virtual_mailbox_maps): somente leitura mínima.
REVOKE ALL ON mail_accounts, mail_domains FROM ${ROLE_POSTFIX};
GRANT SELECT (id, domain_name, active) ON mail_domains TO ${ROLE_POSTFIX};
GRANT SELECT (domain_id, email, active) ON mail_accounts TO ${ROLE_POSTFIX};

-- Fail2ban action: apenas INSERT na telemetria.
REVOKE ALL ON security_events FROM ${ROLE_TELEMETRY};
GRANT INSERT ON security_events TO ${ROLE_TELEMETRY};
EOF
}

# ---------------------------------------------------------------------------
# Firewall (nftables): porta do PostgreSQL apenas para o Servidor 1
# ---------------------------------------------------------------------------
setup_firewall() {
    if (( ! FIREWALL )); then
        log "Firewall nftables desativado (--no-firewall)"
        return 0
    fi
    step "Restringindo porta ${DB_PORT}/tcp ao Servidor 1 (nftables)"
    install -d -m 0750 /etc/mail-platform
    local allow_rule
    if is_ipv4 "$ALLOWED_IP"; then allow_rule="ip saddr ${ALLOWED_IP} tcp dport ${DB_PORT} accept"
    else allow_rule="ip6 saddr ${ALLOWED_IP} tcp dport ${DB_PORT} accept"; fi
    cat > "$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
# Gerado por ${SCRIPT_NAME}. Tabela isolada; não interfere em outras regras.
table inet mailplatform_db
delete table inet mailplatform_db
table inet mailplatform_db {
    chain input {
        type filter hook input priority -10; policy accept;
        iifname "lo" accept
        ${allow_rule}
        tcp dport ${DB_PORT} counter drop
    }
}
EOF
    chmod 0640 "$NFT_FILE"
    nft -c -f "$NFT_FILE" || die "regras nftables inválidas"
    cat > "$NFT_UNIT" <<EOF
[Unit]
Description=Mail Platform - firewall da porta PostgreSQL
Wants=network-pre.target
Before=network-pre.target postgresql.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${NFT_FILE}
ExecStop=/usr/sbin/nft delete table inet mailplatform_db

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --quiet mail-platform-db-firewall.service
    systemctl restart mail-platform-db-firewall.service
}

# ---------------------------------------------------------------------------
# Verificação e saída
# ---------------------------------------------------------------------------
verify_tls_login() {
    step "Validando login TLS (verify-full) com a role de ingestão"
    local host=$ADVERTISE_HOST
    # Em instalação all-in-one o Servidor 1 é 127.0.0.1.
    [[ $ALLOWED_IP == 127.0.0.1 || $ALLOWED_IP == ::1 ]] && host=$ALLOWED_IP
    if [[ $host != "$ALLOWED_IP" ]]; then
        log "Teste remoto ignorado: este nó não é o IP autorizado (${ALLOWED_IP}); o deploy do Servidor 1 valida a conexão"
        return 0
    fi
    PGPASSWORD=$PW_INGEST PGSSLMODE=verify-full PGSSLROOTCERT="${PG_TLS_DIR}/ca.crt" \
        psql -X -q -h "$host" -p "$DB_PORT" -U "$ROLE_INGEST" -d "$DB_NAME" -At \
        -c "SELECT 'tls=' || ssl || ' ' || version FROM pg_stat_ssl WHERE pid = pg_backend_pid()" \
        | sed 's/^/[deploy-db] /'
}

write_credentials() {
    step "Gravando credenciais em ${OUTPUT_FILE}"
    local ca_b64 host=$ADVERTISE_HOST
    [[ $ALLOWED_IP == 127.0.0.1 || $ALLOWED_IP == ::1 ]] && host=$ALLOWED_IP
    ca_b64=$(base64 -w0 "${PG_TLS_DIR}/ca.crt")
    install -d -m 0700 "$(dirname "$OUTPUT_FILE")"
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# Mail Platform — credenciais do Servidor 2 (gerado por ${SCRIPT_NAME} em $(date -u +%FT%TZ))
# Copie este arquivo para o Servidor 1 e use: deploy-mail-node.sh --db-env <arquivo>
# CONFIDENCIAL: contém senhas. Permissão 0600.
MP_DB_HOST='${host}'
MP_DB_PORT='${DB_PORT}'
MP_DB_NAME='${DB_NAME}'
MP_DB_SSLMODE='verify-full'
MP_DB_APP_USER='${ROLE_APP}'
MP_DB_APP_PASSWORD='${PW_APP}'
MP_DB_INGEST_USER='${ROLE_INGEST}'
MP_DB_INGEST_PASSWORD='${PW_INGEST}'
MP_DB_POSTFIX_USER='${ROLE_POSTFIX}'
MP_DB_POSTFIX_PASSWORD='${PW_POSTFIX}'
MP_DB_TELEMETRY_USER='${ROLE_TELEMETRY}'
MP_DB_TELEMETRY_PASSWORD='${PW_TELEMETRY}'
MP_DB_ALLOWED_CLIENT='${ALLOWED_IP}'
MP_DB_CA_PEM_B64='${ca_b64}'
EOF
    install -m 0600 -o root -g root "$tmp" "$OUTPUT_FILE"
    rm -f "$tmp"
}

summary() {
    step "Deploy do Servidor 2 concluído"
    log "PostgreSQL ${PG_MAJOR} + TimescaleDB em ${ADVERTISE_HOST}:${DB_PORT} (TLS 1.3 obrigatório)"
    log "Cliente autorizado: ${ALLOWED_IP} (pg_hba hostssl + nftables)"
    log "Credenciais: ${OUTPUT_FILE}"
    log "Próximo passo no Servidor 1:"
    log "  scp root@${ADVERTISE_HOST}:${OUTPUT_FILE} /root/"
    log "  deploy-mail-node.sh --hostname <mail.seudominio> --db-env ${OUTPUT_FILE}"
    printf 'MP_DEPLOY_RESULT=DEPLOY_OK role=db_timescale host=%s\n' "$ADVERTISE_HOST"
}

main() {
    parse_args "$@"
    preflight
    install_base_packages
    configure_timescale_repo
    install_postgres
    tune_timescale
    setup_tls
    configure_postgres
    restart_postgres
    load_or_generate_secrets
    create_roles_and_db
    apply_schema
    apply_grants
    setup_firewall
    write_credentials
    verify_tls_login
    summary
}

main "$@"
