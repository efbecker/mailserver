#!/usr/bin/env bash
# =============================================================================
# Mail Platform :: deploy-mail-node.sh
# Provisiona o Servidor 1 (Debian 13 "trixie"): Apache2 (mpm_event + TLS 1.3),
# PHP 8.4-FPM, Postfix + postfix-pgsql (domínios/contas no TimescaleDB),
# OpenDKIM, Rspamd, Fail2ban (com telemetria no TimescaleDB) e o pipe de
# ingestão criptográfica /usr/local/bin/mail-ingest.py.
#
# Idempotente: reexecutar não perde chaves nem configurações geradas
# (chave mestra da aplicação, chave HMAC do blind index, hash do admin).
#
# Uso:
#   deploy-mail-node.sh --hostname mail.empresa.com.br \
#                       --db-env /root/mail-platform-db-credentials.env [opções]
#
# Opções:
#   --hostname FQDN        Nome do servidor de e-mail / painel (obrigatório)
#   --db-env ARQUIVO       Credenciais geradas pelo deploy-db-node.sh (obrigatório)
#   --admin-allow LISTA    IPs/CIDRs (separados por vírgula) com acesso ao painel
#                          admin. Padrão: IP da sessão SSH atual + loopback.
#   --acme-email EMAIL     Emite certificado Let's Encrypt (certbot, webroot).
#                          Sem esta opção é usado um certificado autoassinado.
#   --admin-email EMAIL    Destino dos e-mails de sistema (root/postmaster)
#   --app-dir DIR          Diretório da aplicação (padrão: diretório pai deste script)
#   --no-rbl               Não consulta RBL (zen.spamhaus.org) no RCPT TO
#   -h | --help            Mostra esta ajuda
#
# Saída: cada etapa é impressa com o prefixo "[deploy-mail]" (o painel admin
# faz streaming dessas linhas via SSE). Código de saída != 0 em qualquer falha.
# =============================================================================
set -Eeuo pipefail
umask 022
shopt -u patsub_replacement 2>/dev/null || true

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SCRIPT_NAME="deploy-mail-node"
readonly PHP_VER=8.4
readonly ETC_MP=/etc/mail-platform
readonly TLS_DIR=${ETC_MP}/tls
readonly FPM_SOCKET=/run/php/php${PHP_VER}-fpm-mailplatform.sock
readonly APP_USER=mailplatform
readonly INGEST_USER=mailingest

MAIL_HOSTNAME="${MP_MAIL_HOSTNAME:-}"
DB_ENV_FILE="${MP_DB_ENV_FILE:-}"
ADMIN_ALLOW="${MP_ADMIN_ALLOW:-}"
ACME_EMAIL="${MP_ACME_EMAIL:-}"
ADMIN_EMAIL="${MP_ADMIN_EMAIL:-}"
APP_DIR="${MP_APP_DIR:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
ENABLE_RBL="${MP_ENABLE_RBL:-1}"

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8

declare -A TPL=()
ADMIN_PASSWORD_PLAIN=""

# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
log()  { printf '[deploy-mail] %s\n' "$*"; }
step() { printf '[deploy-mail] ==> %s\n' "$*"; }
warn() { printf '[deploy-mail] AVISO: %s\n' "$*" >&2; }
die()  { printf '[deploy-mail] ERRO: %s\n' "$*" >&2; exit 1; }
trap 'printf "[deploy-mail] ERRO: falha na linha %s (comando: %s)\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

usage() { sed -n '3,/^# =====/{s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" | sed '$d'; }

is_ipv4() {
    local ip=$1 o
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
is_ipv6() { [[ $1 =~ ^[0-9A-Fa-f:.]+$ && $1 == *:* && ${#1} -le 45 ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
is_cidr() {
    local addr=${1%/*} len
    [[ $1 == */* ]] || { is_ip "$1"; return; }
    len=${1##*/}
    [[ $len =~ ^[0-9]{1,3}$ ]] || return 1
    if is_ipv4 "$addr"; then (( len <= 32 )); elif is_ipv6 "$addr"; then (( len <= 128 )); else return 1; fi
}
is_fqdn() {
    [[ ${#1} -le 253 && $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}
is_hostname() { [[ $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ && ${#1} -le 253 ]]; }
is_email() { [[ ${#1} -le 254 && $1 =~ ^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]]; }

# Lê KEY='valor' de um arquivo sem executá-lo (o arquivo vem de outro host).
read_kv() {
    local file=$1 key=$2 line
    [[ -r $file ]] || return 0
    line=$(grep -E "^${key}='[^']*'$" "$file" | tail -n1 || true)
    [[ -n $line ]] || return 0
    line=${line#*=\'}
    printf '%s' "${line%\'}"
}

pkg_candidate() {
    apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {if ($2 != "(none)") print $2; exit}'
}

backup_once() { [[ -e $1 && ! -e $1.mp-orig ]] && cp -a "$1" "$1.mp-orig"; return 0; }

# Escreve conteúdo (stdin) em destino de forma atômica com modo/dono.
write_file() {
    local dst=$1 mode=$2 owner=$3 tmp
    tmp=$(mktemp)
    cat > "$tmp"
    backup_once "$dst"
    install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$tmp" "$dst"
    rm -f "$tmp"
}

# Renderiza um template de config/ substituindo {{CHAVE}} por TPL[CHAVE].
render() {
    local src=$1 dst=$2 mode=$3 owner=$4 content key
    [[ -r ${APP_DIR}/config/${src} ]] || die "template ausente: config/${src}"
    content=$(<"${APP_DIR}/config/${src}")
    for key in "${!TPL[@]}"; do
        content=${content//"{{${key}}}"/"${TPL[$key]}"}
    done
    if [[ $content =~ \{\{[A-Z0-9_]+\}\} ]]; then
        die "placeholder não resolvido em config/${src}: ${BASH_REMATCH[0]}"
    fi
    printf '%s\n' "$content" | write_file "$dst" "$mode" "$owner"
}

wait_port() {
    local host=$1 port=$2 name=$3
    for _ in $(seq 1 30); do
        if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then return 0; fi
        sleep 1
    done
    die "${name} não respondeu em ${host}:${port}"
}

# ---------------------------------------------------------------------------
# Argumentos e pré-requisitos
# ---------------------------------------------------------------------------
parse_args() {
    while (($#)); do
        case $1 in
            --hostname)    MAIL_HOSTNAME=${2:?}; shift 2 ;;
            --db-env)      DB_ENV_FILE=${2:?}; shift 2 ;;
            --admin-allow) ADMIN_ALLOW=${2:?}; shift 2 ;;
            --acme-email)  ACME_EMAIL=${2:?}; shift 2 ;;
            --admin-email) ADMIN_EMAIL=${2:?}; shift 2 ;;
            --app-dir)     APP_DIR=${2:?}; shift 2 ;;
            --no-rbl)      ENABLE_RBL=0; shift ;;
            -h|--help)     usage; exit 0 ;;
            *) die "opção desconhecida: $1 (use --help)" ;;
        esac
    done
}

preflight() {
    step "Verificações iniciais"
    [[ $EUID -eq 0 ]] || die "execute como root"
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ ${ID:-} == debian && ${VERSION_CODENAME:-} == trixie ]] \
        || die "este script exige Debian 13 (trixie); detectado: ${PRETTY_NAME:-desconhecido}"

    MAIL_HOSTNAME=${MAIL_HOSTNAME,,}
    [[ -n $MAIL_HOSTNAME ]] || die "--hostname é obrigatório (ex.: mail.empresa.com.br)"
    is_fqdn "$MAIL_HOSTNAME" || die "--hostname precisa ser um FQDN válido: $MAIL_HOSTNAME"
    [[ -n $DB_ENV_FILE && -r $DB_ENV_FILE ]] || die "--db-env obrigatório e legível (gerado pelo deploy-db-node.sh)"
    [[ -z $ACME_EMAIL ]] || is_email "$ACME_EMAIL" || die "--acme-email inválido"
    [[ -z $ADMIN_EMAIL ]] || is_email "$ADMIN_EMAIL" || die "--admin-email inválido"
    APP_DIR=$(readlink -f "$APP_DIR")
    [[ -d ${APP_DIR}/config && -f ${APP_DIR}/apache-vhost.conf ]] || die "APP_DIR inválido: ${APP_DIR}"

    # Lista de IPs do painel admin
    if [[ -z $ADMIN_ALLOW ]]; then
        local ssh_ip=${SSH_CONNECTION:-}
        [[ -n $ssh_ip ]] || ssh_ip=${SSH_CLIENT:-}
        ssh_ip=${ssh_ip%% *}
        if [[ -n $ssh_ip ]] && is_ip "$ssh_ip"; then
            ADMIN_ALLOW=$ssh_ip
            log "Painel admin liberado para o IP da sessão SSH: ${ssh_ip}"
        else
            warn "--admin-allow não informado: painel admin acessível apenas via loopback (use um túnel SSH)"
        fi
    fi
    local entry
    ADMIN_ALLOW_LIST=(127.0.0.1 ::1)
    IFS=',' read -r -a _entries <<< "${ADMIN_ALLOW// /}"
    for entry in "${_entries[@]}"; do
        [[ -z $entry ]] && continue
        is_cidr "$entry" || die "--admin-allow: entrada inválida: $entry"
        ADMIN_ALLOW_LIST+=("$entry")
    done

    log "Hostname      : ${MAIL_HOSTNAME}"
    log "Aplicação     : ${APP_DIR}"
    log "Painel admin  : ${ADMIN_ALLOW_LIST[*]}"
}

load_db_env() {
    step "Lendo credenciais do Servidor 2 (${DB_ENV_FILE})"
    DB_HOST=$(read_kv "$DB_ENV_FILE" MP_DB_HOST)
    DB_PORT=$(read_kv "$DB_ENV_FILE" MP_DB_PORT)
    DB_NAME=$(read_kv "$DB_ENV_FILE" MP_DB_NAME)
    DB_APP_USER=$(read_kv "$DB_ENV_FILE" MP_DB_APP_USER)
    DB_APP_PASSWORD=$(read_kv "$DB_ENV_FILE" MP_DB_APP_PASSWORD)
    DB_INGEST_USER=$(read_kv "$DB_ENV_FILE" MP_DB_INGEST_USER)
    DB_INGEST_PASSWORD=$(read_kv "$DB_ENV_FILE" MP_DB_INGEST_PASSWORD)
    DB_POSTFIX_USER=$(read_kv "$DB_ENV_FILE" MP_DB_POSTFIX_USER)
    DB_POSTFIX_PASSWORD=$(read_kv "$DB_ENV_FILE" MP_DB_POSTFIX_PASSWORD)
    DB_TELEMETRY_USER=$(read_kv "$DB_ENV_FILE" MP_DB_TELEMETRY_USER)
    DB_TELEMETRY_PASSWORD=$(read_kv "$DB_ENV_FILE" MP_DB_TELEMETRY_PASSWORD)
    local ca_b64
    ca_b64=$(read_kv "$DB_ENV_FILE" MP_DB_CA_PEM_B64)

    is_ip "$DB_HOST" || is_hostname "$DB_HOST" || die "MP_DB_HOST inválido"
    [[ $DB_PORT =~ ^[0-9]{2,5}$ ]] || die "MP_DB_PORT inválida"
    [[ $DB_NAME =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "MP_DB_NAME inválido"
    local u p
    for u in DB_APP_USER DB_INGEST_USER DB_POSTFIX_USER DB_TELEMETRY_USER; do
        [[ ${!u} =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "MP_${u} inválido"
    done
    for p in DB_APP_PASSWORD DB_INGEST_PASSWORD DB_POSTFIX_PASSWORD DB_TELEMETRY_PASSWORD; do
        [[ ${!p} =~ ^[0-9a-f]{48}$ ]] || die "MP_${p} inválida"
    done
    [[ $ca_b64 =~ ^[A-Za-z0-9+/=]+$ ]] || die "MP_DB_CA_PEM_B64 inválido"

    install -d -m 0755 "$ETC_MP"
    printf '%s' "$ca_b64" | base64 -d | write_file "${ETC_MP}/db-ca.crt" 0644 root:root
    openssl x509 -in "${ETC_MP}/db-ca.crt" -noout 2>/dev/null || die "CA do Servidor 2 inválida"
    log "Servidor 2: ${DB_HOST}:${DB_PORT}/${DB_NAME} (CA: $(openssl x509 -in "${ETC_MP}/db-ca.crt" -noout -subject -nameopt RFC2253 | sed 's/^subject=//'))"
}

# ---------------------------------------------------------------------------
# Pacotes e usuários
# ---------------------------------------------------------------------------
install_packages() {
    step "Instalando pacotes (DEBIAN_FRONTEND=noninteractive)"
    debconf-set-selections <<EOF
postfix postfix/main_mailer_type select No configuration
postfix postfix/mailname string ${MAIL_HOSTNAME}
EOF
    printf '%s\n' "$MAIL_HOSTNAME" > /etc/mailname
    apt-get update -qq
    local pkgs=(
        ca-certificates curl openssl sudo git logrotate nftables iproute2
        apache2
        "php${PHP_VER}-fpm" "php${PHP_VER}-cli" "php${PHP_VER}-pgsql" "php${PHP_VER}-ssh2"
        "php${PHP_VER}-mbstring" "php${PHP_VER}-intl" "php${PHP_VER}-opcache"
        postfix postfix-pgsql postfix-lmdb
        opendkim opendkim-tools
        rspamd redis-server
        fail2ban python3-systemd
        python3 python3-psycopg2 python3-nacl
        postgresql-client
    )
    [[ -n $ACME_EMAIL ]] && pkgs+=(certbot)

    # Rspamd: usa o pacote oficial do Debian; se indisponível nesta release,
    # recorre ao repositório oficial do projeto (rspamd.com, Apache-2.0).
    if [[ -z $(pkg_candidate rspamd) ]]; then
        warn "rspamd indisponível nos repositórios Debian; configurando repositório oficial rspamd.com"
        apt-get install -y -qq --no-install-recommends gnupg curl ca-certificates >/dev/null
        local tmp
        tmp=$(mktemp)
        curl -fsSL --proto '=https' https://rspamd.com/apt-stable/gpg.key -o "$tmp"
        gpg --batch --yes --dearmor -o /usr/share/keyrings/rspamd.gpg "$tmp"
        rm -f "$tmp"
        chmod 0644 /usr/share/keyrings/rspamd.gpg
        printf 'Types: deb\nURIs: https://rspamd.com/apt-stable/\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/rspamd.gpg\n' \
            > /etc/apt/sources.list.d/rspamd.sources
        apt-get update -qq
    fi
    local p unavailable=()
    for p in "${pkgs[@]}"; do
        [[ -n $(pkg_candidate "$p") ]] || unavailable+=("$p")
    done
    (( ${#unavailable[@]} == 0 )) || die "pacotes indisponíveis no APT: ${unavailable[*]}"

    apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "${pkgs[@]}" >/dev/null

    # Extensões PHP obrigatórias
    local mods missing=() m
    mods=$("php${PHP_VER}" -m | tr '[:upper:]' '[:lower:]')
    for m in pgsql pdo_pgsql ssh2 sodium mbstring intl openssl; do
        grep -qx "$m" <<< "$mods" || missing+=("$m")
    done
    (( ${#missing[@]} == 0 )) || die "extensões PHP ausentes: ${missing[*]}"
    log "PHP ${PHP_VER}: pgsql, pdo_pgsql, ssh2, sodium, mbstring, intl, openssl OK"
    python3 -c 'import nacl.public, psycopg2' || die "PyNaCl/psycopg2 indisponíveis"
}

create_users_and_dirs() {
    step "Criando usuários de serviço e diretórios"
    getent group "$APP_USER" >/dev/null || groupadd --system "$APP_USER"
    getent passwd "$APP_USER" >/dev/null || useradd --system --gid "$APP_USER" \
        --home-dir /var/lib/mail-platform --no-create-home --shell /usr/sbin/nologin "$APP_USER"
    getent group "$INGEST_USER" >/dev/null || groupadd --system "$INGEST_USER"
    getent passwd "$INGEST_USER" >/dev/null || useradd --system --gid "$INGEST_USER" \
        --home-dir /var/lib/mail-ingest --no-create-home --shell /usr/sbin/nologin "$INGEST_USER"

    install -d -m 0755 -o root -g root "$ETC_MP"
    install -d -m 0700 -o root -g root "$TLS_DIR"
    install -d -m 0750 -o "$APP_USER" -g "$APP_USER" /var/lib/mail-platform
    install -d -m 0700 -o "$APP_USER" -g "$APP_USER" /var/lib/mail-platform/sessions /var/lib/mail-platform/tmp
    install -d -m 0750 -o "$INGEST_USER" -g "$INGEST_USER" /var/lib/mail-ingest
    install -d -m 0770 -o "$APP_USER" -g adm /var/log/mail-platform
    install -d -m 0700 -o root -g root /var/spool/mail-platform
    install -d -m 0755 /var/www/letsencrypt/.well-known/acme-challenge
    [[ -e /var/log/mail-platform/auth.log ]] || install -m 0640 -o "$APP_USER" -g adm /dev/null /var/log/mail-platform/auth.log
    [[ -e /var/log/postfix.log ]] || install -m 0640 -o root -g adm /dev/null /var/log/postfix.log

    # Código da aplicação: somente leitura para os serviços
    chown -R root:root "$APP_DIR"
    chmod -R u=rwX,go=rX "$APP_DIR"
    find "${APP_DIR}/bin" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} +
}

# ---------------------------------------------------------------------------
# Segredos e arquivos de configuração da aplicação
# ---------------------------------------------------------------------------
get_or_gen_key() {
    local file=$1 key=$2 val
    val=$(read_kv "$file" "$key")
    if [[ $val =~ ^[A-Za-z0-9+/]{43}=$ ]]; then printf '%s' "$val"; else openssl rand -base64 32; fi
}

write_app_config() {
    step "Gerando configuração da aplicação (${ETC_MP})"
    local app_env=${ETC_MP}/app.env
    MASTER_KEY=$(get_or_gen_key "$app_env" MP_APP_MASTER_KEY)
    HMAC_KEY=$(get_or_gen_key "$app_env" MP_SUBJECT_HMAC_KEY)
    local admin_hash
    admin_hash=$(read_kv "$app_env" MP_ADMIN_PASSWORD_HASH)
    if [[ $admin_hash != \$argon2id\$* ]]; then
        ADMIN_PASSWORD_PLAIN=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
        admin_hash=$(MP_PW="$ADMIN_PASSWORD_PLAIN" "php${PHP_VER}" -r 'echo password_hash(getenv("MP_PW"), PASSWORD_ARGON2ID, ["memory_cost" => 65536, "time_cost" => 4, "threads" => 1]);')
        [[ $admin_hash == \$argon2id\$* ]] || die "falha ao gerar hash Argon2id do admin"
        printf 'Painel admin: https://%s/admin.html\nUsuário: admin\nSenha: %s\n' \
            "$MAIL_HOSTNAME" "$ADMIN_PASSWORD_PLAIN" | write_file /root/mail-platform-admin.txt 0600 root:root
    fi

    write_file "$app_env" 0640 "root:${APP_USER}" <<EOF
# Mail Platform — configuração do backend PHP (gerado por ${SCRIPT_NAME})
# CONFIDENCIAL. MP_APP_MASTER_KEY cifra chaves SSH/DKIM no banco: NÃO PERCA.
MP_ENV='production'
MP_HOSTNAME='${MAIL_HOSTNAME}'
MP_APP_DIR='${APP_DIR}'
MP_DB_HOST='${DB_HOST}'
MP_DB_PORT='${DB_PORT}'
MP_DB_NAME='${DB_NAME}'
MP_DB_USER='${DB_APP_USER}'
MP_DB_PASSWORD='${DB_APP_PASSWORD}'
MP_DB_SSLMODE='verify-full'
MP_DB_SSLROOTCERT='${ETC_MP}/db-ca.crt'
MP_APP_MASTER_KEY='${MASTER_KEY}'
MP_SUBJECT_HMAC_KEY='${HMAC_KEY}'
MP_ADMIN_USER='admin'
MP_ADMIN_PASSWORD_HASH='${admin_hash}'
MP_SMTP_HOST='127.0.0.1'
MP_SMTP_PORT='587'
MP_AUTH_LOG='/var/log/mail-platform/auth.log'
MP_DKIM_CTL='/usr/local/sbin/mp-dkim-ctl'
MP_F2B_CTL='/usr/local/sbin/mp-f2b-ctl'
EOF

    write_file "${ETC_MP}/ingest.conf" 0640 "root:${INGEST_USER}" <<EOF
# Mail Platform — configuração do mail-ingest.py (gerado por ${SCRIPT_NAME})
MP_DB_HOST='${DB_HOST}'
MP_DB_PORT='${DB_PORT}'
MP_DB_NAME='${DB_NAME}'
MP_DB_USER='${DB_INGEST_USER}'
MP_DB_PASSWORD='${DB_INGEST_PASSWORD}'
MP_DB_SSLMODE='verify-full'
MP_DB_SSLROOTCERT='${ETC_MP}/db-ca.crt'
MP_SUBJECT_HMAC_KEY='${HMAC_KEY}'
MP_MAX_MESSAGE_BYTES='52428800'
EOF

    write_file "${ETC_MP}/telemetry.conf" 0600 root:root <<EOF
# Mail Platform — telemetria Fail2ban -> security_events (gerado por ${SCRIPT_NAME})
MP_DB_HOST='${DB_HOST}'
MP_DB_PORT='${DB_PORT}'
MP_DB_NAME='${DB_NAME}'
MP_DB_USER='${DB_TELEMETRY_USER}'
MP_DB_PASSWORD='${DB_TELEMETRY_PASSWORD}'
MP_DB_SSLMODE='verify-full'
MP_DB_SSLROOTCERT='${ETC_MP}/db-ca.crt'
EOF
}

setup_tls() {
    step "Certificado TLS (Apache + Postfix)"
    if [[ -s ${TLS_DIR}/fullchain.pem && -s ${TLS_DIR}/privkey.pem ]] \
       && openssl x509 -in "${TLS_DIR}/fullchain.pem" -noout -checkend 86400 >/dev/null 2>&1 \
       && openssl x509 -in "${TLS_DIR}/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | grep -qF "DNS:${MAIL_HOSTNAME}"; then
        log "Certificado existente válido para ${MAIL_HOSTNAME}"
        return 0
    fi
    log "Gerando certificado autoassinado provisório (ECDSA P-256) para ${MAIL_HOSTNAME}"
    rm -f "${TLS_DIR}/fullchain.pem" "${TLS_DIR}/privkey.pem"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
        -keyout "${TLS_DIR}/privkey.pem" -out "${TLS_DIR}/fullchain.pem" \
        -subj "/CN=${MAIL_HOSTNAME}" -addext "subjectAltName=DNS:${MAIL_HOSTNAME}" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
    chmod 0600 "${TLS_DIR}/privkey.pem"
    chmod 0644 "${TLS_DIR}/fullchain.pem"
}

# ---------------------------------------------------------------------------
# Postfix
# ---------------------------------------------------------------------------
configure_postfix() {
    step "Configurando Postfix (domínios virtuais no PostgreSQL + pipe mail-ingest.py)"
    local default_env inet_proto=all rbl=""
    default_env=$(postconf -d -h import_environment)
    [[ -s /proc/net/if_inet6 ]] || inet_proto=ipv4
    (( ENABLE_RBL )) && rbl="reject_rbl_client zen.spamhaus.org=127.0.0.[2..11],"

    TPL[MAIL_DOMAIN]=${MAIL_HOSTNAME#*.}
    TPL[INET_PROTOCOLS]=$inet_proto
    TPL[TLS_CERT]=${TLS_DIR}/fullchain.pem
    TPL[TLS_KEY]=${TLS_DIR}/privkey.pem
    TPL[IMPORT_ENVIRONMENT]=$default_env
    TPL[DB_CA_FILE]=${ETC_MP}/db-ca.crt
    TPL[RBL_RESTRICTIONS]=$rbl
    TPL[DB_HOST]=$DB_HOST
    TPL[DB_PORT]=$DB_PORT
    TPL[DB_NAME]=$DB_NAME
    TPL[DB_POSTFIX_USER]=$DB_POSTFIX_USER
    TPL[DB_POSTFIX_PASSWORD]=$DB_POSTFIX_PASSWORD

    render postfix/main.cf /etc/postfix/main.cf 0644 root:root
    render postfix/master.cf /etc/postfix/master.cf 0644 root:root
    install -d -m 0750 -o root -g postfix /etc/postfix/pgsql
    render postfix/pgsql-virtual-domains.cf /etc/postfix/pgsql/virtual_domains.cf 0640 root:postfix
    render postfix/pgsql-virtual-mailboxes.cf /etc/postfix/pgsql/virtual_mailboxes.cf 0640 root:postfix

    # Aliases do sistema (root/postmaster/abuse)
    touch /etc/aliases
    local tmp
    tmp=$(mktemp)
    grep -Ev '^(postmaster|abuse|hostmaster|webmaster|root):' /etc/aliases > "$tmp" || true
    {
        echo "postmaster: root"
        echo "abuse: root"
        echo "hostmaster: root"
        echo "webmaster: root"
        if [[ -n $ADMIN_EMAIL ]]; then echo "root: ${ADMIN_EMAIL}"; fi
    } >> "$tmp"
    install -m 0644 "$tmp" /etc/aliases
    rm -f "$tmp"
    newaliases

    install_ingest_worker

    postfix check || die "postfix check falhou"
    systemctl enable --quiet postfix
    systemctl restart postfix
}

install_ingest_worker() {
    local dst=/usr/local/bin/mail-ingest.py
    if [[ -f ${APP_DIR}/bin/mail-ingest.py ]]; then
        log "Instalando ${dst} a partir da aplicação"
        install -m 0755 -o root -g root "${APP_DIR}/bin/mail-ingest.py" "$dst"
    else
        # A Entrega 2 traz o worker criptográfico. Até lá, este stub mantém as
        # mensagens na fila do Postfix (EX_TEMPFAIL) — nenhuma é perdida nem
        # gravada em texto plano.
        warn "bin/mail-ingest.py ainda não existe; instalando stub que adia (tempfail) as entregas"
        write_file "$dst" 0755 root:root <<'EOF'
#!/usr/bin/python3 -I
# Mail Platform :: stub temporário do pipe de ingestão.
# Mantém as mensagens na fila do Postfix até o worker real ser instalado.
import sys
sys.stdin.buffer.read()
sys.stderr.write("4.3.0 mail-ingest.py ainda não instalado; mensagem mantida na fila\n")
sys.exit(75)  # EX_TEMPFAIL
EOF
    fi
}

# ---------------------------------------------------------------------------
# OpenDKIM
# ---------------------------------------------------------------------------
configure_opendkim() {
    step "Configurando OpenDKIM (assinatura, inet:8891@127.0.0.1)"
    install -d -m 0750 -o opendkim -g opendkim /etc/opendkim /etc/opendkim/keys
    render opendkim/opendkim.conf /etc/opendkim.conf 0644 root:root
    render opendkim/TrustedHosts /etc/opendkim/TrustedHosts 0640 root:opendkim
    local f
    for f in KeyTable SigningTable; do
        [[ -e /etc/opendkim/$f ]] || printf '# Gerado por mp-dkim-ctl — não edite manualmente.\n' \
            | write_file "/etc/opendkim/$f" 0640 root:opendkim
    done

    # Debian: o socket padrão vem de /etc/default/opendkim; forçamos o inet.
    if [[ -f /etc/default/opendkim ]]; then
        backup_once /etc/default/opendkim
        sed -i -E '/^SOCKET=/d' /etc/default/opendkim
        echo 'SOCKET="inet:8891@127.0.0.1"' >> /etc/default/opendkim
    fi
    write_file /etc/systemd/system/opendkim.service.d/zz-mail-platform.conf 0644 root:root <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/opendkim -x /etc/opendkim.conf -P /run/opendkim/opendkim.pid
RuntimeDirectory=opendkim
RuntimeDirectoryMode=0750
EOF
    systemctl daemon-reload
    systemctl enable --quiet opendkim
    systemctl restart opendkim
    wait_port 127.0.0.1 8891 OpenDKIM
}

# ---------------------------------------------------------------------------
# Rspamd + Redis
# ---------------------------------------------------------------------------
configure_rspamd() {
    step "Configurando Rspamd (milter 127.0.0.1:11332) + Redis local"
    systemctl enable --quiet redis-server
    systemctl restart redis-server

    local hash_file=${ETC_MP}/rspamd-controller.hash hash pw
    if [[ -s $hash_file ]]; then
        hash=$(<"$hash_file")
    else
        pw=$(openssl rand -hex 24)
        hash=$(rspamadm pw -p "$pw" | tail -n1)
        printf '%s' "$hash" | write_file "$hash_file" 0600 root:root
    fi
    TPL[RSPAMD_PASSWORD_HASH]=$hash

    local f
    for f in "${APP_DIR}"/config/rspamd/local.d/*; do
        render "rspamd/local.d/$(basename "$f")" "/etc/rspamd/local.d/$(basename "$f")" 0644 root:root
    done
    rspamadm configtest >/dev/null || die "rspamadm configtest falhou"
    systemctl enable --quiet rspamd
    systemctl restart rspamd
    wait_port 127.0.0.1 11332 "Rspamd milter"
}

# ---------------------------------------------------------------------------
# PHP-FPM + Apache2
# ---------------------------------------------------------------------------
configure_php() {
    step "Configurando PHP ${PHP_VER}-FPM (pool dedicado ${APP_USER})"
    render php/fpm-pool.conf "/etc/php/${PHP_VER}/fpm/pool.d/mail-platform.conf" 0644 root:root
    render php/99-mail-platform.ini "/etc/php/${PHP_VER}/fpm/conf.d/99-mail-platform.ini" 0644 root:root
    render php/99-mail-platform.ini "/etc/php/${PHP_VER}/cli/conf.d/99-mail-platform.ini" 0644 root:root
    if [[ -f /etc/php/${PHP_VER}/fpm/pool.d/www.conf ]]; then
        mv "/etc/php/${PHP_VER}/fpm/pool.d/www.conf" "/etc/php/${PHP_VER}/fpm/pool.d/www.conf.disabled"
    fi
    "php-fpm${PHP_VER}" -t >/dev/null 2>&1 || { "php-fpm${PHP_VER}" -t; die "configuração PHP-FPM inválida"; }
    systemctl enable --quiet "php${PHP_VER}-fpm"
    systemctl restart "php${PHP_VER}-fpm"
}

configure_apache() {
    step "Configurando Apache2 (mpm_event, TLS 1.3, CSP, HSTS)"
    a2dismod -q -f mpm_prefork mpm_worker "php${PHP_VER}" >/dev/null 2>&1 || true
    a2enmod -q mpm_event ssl headers rewrite proxy proxy_fcgi setenvif http2 dir alias >/dev/null
    a2disconf -q "php${PHP_VER}-fpm" >/dev/null 2>&1 || true

    write_file /etc/apache2/conf-available/mail-platform-vars.conf 0644 root:root <<EOF
# Gerado por ${SCRIPT_NAME} — variáveis usadas em sites-available/mail-platform.conf
Define MP_SERVER_NAME ${MAIL_HOSTNAME}
Define MP_APP_DIR ${APP_DIR}
Define MP_TLS_CERT ${TLS_DIR}/fullchain.pem
Define MP_TLS_KEY ${TLS_DIR}/privkey.pem
Define MP_FPM_SOCKET ${FPM_SOCKET}
EOF
    write_file /etc/apache2/mail-platform/admin-allow.conf 0644 root:root <<EOF
# Gerado por ${SCRIPT_NAME} — IPs/CIDRs com acesso ao painel admin
Require ip ${ADMIN_ALLOW_LIST[*]}
EOF
    render apache/zz-mail-platform-hardening.conf /etc/apache2/conf-available/zz-mail-platform-hardening.conf 0644 root:root
    install -m 0644 -o root -g root "${APP_DIR}/apache-vhost.conf" /etc/apache2/sites-available/mail-platform.conf

    a2enconf -q mail-platform-vars zz-mail-platform-hardening >/dev/null
    a2dissite -q 000-default default-ssl >/dev/null 2>&1 || true
    a2ensite -q mail-platform >/dev/null
    apache2ctl configtest 2>&1 | grep -v '^Syntax OK$' | sed 's/^/[deploy-mail] apache: /' || true
    apache2ctl -t >/dev/null 2>&1 || die "configuração do Apache inválida"
    systemctl enable --quiet apache2
    systemctl restart apache2
}

setup_acme() {
    [[ -n $ACME_EMAIL ]] || return 0
    step "Emitindo certificado Let's Encrypt para ${MAIL_HOSTNAME} (webroot)"
    if certbot certonly --webroot -w /var/www/letsencrypt -d "$MAIL_HOSTNAME" \
        --email "$ACME_EMAIL" --agree-tos --non-interactive --keep-until-expiring \
        --deploy-hook /usr/local/sbin/mp-tls-deploy-hook; then
        ln -sfn "/etc/letsencrypt/live/${MAIL_HOSTNAME}/fullchain.pem" "${TLS_DIR}/fullchain.pem"
        ln -sfn "/etc/letsencrypt/live/${MAIL_HOSTNAME}/privkey.pem" "${TLS_DIR}/privkey.pem"
        systemctl reload apache2
        systemctl reload postfix
        log "Certificado Let's Encrypt ativo (renovação automática via certbot.timer)"
    else
        warn "certbot falhou (DNS A/AAAA de ${MAIL_HOSTNAME} aponta para este servidor? porta 80 aberta?). Mantendo certificado autoassinado."
    fi
}

# ---------------------------------------------------------------------------
# Fail2ban + helpers
# ---------------------------------------------------------------------------
install_helpers() {
    step "Instalando utilitários (mp-security-event, mp-f2b-ctl, mp-dkim-ctl)"
    local h
    for h in mp-security-event mp-f2b-ctl mp-dkim-ctl mp-tls-deploy-hook; do
        install -m 0755 -o root -g root "${APP_DIR}/bin/helpers/${h}" "/usr/local/sbin/${h}"
    done
    write_file /etc/sudoers.d/mail-platform 0440 root:root <<EOF
# Gerado por ${SCRIPT_NAME}: o backend PHP só pode executar os wrappers validados.
Defaults:${APP_USER} !requiretty, env_reset, secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
${APP_USER} ALL=(root) NOPASSWD: /usr/local/sbin/mp-f2b-ctl, /usr/local/sbin/mp-dkim-ctl
EOF
    visudo -cf /etc/sudoers.d/mail-platform >/dev/null || die "sudoers inválido"
}

configure_fail2ban() {
    step "Configurando Fail2ban (sshd, postfix, postfix-sasl, postfix-rbl, apache-auth + telemetria)"
    local ssh_port ignore=() e
    ssh_port=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}' || true)
    [[ $ssh_port =~ ^[0-9]+$ ]] || ssh_port=22
    is_ip "$DB_HOST" && ignore+=("$DB_HOST")
    for e in "${ADMIN_ALLOW_LIST[@]}"; do
        [[ $e == 127.0.0.1 || $e == ::1 ]] || ignore+=("$e")
    done

    TPL[SSH_PORT]=$ssh_port
    TPL[IGNORE_IPS]="${ignore[*]}"
    render fail2ban/jail.local /etc/fail2ban/jail.local 0644 root:root
    render fail2ban/action.d/mail-platform-timescale.conf /etc/fail2ban/action.d/mail-platform-timescale.conf 0644 root:root
    render fail2ban/filter.d/mail-platform-auth.conf /etc/fail2ban/filter.d/mail-platform-auth.conf 0644 root:root
    [[ -e /var/log/apache2/mail-platform-error.log ]] || install -m 0640 -o root -g adm /dev/null /var/log/apache2/mail-platform-error.log

    fail2ban-client -t >/dev/null 2>&1 || { fail2ban-client -t || true; die "configuração do Fail2ban inválida"; }
    systemctl enable --quiet fail2ban
    systemctl restart fail2ban
    sleep 2
    log "Jails ativas: $(fail2ban-client status | sed -n 's/^.*Jail list:[[:space:]]*//p')"
}

configure_logrotate() {
    write_file /etc/logrotate.d/mail-platform 0644 root:root <<EOF
/var/log/postfix.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}

/var/log/mail-platform/*.log {
    su ${APP_USER} adm
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
}

# ---------------------------------------------------------------------------
# Verificações finais
# ---------------------------------------------------------------------------
verify_db_connectivity() {
    step "Validando conexão TLS (verify-full) com o Servidor 2"
    local ok=1 out
    if out=$(PGPASSWORD=$DB_POSTFIX_PASSWORD PGSSLMODE=verify-full PGSSLROOTCERT="${ETC_MP}/db-ca.crt" PGCONNECT_TIMEOUT=5 \
        psql -X -q -h "$DB_HOST" -p "$DB_PORT" -U "$DB_POSTFIX_USER" -d "$DB_NAME" -At \
        -c "SELECT 'dominios=' || count(*) FROM mail_domains" 2>&1); then
        log "Postfix -> PostgreSQL OK (${out})"
    else
        ok=0; warn "role postfix não conectou: ${out}"
    fi
    if out=$(PGPASSWORD=$DB_INGEST_PASSWORD PGSSLMODE=verify-full PGSSLROOTCERT="${ETC_MP}/db-ca.crt" PGCONNECT_TIMEOUT=5 \
        psql -X -q -h "$DB_HOST" -p "$DB_PORT" -U "$DB_INGEST_USER" -d "$DB_NAME" -At \
        -c "SELECT 'tls=' || ssl || ' ' || version FROM pg_stat_ssl WHERE pid = pg_backend_pid()" 2>&1); then
        log "Ingestão -> PostgreSQL OK (${out})"
    else
        ok=0; warn "role de ingestão não conectou: ${out}"
    fi
    out=$(PGSSLMODE=verify-full PGSSLROOTCERT="${ETC_MP}/db-ca.crt" PGCONNECT_TIMEOUT=5 \
        postmap -q "nao-existe.invalid" pgsql:/etc/postfix/pgsql/virtual_domains.cf 2>&1 || true)
    if [[ -z $out ]]; then
        log "Lookup pgsql do Postfix OK"
    else
        ok=0; warn "lookup pgsql do Postfix: ${out}"
    fi
    if (( ok )); then
        /usr/local/sbin/mp-security-event --service ssh_deploy --action DEPLOY_OK \
            --details "mail_frontend ${MAIL_HOSTNAME}" || true
    else
        warn "Verifique: IP deste servidor autorizado no deploy-db-node.sh (--allowed-ip) e porta ${DB_PORT} liberada"
    fi
}

summary() {
    local ip4
    ip4=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)
    step "Deploy do Servidor 1 concluído"
    log "Webmail     : https://${MAIL_HOSTNAME}/webmail.html"
    log "Painel admin: https://${MAIL_HOSTNAME}/admin.html (IPs: ${ADMIN_ALLOW_LIST[*]})"
    if [[ -n $ADMIN_PASSWORD_PLAIN ]]; then
        log "Credenciais iniciais do admin gravadas em /root/mail-platform-admin.txt (0600)"
    fi
    log "DNS necessário para o servidor:"
    log "  ${MAIL_HOSTNAME}.  A    ${ip4:-<IPv4 deste servidor>}"
    log "  PTR/rDNS de ${ip4:-<IPv4>} -> ${MAIL_HOSTNAME} (configure no provedor do IP)"
    log "  Portas de entrada: 25/tcp (SMTP), 80/tcp (ACME), 443/tcp (HTTPS)"
    log "Os registros MX/SPF/DKIM/DMARC de cada domínio são gerados no painel admin."
    printf 'MP_DEPLOY_RESULT=DEPLOY_OK role=mail_frontend host=%s\n' "$MAIL_HOSTNAME"
}

init_templates() {
    TPL[MAIL_HOSTNAME]=$MAIL_HOSTNAME
    TPL[APP_DIR]=$APP_DIR
    TPL[FPM_SOCKET]=$FPM_SOCKET
}

main() {
    parse_args "$@"
    preflight
    init_templates
    load_db_env
    install_packages
    create_users_and_dirs
    write_app_config
    setup_tls
    install_helpers
    configure_postfix
    configure_opendkim
    configure_rspamd
    configure_php
    configure_apache
    setup_acme
    configure_fail2ban
    configure_logrotate
    verify_db_connectivity
    summary
}

main "$@"
