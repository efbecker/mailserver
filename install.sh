#!/usr/bin/env bash
# shellcheck disable=SC1091
# =============================================================================
# Mail Platform :: install.sh — deploy da aplicação via curl (Debian 13)
#
# Servidor 2 (PostgreSQL 17 + TimescaleDB):
#   curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
#     | sudo bash -s -- --role db --allowed-ip <IP_DO_SERVIDOR_1>
#
# Servidor 1 (Apache/PHP, Postfix, OpenDKIM, Rspamd, Fail2ban):
#   scp root@<IP_DO_SERVIDOR_2>:/root/mail-platform-db-credentials.env /root/
#   curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
#     | sudo bash -s -- --role mail --hostname mail.empresa.com.br \
#         --db-env /root/mail-platform-db-credentials.env \
#         --acme-email admin@empresa.com.br --admin-allow 203.0.113.10
#
# Tudo em um único host (laboratório / pequeno porte):
#   curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
#     | sudo bash -s -- --role all --hostname mail.empresa.com.br
#
# Opções do instalador (as demais são repassadas ao script de deploy):
#   --role db|mail|all   Papel deste servidor (obrigatório)
#   --ref REF            Branch/tag do repositório (padrão: main)
#   --repo URL           Repositório git (padrão: https://github.com/efbecker/mailserver.git)
#   --dir DIR            Destino da aplicação (padrão: /var/www/mail-platform;
#                        no papel "db": /opt/mail-platform)
#   --no-update          Usa o checkout existente sem buscar atualizações
#   -h | --help          Ajuda
#
# Reexecutar o mesmo comando atualiza o código para a última versão do REF e
# reaplica o deploy (os scripts são idempotentes e preservam chaves/senhas).
# =============================================================================

# Todo o script está dentro de main(): se o download via curl for
# interrompido no meio, nada é executado pela metade.
main() {
    set -Eeuo pipefail
    umask 022
    export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8

    local role="" ref="${MP_REF:-main}" repo="${MP_REPO:-https://github.com/efbecker/mailserver.git}"
    local dir="" update=1
    local -a passthrough=()

    log()  { printf '[install] %s\n' "$*"; }
    die()  { printf '[install] ERRO: %s\n' "$*" >&2; exit 1; }
    usage() {
        cat <<'EOF'
Mail Platform — instalador via curl (Debian 13)

  curl -fsSL https://raw.githubusercontent.com/efbecker/mailserver/main/install.sh \
    | sudo bash -s -- --role <db|mail|all> [opções]

Opções do instalador:
  --role db|mail|all   Papel deste servidor (obrigatório)
  --ref REF            Branch/tag do repositório (padrão: main)
  --repo URL           Repositório git
  --dir DIR            Destino (padrão: /var/www/mail-platform; papel db: /opt/mail-platform)
  --no-update          Não atualiza um checkout existente

Papel db   -> bin/deploy-db-node.sh   (ex.: --allowed-ip <IP do Servidor 1>)
Papel mail -> bin/deploy-mail-node.sh (ex.: --hostname <fqdn> --db-env <arquivo>)
Papel all  -> ambos no mesmo host     (ex.: --hostname <fqdn>)
Use "--role db --help" ou "--role mail --help" para ver as opções de cada deploy.
EOF
    }

    while (($#)); do
        case $1 in
            --role)      role=${2:-}; shift 2 ;;
            --ref)       ref=${2:-}; shift 2 ;;
            --repo)      repo=${2:-}; shift 2 ;;
            --dir)       dir=${2:-}; shift 2 ;;
            --no-update) update=0; shift ;;
            -h|--help)
                if [[ -z $role ]]; then usage; exit 0; fi
                passthrough+=("$1"); shift ;;
            *)           passthrough+=("$1"); shift ;;
        esac
    done

    [[ $role == db || $role == mail || $role == all ]] || { usage; die "--role deve ser db, mail ou all"; }
    [[ $EUID -eq 0 ]] || die "execute como root (ex.: curl ... | sudo bash -s -- --role ${role})"
    [[ -r /etc/os-release ]] || die "/etc/os-release ausente"
    local os_id os_codename os_pretty
    os_id=$(. /etc/os-release && printf '%s' "${ID:-}")
    os_codename=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
    os_pretty=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")
    [[ $os_id == debian && $os_codename == trixie ]] || die "requer Debian 13 (trixie); detectado: ${os_pretty:-desconhecido}"
    [[ $ref =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || die "--ref inválido"
    [[ $repo == https://* && $repo != *[[:space:]]* ]] || die "--repo deve ser uma URL https"

    if [[ -z $dir ]]; then
        if [[ $role == db ]]; then dir=/opt/mail-platform; else dir=/var/www/mail-platform; fi
    fi
    [[ $dir == /* && $dir != / ]] || die "--dir deve ser um caminho absoluto"

    log "Papel: ${role} | repositório: ${repo} (${ref}) | destino: ${dir}"

    # ---- Dependências mínimas do instalador --------------------------------
    if ! command -v git >/dev/null 2>&1; then
        log "Instalando git"
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends git ca-certificates >/dev/null
    fi

    # ---- Código da aplicação ------------------------------------------------
    if [[ -d ${dir}/.git ]]; then
        if (( update )); then
            log "Atualizando checkout existente em ${dir}"
            git -C "$dir" remote set-url origin "$repo"
            git -C "$dir" fetch --quiet --depth 1 origin "$ref"
            git -C "$dir" reset --quiet --hard FETCH_HEAD
            git -C "$dir" clean -qfd
        else
            log "Usando checkout existente (--no-update)"
        fi
    else
        if [[ -e $dir ]] && [[ -n $(ls -A "$dir" 2>/dev/null) ]]; then
            die "${dir} já existe e não é um checkout git; mova-o ou use --dir"
        fi
        log "Clonando ${repo} (${ref}) em ${dir}"
        install -d -m 0755 "$(dirname "$dir")"
        git clone --quiet --depth 1 --branch "$ref" "$repo" "$dir"
    fi
    log "Versão: $(git -C "$dir" log -1 --format='%h %s (%cd)' --date=short)"
    chmod 0755 "${dir}/bin/"*.sh

    # ---- Deploy --------------------------------------------------------------
    case $role in
        db)
            exec "${dir}/bin/deploy-db-node.sh" --schema "${dir}/sql/schema_timescaledb.sql" "${passthrough[@]}"
            ;;
        mail)
            exec "${dir}/bin/deploy-mail-node.sh" --app-dir "$dir" "${passthrough[@]}"
            ;;
        all)
            local creds=/root/mail-platform-db-credentials.env
            log "Instalação all-in-one: PostgreSQL + TimescaleDB acessível apenas por 127.0.0.1"
            "${dir}/bin/deploy-db-node.sh" --schema "${dir}/sql/schema_timescaledb.sql" \
                --allowed-ip 127.0.0.1 --advertise-host 127.0.0.1 --output "$creds"
            exec "${dir}/bin/deploy-mail-node.sh" --app-dir "$dir" --db-env "$creds" "${passthrough[@]}"
            ;;
    esac
}

main "$@"
