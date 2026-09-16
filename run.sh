#!/usr/bin/env bash
# run.sh
# Uso:
#   ./run.sh              cria novo container APP_NAME_N
#   ./run.sh --reboot N   rebuilda e recria APP_NAME_N preservando a porta se possível
#   ./run.sh --remove N   remove APP_NAME_N
#   ./run.sh --list       lista containers do app

set -Eeuo pipefail

# ==========================================
# Config
# ==========================================

APP_PORT="${APP_PORT:-8000}"
BUILD_LOG="${BUILD_LOG:-./docker-build.log}"

# Usa docker direto se o usuário tiver permissão.
# Caso contrário, usa sudo docker.
if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    DOCKER=(sudo docker)
fi

# ==========================================
# Funções auxiliares
# ==========================================

die() {
    echo "❌ $*" >&2
    exit 1
}

source_env() {
    [[ -f .env ]] || die "Arquivo .env não encontrado"

    set -a
    source .env
    set +a

    [[ -n "${APP_NAME:-}" ]] || die "APP_NAME não definido no .env"
}

container_name() {
    echo "${APP_NAME}_$1"
}

image_name() {
    echo "${APP_NAME}:$1"
}

porta_em_uso() {
    local porta="$1"

    if command -v ss >/dev/null 2>&1; then
        ss -ltn | awk '{print $4}' | grep -qE "[:.]${porta}$"
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i :"$porta" >/dev/null 2>&1
    else
        "${DOCKER[@]}" ps --format '{{.Ports}}' | grep -q ":${porta}->"
    fi
}

proxima_porta_livre() {
    local porta

    for _ in {1..100}; do
        porta=$((RANDOM % 50000 + 10000))

        if ! porta_em_uso "$porta"; then
            echo "$porta"
            return 0
        fi
    done

    die "Não consegui encontrar uma porta livre"
}

porta_do_container() {
    local nome="$1"

    "${DOCKER[@]}" port "$nome" "$APP_PORT/tcp" 2>/dev/null \
        | head -n1 \
        | sed -E 's/.*:([0-9]+)$/\1/'
}

proximo_numero() {
    local num=1

    while "${DOCKER[@]}" ps -a --format '{{.Names}}' | grep -qx "${APP_NAME}_${num}"; do
        num=$((num + 1))
    done

    echo "$num"
}

container_existe() {
    local nome="$1"

    "${DOCKER[@]}" ps -a --format '{{.Names}}' | grep -qx "$nome"
}

container_rodando() {
    local nome="$1"

    "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx "$nome"
}

build_image() {
    local imagem="$1"

    echo "🏗️ Build da imagem: $imagem"

    if ! "${DOCKER[@]}" build --pull --no-cache -t "$imagem" . > "$BUILD_LOG" 2>&1; then
        echo "❌ Build falhou. Últimas linhas:"
        tail -40 "$BUILD_LOG"
        exit 1
    fi
}

remove_container() {
    local nome="$1"

    if container_existe "$nome"; then
        echo "🧹 Removendo container antigo: $nome"
        "${DOCKER[@]}" rm -f "$nome" >/dev/null
    else
        echo "ℹ️ Container não existe: $nome"
    fi
}

run_container() {
    local nome="$1"
    local imagem="$2"
    local porta="$3"

    echo "🐳 Subindo container: $nome"
    echo "🌐 Porta: $porta -> $APP_PORT"

    "${DOCKER[@]}" run -d \
        --name "$nome" \
        --restart unless-stopped \
        --env-file .env \
        -p "${porta}:${APP_PORT}" \
        "$imagem" >/dev/null

    echo "✅ Rodando: http://localhost:$porta"
}

# ==========================================
# Modos
# ==========================================

modo_novo() {
    source_env

    local numero nome imagem porta

    numero="$(proximo_numero)"
    nome="$(container_name "$numero")"
    imagem="$(image_name "$numero")"
    porta="$(proxima_porta_livre)"

    echo "🚀 Novo container: $nome"

    build_image "$imagem"
    run_container "$nome" "$imagem" "$porta"
}

modo_reboot() {
    local numero="$1"

    source_env

    local nome imagem porta_antiga porta_nova porta_final

    nome="$(container_name "$numero")"
    imagem="$(image_name "$numero")"

    echo "🔄 Atualizando container: $nome"

    porta_antiga="$(porta_do_container "$nome" || true)"

    if [[ -n "${porta_antiga:-}" ]]; then
        porta_final="$porta_antiga"
        echo "📌 Preservando porta antiga: $porta_final"
    else
        porta_final="$(proxima_porta_livre)"
        echo "📌 Usando nova porta: $porta_final"
    fi

    remove_container "$nome"

    echo "🗑️ Removendo imagem antiga, se existir..."
    "${DOCKER[@]}" rmi -f "$imagem" >/dev/null 2>&1 || true

    build_image "$imagem"
    run_container "$nome" "$imagem" "$porta_final"
}

modo_remove() {
    local numero="$1"

    source_env

    local nome imagem

    nome="$(container_name "$numero")"
    imagem="$(image_name "$numero")"

    remove_container "$nome"

    echo "🗑️ Removendo imagem: $imagem"
    "${DOCKER[@]}" rmi -f "$imagem" >/dev/null 2>&1 || true

    echo "✅ Removido: $nome"
}

modo_list() {
    source_env

    echo "📦 Containers de $APP_NAME:"
    "${DOCKER[@]}" ps -a \
        --filter "name=^/${APP_NAME}_[0-9]+$" \
        --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}'
}

# ==========================================
# Main
# ==========================================

case "${1:-}" in
    "")
        modo_novo
        ;;

    --reboot)
        [[ "${2:-}" =~ ^[0-9]+$ ]] || die "Uso: $0 --reboot NUMERO"
        modo_reboot "$2"
        ;;

    --remove)
        [[ "${2:-}" =~ ^[0-9]+$ ]] || die "Uso: $0 --remove NUMERO"
        modo_remove "$2"
        ;;

    --list)
        modo_list
        ;;

    *)
        echo "Uso:"
        echo "  $0              cria novo container"
        echo "  $0 --reboot N   rebuilda e recria container N"
        echo "  $0 --remove N   remove container N"
        echo "  $0 --list       lista containers do app"
        exit 1
        ;;
esac