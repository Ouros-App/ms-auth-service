#!/bin/bash

# Função para mostrar loading
show_loading() {
    local pid=$1
    local message=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % ${#spin} ))
        printf "\r%s ${spin:$i:1}" "$message"
        sleep 0.1
    done
    printf "\r"
}

# Função para feedback colorido
color_echo() {
    local color=$1
    local message=$2
    case $color in
        "green") echo -e "\033[0;32m$message\033[0m" ;;
        "red") echo -e "\033[0;31m$message\033[0m" ;;
        "yellow") echo -e "\033[1;33m$message\033[0m" ;;
        "blue") echo -e "\033[0;34m$message\033[0m" ;;
        "cyan") echo -e "\033[0;36m$message\033[0m" ;;
        *) echo "$message" ;;
    esac
}

detectar_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
    else
        color_echo "red" "Docker Compose nao encontrado. Instale 'docker compose' ou 'docker-compose'."
        exit 1
    fi
}

# Help
show_help() {
    echo "Uso: $0 [--reboot NUMERO]"
    echo ""
    echo "Opções:"
    echo "  (sem argumentos)   Builda a imagem e sobe uma nova instância com número incremental"
    echo "  --reboot NUMERO    Para, remove e rebuilda a instância com o número especificado"
    echo "  -h, --help         Mostra esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0                 # Sobe nova instância (ex: minha_app_1, minha_app_2, ...)"
    echo "  $0 --reboot 1      # Rebuilda do zero a instância minha_app_1"
}

# ─────────────────────────────────────────
# Funções principais
# ─────────────────────────────────────────

carregar_env() {
    color_echo "blue" "📁 Verificando configurações..."
    if [ ! -f .env ]; then
        color_echo "red" "❌ Arquivo .env não encontrado!"
        exit 1
    fi

    # Parser seguro: só aceita linhas no formato CHAVE=VALOR, ignora comentários e texto solto
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# || ! "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] && continue
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        export "$key=$value"
    done < .env

    if [ -z "$APP_NAME" ]; then
        color_echo "red" "❌ APP_NAME não encontrado no .env"
        exit 1
    fi

    BASE_NAME="$APP_NAME"
    color_echo "green" "✓ APP_NAME: $BASE_NAME"
}

proxima_porta_livre() {
    local porta=$((RANDOM % 9000 + 1000))
    while lsof -i :$porta &>/dev/null; do
        porta=$((RANDOM % 9000 + 1000))
    done
    echo $porta
}

gerar_compose_file() {
    local numero="$1"
    local porta="$2"
    local base_name="$3"
    local compose_file="docker-compose.${numero}.yml"

    cat > "$compose_file" << EOF
version: "3.8"

services:
  api:
    build:
      context: "."
    image: "${base_name}_${numero}:latest"
    container_name: "${base_name}_${numero}"
    env_file:
      - ".env"
    ports:
      - "${porta}:8000"
    volumes:
      - "./app:/app/app"
      - "./requirements.txt:/app/requirements.txt:ro"
    command: ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
    restart: unless-stopped
EOF

    echo "$compose_file"
}

buildar_e_subir() {
    local numero=$1
    local porta=$2
    local nome="${BASE_NAME}_${numero}"
    local compose_file
    compose_file=$(gerar_compose_file "$numero" "$porta" "$BASE_NAME")

    export APP_PORT=$porta
    export INSTANCE=$numero
    export APP_NAME=$BASE_NAME

    # Limpar cache
    color_echo "blue" "🧹 Limpando cache de build..."
    (
        docker builder prune -f > /dev/null 2>&1
    ) &
    show_loading $! "🧹 Limpando cache"
    wait $!
    color_echo "green" "✓ Cache limpo"

    # Build sem cache
    color_echo "blue" "🔨 Construindo imagem do zero (sem cache)..."
    (
        "${COMPOSE_CMD[@]}" -f $compose_file build --no-cache --pull > /tmp/docker_build_${numero}.log 2>&1
    ) &
    local build_pid=$!
    show_loading $build_pid "🔨 Build da imagem do zero (isso pode levar alguns minutos)"
    wait $build_pid

    if [ $? -ne 0 ]; then
        color_echo "red" "❌ Falha ao construir a imagem"
        color_echo "yellow" "📋 Últimas linhas do log de build:"
        tail -10 /tmp/docker_build_${numero}.log
        rm -f $compose_file /tmp/docker_build_${numero}.log
        exit 1
    fi
    color_echo "green" "✓ Imagem construída com sucesso"

    # Subir container
    color_echo "blue" "🐳 Iniciando container com docker-compose..."
    (
        "${COMPOSE_CMD[@]}" -f $compose_file up -d > /tmp/docker_compose_${numero}.log 2>&1
    ) &
    local up_pid=$!
    show_loading $up_pid "🐳 Subindo container"
    wait $up_pid

    if [ $? -eq 0 ]; then
        color_echo "green" "✓ Container iniciado com sucesso"
    else
        color_echo "red" "❌ Falha ao iniciar container"
        color_echo "yellow" "📋 Últimas linhas do log:"
        tail -10 /tmp/docker_compose_${numero}.log
        rm -f $compose_file /tmp/docker_build_${numero}.log /tmp/docker_compose_${numero}.log
        exit 1
    fi

    echo ""
    color_echo "green" "✅ ${nome} iniciado na porta $porta"
    color_echo "cyan" "🌐 Acesse: http://localhost:$porta"
    echo ""

    # Aguardar 2s para o container estabilizar antes de verificar
    sleep 2

    if docker ps --format '{{.Names}}' | grep -q "^${nome}$"; then
        color_echo "green" "✓ Container está ativo e funcionando"
        color_echo "blue" "📊 Status:"
        "${COMPOSE_CMD[@]}" -f $compose_file ps
    else
        color_echo "red" "❌ Container subiu mas caiu em seguida. Logs:"
        docker logs $nome --tail=30 2>&1
        color_echo "yellow" "⚠️ Verifique os logs acima para identificar o erro."
        rm -f $compose_file /tmp/docker_build_${numero}.log /tmp/docker_compose_${numero}.log
        exit 1
    fi

    # Limpar arquivos temporários
    rm -f $compose_file /tmp/docker_build_${numero}.log /tmp/docker_compose_${numero}.log

    echo ""
    color_echo "green" "✨ Concluído com sucesso!"
}

# ─────────────────────────────────────────
# Modo: NOVA instância incremental
# ─────────────────────────────────────────

modo_novo() {
    echo ""
    color_echo "cyan" "🚀 SUBINDO NOVA INSTÂNCIA COMPOSE..."
    echo ""

    carregar_env

    # Descobrir próximo número disponível
    local numero=1
    while docker ps -a --format '{{.Names}}' | grep -q "^${BASE_NAME}_${numero}$"; do
        numero=$((numero + 1))
    done
    color_echo "green" "✓ Próximo número disponível: $numero"

    local porta
    porta=$(proxima_porta_livre)
    color_echo "green" "✓ Porta disponível: $porta"

    buildar_e_subir "$numero" "$porta"
}

# ─────────────────────────────────────────
# Modo: REBOOT de instância existente
# ─────────────────────────────────────────

modo_reboot() {
    local NUMERO=$1

    echo ""
    color_echo "cyan" "🔄 REINICIANDO COMPOSE INSTÂNCIA #$NUMERO..."
    echo ""

    carregar_env

    local NOME="${BASE_NAME}_${NUMERO}"

    # Verificar se a instância existe
    color_echo "blue" "🔍 Verificando se a instância $NUMERO existe..."
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${NOME}$"; then
        color_echo "red" "❌ Instância $NOME não encontrada!"
        exit 1
    fi
    color_echo "green" "✓ Instância encontrada"

    # Obter porta atual
    local PORTA_ATUAL
    PORTA_ATUAL=$(docker port $NOME 8000 2>/dev/null | cut -d ':' -f2)
    if [ -z "$PORTA_ATUAL" ]; then
        color_echo "yellow" "⚠️ Não foi possível obter a porta atual, gerando nova porta..."
        PORTA_ATUAL=$(proxima_porta_livre)
    fi
    color_echo "green" "✓ Porta: $PORTA_ATUAL"

    # Criar compose temporário para fazer o down correto
    local COMPOSE_FILE
    COMPOSE_FILE=$(gerar_compose_file "$NUMERO" "$PORTA_ATUAL" "$BASE_NAME")

    # Parar e remover container + imagem
    color_echo "blue" "🛑 Parando e removendo instância $NUMERO..."
    (
        "${COMPOSE_CMD[@]}" -f $COMPOSE_FILE down --rmi local --volumes --remove-orphans > /dev/null 2>&1
    ) &
    local down_pid=$!
    show_loading $down_pid "🛑 Parando e removendo tudo"
    wait $down_pid
    color_echo "green" "✓ Containers e imagens removidos"

    # Garantir remoção da imagem e dangling
    color_echo "blue" "🗑️ Garantindo remoção de imagens residuais..."
    (
        docker rmi -f $NOME > /dev/null 2>&1
        docker image prune -f > /dev/null 2>&1
    ) &
    local rmi_pid=$!
    show_loading $rmi_pid "🗑️ Removendo imagens residuais"
    wait $rmi_pid
    color_echo "green" "✓ Imagens limpas"

    buildar_e_subir "$NUMERO" "$PORTA_ATUAL"
}

modo_bind() {
    local NUMERO=$1

    echo ""
    color_echo "cyan" "MODO BIND INSTANCIA #$NUMERO..."
    echo ""

    carregar_env

    local NOME="${BASE_NAME}_${NUMERO}"

    color_echo "blue" "Verificando instancia $NUMERO..."
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${NOME}$"; then
        color_echo "red" "Instancia $NOME nao encontrada!"
        exit 1
    fi
    color_echo "green" "Instancia encontrada"

    local PORTA_ATUAL
    PORTA_ATUAL=$(docker port $NOME 8000 2>/dev/null | cut -d ':' -f2)
    if [ -z "$PORTA_ATUAL" ]; then
        color_echo "yellow" "Nao foi possivel obter a porta atual, gerando nova porta..."
        PORTA_ATUAL=$(proxima_porta_livre)
    fi
    color_echo "green" "Porta: $PORTA_ATUAL"

    local COMPOSE_FILE
    COMPOSE_FILE=$(gerar_compose_file "$NUMERO" "$PORTA_ATUAL" "$BASE_NAME")

    export APP_PORT=$PORTA_ATUAL
    export INSTANCE=$NUMERO
    export APP_NAME=$BASE_NAME

    color_echo "blue" "Parando instancia sem remover imagem..."
    "${COMPOSE_CMD[@]}" -f $COMPOSE_FILE stop > /tmp/docker_bind_${NUMERO}.log 2>&1

    color_echo "blue" "Subindo instancia sem rebuild..."
    "${COMPOSE_CMD[@]}" -f $COMPOSE_FILE up -d --no-build >> /tmp/docker_bind_${NUMERO}.log 2>&1

    if [ $? -ne 0 ]; then
        color_echo "red" "Falha ao subir instancia em modo bind"
        tail -10 /tmp/docker_bind_${NUMERO}.log
        rm -f $COMPOSE_FILE /tmp/docker_bind_${NUMERO}.log
        exit 1
    fi

    rm -f $COMPOSE_FILE /tmp/docker_bind_${NUMERO}.log

    color_echo "green" "${NOME} iniciado sem rebuild"
    color_echo "cyan" "Acesse: http://localhost:$PORTA_ATUAL"
}

show_help() {
    echo "Uso: $0 [--rebuild [NUMERO] | --bind NUMERO]"
    echo ""
    echo "Opcoes:"
    echo "  (sem argumentos)   Mesmo que --rebuild: builda e sobe nova instancia incremental"
    echo "  --rebuild          Builda do zero e sobe nova instancia incremental"
    echo "  --rebuild NUMERO   Para, remove e rebuilda a instancia informada"
    echo "  --reboot NUMERO    Alias legado de --rebuild NUMERO"
    echo "  --bind NUMERO      Para e sobe a instancia sem rebuild, usando bind mount"
    echo "  -h, --help         Mostra esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0"
    echo "  $0 --rebuild 1"
    echo "  $0 --bind 1"
}

# ─────────────────────────────────────────
# Roteamento de argumentos
# ─────────────────────────────────────────

detectar_compose

if [ $# -eq 0 ]; then
    modo_novo

elif [ $# -eq 1 ] && [ "$1" = "--rebuild" ]; then
    modo_novo

elif [ $# -eq 2 ] && [ "$1" = "--rebuild" ]; then
    if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        color_echo "red" "Numero invalido: $2"
        exit 1
    fi
    modo_reboot "$2"

elif [ $# -eq 2 ] && [ "$1" = "--reboot" ]; then
    if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        color_echo "red" "❌ Número inválido: $2"
        exit 1
    fi
    modo_reboot "$2"

elif [ $# -eq 2 ] && [ "$1" = "--bind" ]; then
    if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        color_echo "red" "Numero invalido: $2"
        exit 1
    fi
    modo_bind "$2"

elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help

else
    show_help
    exit 1
fi
