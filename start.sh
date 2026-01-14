#!/bin/bash
set -e

# Função para tratamento de sinais
cleanup() {
    echo "Recebido sinal de shutdown, encerrando Jekyll..."
    kill -TERM "$jekyll_pid" 2>/dev/null || true
    wait "$jekyll_pid" 2>/dev/null || true
    exit 0
}

trap cleanup SIGTERM SIGINT

# Verificar se o build existe, se não, fazer build
if [ ! -d "_site" ] || [ -z "$(ls -A _site 2>/dev/null)" ]; then
    echo "Build não encontrado, fazendo build do site..."
    JEKYLL_ENV=production bundle exec jekyll build
fi

# Iniciar servidor Jekyll
echo "Iniciando servidor Jekyll na porta ${PORT:-8080}..."
bundle exec jekyll serve \
    --host 0.0.0.0 \
    --port ${PORT:-8080} \
    --no-watch \
    --skip-initial-build \
    --trace &

jekyll_pid=$!
wait $jekyll_pid
