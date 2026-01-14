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

# Garantir que estamos no diretório correto
cd /app

# Configurar bundle path explicitamente
export BUNDLE_PATH=/usr/local/bundle
export BUNDLE_WITHOUT=development:test

# Verificar se as gems estão instaladas
echo "Verificando instalação das gems..."
bundle check || {
    echo "Gems não encontradas, instalando..."
    bundle config set --local path '/usr/local/bundle'
    bundle config set --local without 'development test'
    bundle install --jobs 4 --retry 3
    bundle check || {
        echo "ERRO: Falha ao instalar gems"
        echo "Listando gems instaladas:"
        bundle list
        exit 1
    }
}

# Verificar se o build existe, se não, fazer build
if [ ! -d "_site" ] || [ -z "$(ls -A _site 2>/dev/null)" ]; then
    echo "Build não encontrado, fazendo build do site..."
    JEKYLL_ENV=production bundle exec jekyll build || {
        echo "ERRO: Falha ao fazer build do site"
        exit 1
    }
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
