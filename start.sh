#!/bin/bash
# Não usar set -e para permitir tratamento manual de erros

# Função para tratamento de sinais
cleanup() {
    echo "Recebido sinal de shutdown, encerrando Jekyll..."
    if [ -n "$jekyll_pid" ]; then
        kill -TERM "$jekyll_pid" 2>/dev/null || true
        wait "$jekyll_pid" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT EXIT

# Garantir que estamos no diretório correto
cd /app || {
    echo "ERRO: Não foi possível acessar /app"
    exit 1
}

# Configurar locale (ignorar warnings)
export LANG=${LANG:-en_US.UTF-8}
export LC_ALL=${LC_ALL:-en_US.UTF-8}

# Configurar bundle path explicitamente
export BUNDLE_PATH=/usr/local/bundle
export BUNDLE_WITHOUT=development:test

# Verificar se as gems estão instaladas
echo "Verificando instalação das gems..."
if ! bundle check >/dev/null 2>&1; then
    echo "Gems não encontradas, instalando..."
    bundle config set --local path '/usr/local/bundle' || true
    bundle config set --local without 'development test' || true
    if ! bundle install --jobs 4 --retry 3; then
        echo "ERRO: Falha ao instalar gems"
        echo "Listando gems instaladas:"
        bundle list || true
        echo "Tentando continuar mesmo assim..."
    fi
    # Verificar novamente
    if ! bundle check >/dev/null 2>&1; then
        echo "AVISO: Gems ainda não encontradas após instalação"
        bundle list || true
    fi
fi

# Verificar se o build existe, se não, fazer build
if [ ! -d "_site" ] || [ -z "$(ls -A _site 2>/dev/null)" ]; then
    echo "Build não encontrado, fazendo build do site..."
    if ! JEKYLL_ENV=production bundle exec jekyll build 2>&1; then
        echo "ERRO: Falha ao fazer build do site"
        echo "Tentando continuar mesmo assim..."
    fi
fi

# Verificar se o build foi criado
if [ ! -d "_site" ] || [ -z "$(ls -A _site 2>/dev/null)" ]; then
    echo "AVISO: Diretório _site ainda não existe ou está vazio"
    echo "O servidor pode não funcionar corretamente"
fi

# Iniciar servidor Jekyll
echo "Iniciando servidor Jekyll na porta ${PORT:-8080}..."
if ! bundle exec jekyll serve \
    --host 0.0.0.0 \
    --port ${PORT:-8080} \
    --no-watch \
    --skip-initial-build \
    --trace \
    > /tmp/jekyll.log 2>&1 & then
    echo "ERRO: Falha ao iniciar servidor Jekyll"
    cat /tmp/jekyll.log || true
    exit 1
fi

jekyll_pid=$!
echo "Jekyll iniciado com PID: $jekyll_pid"

# Aguardar um pouco para verificar se o processo ainda está rodando
sleep 2
if ! kill -0 "$jekyll_pid" 2>/dev/null; then
    echo "ERRO: Processo Jekyll terminou prematuramente"
    echo "Últimas linhas do log:"
    tail -20 /tmp/jekyll.log || true
    exit 1
fi

echo "Servidor Jekyll está rodando. Monitorando processo..."
wait $jekyll_pid
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo "ERRO: Servidor Jekyll terminou com código de saída: $exit_code"
    echo "Últimas linhas do log:"
    tail -50 /tmp/jekyll.log || true
fi

exit $exit_code
