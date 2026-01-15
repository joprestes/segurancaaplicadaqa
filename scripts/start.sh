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
    if ! JEKYLL_ENV=production bundle exec jekyll build; then
        echo "ERRO: Falha ao fazer build do site"
        echo "Verificando configuração do Jekyll:"
        bundle exec jekyll doctor 2>&1 || true
        exit 1
    fi
fi

# Verificar se o build foi criado
if [ ! -d "_site" ] || [ -z "$(ls -A _site 2>/dev/null)" ]; then
    echo "ERRO: Diretório _site não existe ou está vazio após build"
    echo "Conteúdo do diretório atual:"
    ls -la 2>&1 || true
    exit 1
fi

echo "Build verificado: $(ls -1 _site | wc -l) arquivos encontrados"

# Iniciar servidor Jekyll
echo "Iniciando servidor Jekyll na porta ${PORT:-8080}..."

# Criar arquivo de log antes de iniciar
touch /tmp/jekyll.log

# Iniciar Jekyll em background e capturar PID
bundle exec jekyll serve \
    --host 0.0.0.0 \
    --port ${PORT:-8080} \
    --no-watch \
    --skip-initial-build \
    --trace \
    > /tmp/jekyll.log 2>&1 &

jekyll_pid=$!
echo "Jekyll iniciado com PID: $jekyll_pid"

# Aguardar e verificar se o processo está rodando
echo "Aguardando servidor Jekyll iniciar..."
sleep 5
if ! kill -0 "$jekyll_pid" 2>/dev/null; then
    echo "ERRO: Processo Jekyll terminou prematuramente"
    echo "Últimas linhas do log:"
    tail -50 /tmp/jekyll.log || true
    exit 1
fi

# Verificar se há erros no log
if grep -i "error\|fatal\|exception" /tmp/jekyll.log 2>/dev/null | tail -5; then
    echo "AVISO: Possíveis erros encontrados no log do Jekyll"
    echo "Últimas linhas do log:"
    tail -20 /tmp/jekyll.log || true
fi

echo "Servidor Jekyll está rodando (PID: $jekyll_pid)"
echo "Aguardando servidor ficar pronto para receber requisições..."

# Tentar verificar se o servidor está respondendo
for i in {1..10}; do
    sleep 1
    if curl -s -f -o /dev/null http://localhost:${PORT:-8080}/ 2>/dev/null || \
       nc -z localhost ${PORT:-8080} 2>/dev/null; then
        echo "✓ Servidor Jekyll está respondendo na porta ${PORT:-8080}"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "AVISO: Servidor pode não estar respondendo ainda, mas processo está rodando"
        echo "Últimas linhas do log:"
        tail -20 /tmp/jekyll.log || true
    fi
done

echo "Servidor Jekyll está rodando. Monitorando processo..."
wait $jekyll_pid
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo "ERRO: Servidor Jekyll terminou com código de saída: $exit_code"
    echo "Últimas linhas do log:"
    tail -50 /tmp/jekyll.log || true
fi

exit $exit_code
