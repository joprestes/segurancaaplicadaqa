#!/bin/bash

# Script para FORÇAR recompilação completa do Jekyll
# Uso: ./force-rebuild.sh

set -e

echo "🛑 Parando qualquer processo Jekyll..."
pkill -f jekyll || true
sleep 2

echo "🧹 Limpando TODOS os caches..."
# Muda para o diretório raiz do projeto (um nível acima do script)
cd "$(dirname "$0")/.."

rm -rf _site
rm -rf .jekyll-cache
rm -rf .sass-cache
rm -rf .jekyll-metadata
find . -name ".sass-cache" -type d -exec rm -rf {} + 2>/dev/null || true

echo "✅ Verificando arquivos fonte..."
if [ ! -f "_sass/components/_empty-states.scss" ]; then
    echo "❌ ERRO: _empty-states.scss não existe!"
    exit 1
fi

if [ ! -f "_sass/components/_footer.scss" ]; then
    echo "❌ ERRO: _footer.scss não existe!"
    exit 1
fi

echo "✅ Arquivos fonte OK"

echo "🔨 Recompilando com trace..."
bundle exec jekyll build --trace 2>&1 | tee build.log

echo ""
echo "🔍 Verificando CSS compilado..."

EMPTY_STATE_COUNT=$(grep -c "\.empty-state" _site/assets/main.css 2>/dev/null || echo "0")
GAP_COUNT=$(grep -c "gap.*1.5rem" _site/assets/main.css 2>/dev/null || echo "0")
FOOTER_COUNT=$(grep -c "\.site-footer" _site/assets/main.css 2>/dev/null || echo "0")

echo "  - .empty-state encontrado: $EMPTY_STATE_COUNT vezes"
echo "  - gap: 1.5rem encontrado: $GAP_COUNT vezes"
echo "  - .site-footer encontrado: $FOOTER_COUNT vezes"

if [ "$EMPTY_STATE_COUNT" -eq "0" ]; then
    echo "❌ PROBLEMA: .empty-state não está no CSS compilado!"
    echo "   Verifique build.log para erros"
    exit 1
fi

if [ "$GAP_COUNT" -eq "0" ]; then
    echo "❌ PROBLEMA: gap: 1.5rem não está no CSS compilado!"
    echo "   Verifique build.log para erros"
    exit 1
fi

echo ""
echo "✅ CSS compilado corretamente!"
echo ""
echo "🚀 Agora rode: bundle exec jekyll serve --force_polling"
echo "💡 Depois limpe o cache do navegador (Cmd+Shift+R)"
