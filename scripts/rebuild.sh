#!/bin/bash

# Script para limpar cache e recompilar o Jekyll
# Uso: ./rebuild.sh

echo "🧹 Limpando cache do Jekyll..."
rm -rf _site
rm -rf .jekyll-cache
rm -rf .sass-cache

echo "🔨 Recompilando site..."
bundle exec jekyll build

echo "✅ Pronto! Agora você pode rodar: bundle exec jekyll serve"
echo ""
echo "💡 Dica: Limpe o cache do navegador também (Ctrl+Shift+R ou Cmd+Shift+R)"
