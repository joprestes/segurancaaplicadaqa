#!/bin/bash
# Script para regenerar Gemfile.lock para Linux
# Remove o lock atual e deixa o Bundler gerar um novo durante o build

echo "⚠️  ATENÇÃO: Este script vai remover o Gemfile.lock atual"
echo "O Bundler vai gerar um novo durante o build do Docker"
echo ""
read -p "Continuar? (s/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Ss]$ ]]; then
    echo "Removendo Gemfile.lock..."
    rm -f Gemfile.lock
    echo "✅ Gemfile.lock removido"
    echo ""
    echo "📝 Próximos passos:"
    echo "1. Faça commit: git add Gemfile.lock && git commit -m 'chore: remove Gemfile.lock para regenerar no build'"
    echo "2. Faça push: git push"
    echo "3. O Dockerfile vai regenerar o lock durante o build"
else
    echo "❌ Operação cancelada"
    exit 1
fi