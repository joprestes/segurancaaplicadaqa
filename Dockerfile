# Dockerfile para Jekyll no Fly.io
# Usa Debian-based image para melhor compatibilidade com gems Ruby

# Imagem base Ruby (Debian-based, mais compatível)
FROM ruby:3.1-slim

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Definir diretório de trabalho
WORKDIR /app

# Copiar Gemfile (Gemfile.lock será regenerado se necessário)
COPY Gemfile Gemfile.lock* ./

# Instalar dependências Ruby
# Primeiro, configurar bundle sem deployment para permitir instalação flexível
RUN bundle config set --local without 'development test' && \
    bundle config set --local path '/usr/local/bundle' && \
    if [ -f Gemfile.lock ]; then \
        bundle lock --add-platform x86_64-linux 2>/dev/null || rm -f Gemfile.lock; \
    fi && \
    bundle install --jobs 4 --retry 3 && \
    bundle check && \
    bundle config set --local deployment 'true' && \
    bundle check && \
    rm -rf /usr/local/bundle/cache/*.gem && \
    find /usr/local/bundle/gems/ -name "*.c" -delete && \
    find /usr/local/bundle/gems/ -name "*.o" -delete

# Copiar script de inicialização
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Copiar todo o código
COPY . .

# Fazer build do site Jekyll durante o build da imagem
# Isso garante que o site está pronto e reduz problemas de inicialização
# Se falhar, não aborta o build - será refeito no startup
RUN JEKYLL_ENV=production bundle exec jekyll build 2>&1 || echo "Build falhou durante construção, será refeito no startup"

# Expor porta (Fly.io usa variável PORT)
ENV PORT=8080
EXPOSE 8080

# Usar script de inicialização robusto
CMD ["/start.sh"]