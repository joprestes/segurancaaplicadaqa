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
# Se Gemfile.lock existir mas não tiver plataforma x86_64-linux, tenta adicionar
# Se falhar, remove e deixa bundle install regenerar com a plataforma correta
RUN bundle config set --local without 'development test' && \
    if [ -f Gemfile.lock ]; then \
        bundle lock --add-platform x86_64-linux 2>/dev/null || rm -f Gemfile.lock; \
    fi && \
    bundle install && \
    bundle config set --local deployment 'true' && \
    rm -rf /usr/local/bundle/cache/*.gem && \
    find /usr/local/bundle/gems/ -name "*.c" -delete && \
    find /usr/local/bundle/gems/ -name "*.o" -delete

# Copiar todo o código
COPY . .

# Expor porta (Fly.io usa variável PORT)
ENV PORT=8080
EXPOSE 8080

# Comando para iniciar o servidor Jekyll
# O Fly.io injeta a variável PORT, então usamos ela
CMD sh -c 'bundle exec jekyll serve --host 0.0.0.0 --port ${PORT:-8080}'