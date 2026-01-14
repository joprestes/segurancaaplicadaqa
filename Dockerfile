# Dockerfile para Jekyll no Fly.io

# Imagem base Ruby
FROM ruby:3.1-alpine

# Instalar dependências do sistema
RUN apk add --no-cache \
    build-base \
    git \
    nodejs \
    npm

# Definir diretório de trabalho
WORKDIR /app

# Copiar Gemfile e Gemfile.lock
COPY Gemfile Gemfile.lock* ./

# Instalar dependências Ruby
RUN bundle config --global frozen 1 && \
    bundle install --without development test && \
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