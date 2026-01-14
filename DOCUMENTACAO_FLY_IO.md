# Documentação Completa do Fly.io (Janeiro 2026)

## Índice
1. [Visão Geral](#visão-geral)
2. [Instalação e Autenticação](#instalação-e-autenticação)
3. [Conceitos Principais](#conceitos-principais)
4. [Deploy de Aplicações](#deploy-de-aplicações)
5. [Configuração do fly.toml](#configuração-do-flytoml)
6. [Dockerfile: Melhores Práticas](#dockerfile-melhores-práticas)
7. [Gerenciamento de Secrets e Variáveis](#gerenciamento-de-secrets-e-variáveis)
8. [Volumes e Armazenamento Persistente](#volumes-e-armazenamento-persistente)
9. [Escalabilidade e Auto-Scaling](#escalabilidade-e-auto-scaling)
10. [Domínios Customizados e SSL](#domínios-customizados-e-ssl)
11. [Sites Estáticos e Jekyll](#sites-estáticos-e-jekyll)
12. [Regiões Disponíveis](#regiões-disponíveis)
13. [Monitoramento e Logs](#monitoramento-e-logs)
14. [Preços e Custos](#preços-e-custos)
15. [Comandos Úteis](#comandos-úteis)

---

## Visão Geral

O Fly.io é uma plataforma que permite executar aplicações globalmente, aproximando-as dos usuários para melhor performance e menor latência. A plataforma gerencia automaticamente a infraestrutura, permitindo que você foque no desenvolvimento.

### Principais Características
- **Fly Machines**: VMs leves que executam suas aplicações
- **Rede Global Anycast**: Roteia requisições para o servidor mais próximo
- **Deploy baseado em Docker**: Flexibilidade total no stack
- **Auto-scaling**: Start/stop automático baseado em tráfego
- **SSL/TLS automático**: HTTPS configurado automaticamente
- **18 regiões globais**: Incluindo São Paulo, Brasil

---

## Instalação e Autenticação

### Instalação do Fly CLI (flyctl)

**macOS (Homebrew):**
```bash
brew install flyctl
```

**Linux/macOS (Script):**
```bash
curl -L https://fly.io/install.sh | sh
```

**Windows (PowerShell):**
```powershell
powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"
```

### Autenticação

```bash
# Fazer login (abre o navegador)
fly auth login

# Verificar autenticação
fly auth whoami

# Ver organizações
fly orgs list
```

---

## Conceitos Principais

### Fly Machines
- VMs leves e rápidas que executam containers Docker
- Podem ser iniciadas/paradas em milissegundos
- Isoladas e seguras
- Podem ter volumes anexados para persistência

### Fly Proxy
- Roteador global que direciona tráfego
- Gerencia auto-start/stop de Machines
- Balanceamento de carga automático
- SSL/TLS termination

### Fly Volumes
- Armazenamento persistente local NVMe
- Anexado a uma máquina específica
- Não replicado automaticamente
- Ideal para bancos de dados e arquivos

---

## Deploy de Aplicações

### Processo Básico

1. **Inicializar aplicação:**
```bash
fly launch
```
Este comando:
- Detecta automaticamente o Dockerfile
- Cria o arquivo `fly.toml`
- Pergunta sobre configurações (nome, região, etc.)
- Faz o primeiro deploy

2. **Deploy manual:**
```bash
fly deploy
```

3. **Abrir aplicação:**
```bash
fly open
```

### Deploy a partir do GitHub

O Fly.io pode ser integrado com GitHub Actions para CI/CD automático:

```yaml
# .github/workflows/fly.yml
name: Deploy to Fly.io
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: superfly/flyctl-actions/setup-flyctl@master
      - run: flyctl deploy --remote-only
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

---

## Configuração do fly.toml

O arquivo `fly.toml` é a configuração principal da aplicação no Fly.io.

### Estrutura Completa

```toml
# Nome da aplicação
app = "seu-app"

# Região primária (onde novas Machines são criadas)
primary_region = "gru"  # São Paulo

# Configuração de build
[build]
  # Usa Dockerfile no diretório raiz (padrão)

# Variáveis de ambiente (não-sensíveis)
[env]
  JEKYLL_ENV = "production"
  PORT = "8080"
  LANG = "en_US.UTF-8"

# Configuração do serviço HTTP
[http_service]
  internal_port = 8080           # Porta que a app escuta internamente
  force_https = true              # Força redirecionamento HTTP -> HTTPS
  auto_stop_machines = true       # Para Machines quando ociosas
  auto_start_machines = true      # Inicia Machines quando há requisições
  min_machines_running = 0        # Mínimo de Machines rodando (0 = para todas quando ociosas)
  processes = ["app"]             # Processos a serem gerenciados

  # Health checks
  [[http_service.checks]]
    interval = "10s"              # Intervalo entre checks
    timeout = "2s"                # Timeout do check
    grace_period = "5s"           # Período de graça no início
    method = "GET"                # Método HTTP
    path = "/"                    # Endpoint a verificar

# Configuração da VM
[vm]
  cpu_kind = "shared"             # "shared" ou "performance"
  cpus = 1                        # Número de CPUs
  memory_mb = 256                 # Memória em MB

# Configuração de volumes (opcional)
[[mounts]]
  source = "nome_volume"          # Nome do volume
  destination = "/caminho/destino" # Onde montar no container

# Sinais de parada
kill_signal = "SIGINT"            # Sinal enviado ao parar (SIGINT, SIGTERM, etc.)
kill_timeout = 5                  # Segundos antes de forçar parada

# Processos múltiplos (opcional)
[processes]
  app = "comando_principal"
  worker = "comando_worker"

# Comando de release (executado antes do deploy)
[deploy]
  release_command = "bundle exec rails db:migrate"

# Servir arquivos estáticos (opcional)
[[statics]]
  guest_path = "/app/public"      # Caminho no container
  url_prefix = "/public"          # Prefixo da URL
```

### Opções de auto_stop_machines

- `"off"`: Machines nunca param automaticamente
- `"stop"`: Machines são paradas quando ociosas (mais lento para reiniciar)
- `"suspend"`: Machines são suspensas quando ociosas (reinício mais rápido)

---

## Dockerfile: Melhores Práticas

### 1. Multi-Stage Builds

Separe o ambiente de build do ambiente de runtime:

```dockerfile
# Stage 1: Build
FROM ruby:3.1-alpine AS builder
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install
COPY . .
RUN bundle exec jekyll build

# Stage 2: Runtime
FROM nginx:alpine
COPY --from=builder /app/_site /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### 2. Use Imagens Minimalistas

Prefira imagens Alpine ou distroless:
```dockerfile
FROM ruby:3.1-alpine  # ~40MB base
# vs
FROM ruby:3.1         # ~870MB base
```

### 3. Otimize Camadas (Layer Caching)

Coloque comandos que mudam menos no início:

```dockerfile
# ✅ Bom: Dependencies primeiro (mudam raramente)
COPY Gemfile Gemfile.lock ./
RUN bundle install

# Código depois (muda frequentemente)
COPY . .

# ❌ Ruim: Invalida cache sempre
COPY . .
RUN bundle install
```

### 4. Combine Comandos RUN

```dockerfile
# ✅ Bom: Uma camada
RUN apk add --no-cache \
    build-base \
    git \
    && rm -rf /var/cache/apk/*

# ❌ Ruim: Múltiplas camadas
RUN apk add build-base
RUN apk add git
RUN rm -rf /var/cache/apk/*
```

### 5. Limpe Após Instalações

```dockerfile
RUN apt-get update && apt-get install -y \
    package-name \
    && rm -rf /var/lib/apt/lists/*
```

### 6. Use .dockerignore

```
# .dockerignore
.git/
.github/
node_modules/
_site/
*.log
*.md
README.md
```

### 7. Fixe Versões de Imagens

```dockerfile
# ✅ Bom: Versão específica
FROM ruby:3.1.4-alpine

# ❌ Ruim: Tag latest (imprevisível)
FROM ruby:latest
```

### 8. Nunca Hardcode Secrets

```dockerfile
# ❌ NUNCA FAÇA ISSO
ENV API_KEY="secret_key_123"

# ✅ Use secrets do Fly.io
# fly secrets set API_KEY=secret_key_123
```

### 9. Execute como Usuário Não-Root

```dockerfile
RUN adduser -D appuser
USER appuser
```

### 10. Build Secrets (para secrets temporários)

```dockerfile
# Para secrets necessários apenas no build
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm install
```

Deploy com:
```bash
fly deploy --build-secret npm_token=$NPM_TOKEN
```

---

## Gerenciamento de Secrets e Variáveis

### Variáveis de Ambiente (Não-Sensíveis)

Defina no `fly.toml`:
```toml
[env]
  PORT = "8080"
  NODE_ENV = "production"
```

### Secrets (Dados Sensíveis)

Use o comando `fly secrets`:

```bash
# Definir secret
fly secrets set API_KEY=abc123

# Definir múltiplos secrets
fly secrets set \
  DATABASE_URL=postgres://... \
  SECRET_KEY=xyz789

# Listar secrets (não mostra valores)
fly secrets list

# Remover secret
fly secrets unset API_KEY

# Definir sem fazer deploy imediato (staged)
fly secrets set API_KEY=abc123 --stage
```

### Secrets como Arquivos

Para secrets que precisam ser arquivos:

```bash
# 1. Codificar em base64 e definir
fly secrets set PRIVATE_KEY=$(cat private_key.pem | base64)

# 2. Configurar no fly.toml para criar arquivo
[[files]]
  guest_path = "/app/config/private_key.pem"
  secret_name = "PRIVATE_KEY"
```

### Importar Secrets de .env

```bash
# Importar de arquivo
fly secrets import < .env
```

---

## Volumes e Armazenamento Persistente

### Características

- **Local NVMe**: Alta performance
- **Anexado a uma Machine**: Não compartilhado
- **Não replicado**: Você gerencia replicação
- **Persistente**: Sobrevive a restarts e deploys

### Criar Volume

```bash
# Criar volume
fly volumes create meu_volume --size 10 --region gru

# Listar volumes
fly volumes list

# Ver detalhes
fly volumes show vol_xxxxx

# Deletar volume
fly volumes delete vol_xxxxx
```

### Configurar no fly.toml

```toml
[[mounts]]
  source = "meu_volume"
  destination = "/data"
```

### Snapshots

```bash
# Criar snapshot
fly volumes snapshots create vol_xxxxx

# Listar snapshots
fly volumes snapshots list vol_xxxxx

# Criar volume a partir de snapshot
fly volumes create meu_volume_novo --snapshot-id vs_xxxxx
```

### Preços

- **Armazenamento**: $0.15/GB/mês
- **Snapshots**: $0.08/GB/mês (primeiros 10GB grátis)

### Backup e Redundância

**Importante**: Fly.io não replica volumes automaticamente!

Para redundância:
1. Crie múltiplos volumes em regiões diferentes
2. Implemente replicação na aplicação (ex: PostgreSQL streaming replication)
3. Faça backups regulares via snapshots

---

## Escalabilidade e Auto-Scaling

### Auto-Start e Auto-Stop

Economize recursos parando Machines quando ociosas:

```toml
[http_service]
  auto_stop_machines = true     # Para quando ocioso
  auto_start_machines = true    # Inicia com novas requisições
  min_machines_running = 0      # Mínimo rodando (0 = para todas)
```

**Comportamento:**
- Machine para após período sem requisições
- Nova requisição acorda a Machine automaticamente
- Cold start: ~100-500ms

### Escalar Manualmente

```bash
# Criar mais Machines
fly scale count 3

# Escalar em região específica
fly scale count 2 --region gru

# Ver status de escala
fly scale show
```

### Escalar Recursos

```bash
# Ver opções disponíveis
fly platform vm-sizes

# Mudar tamanho da VM
fly scale vm shared-cpu-2x --memory 512

# Ver configuração atual
fly scale show
```

### Concorrência

Configure quantas requisições simultâneas uma Machine pode processar:

```toml
[http_service]
  soft_limit = 25    # Limite suave (começa a escalar)
  hard_limit = 100   # Limite rígido (rejeita requisições)
```

---

## Domínios Customizados e SSL

### Adicionar Domínio Customizado

```bash
# Adicionar certificado/domínio
fly certs add seudominio.com

# Ver status
fly certs show seudominio.com

# Listar todos os certificados
fly certs list

# Remover certificado
fly certs delete seudominio.com
```

### Configurar DNS

**Para domínio raiz (exemplo.com):**

1. Obter IPs do Fly.io:
```bash
fly ips list
```

2. Adicionar registros DNS:
```
A     @    <IPv4-do-fly>
AAAA  @    <IPv6-do-fly>
```

**Para subdomínio (app.exemplo.com):**

Adicionar CNAME:
```
CNAME  app   seu-app.fly.dev
```

### SSL/TLS Automático

O Fly.io provisiona certificados Let's Encrypt automaticamente!

**Forçar HTTPS:**
```toml
[http_service]
  force_https = true
```

### Usar com Cloudflare

Se usar proxy do Cloudflare:

1. **Durante emissão do certificado**: Desabilite proxy (nuvem cinza)
2. **Após certificado emitido**: Pode habilitar proxy (nuvem laranja)
3. **Configuração SSL**: Use "Full" ou "Full (Strict)" no Cloudflare

---

## Sites Estáticos e Jekyll

### Abordagem 1: Jekyll Server (Desenvolvimento)

Rode o servidor Jekyll diretamente:

```dockerfile
FROM ruby:3.1-alpine
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install
COPY . .
EXPOSE 8080
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0", "--port", "8080"]
```

**Prós:**
- Simples de configurar
- Bom para protótipos

**Contras:**
- Menos eficiente
- Não otimizado para produção

### Abordagem 2: Multi-Stage com Nginx (Recomendado)

Build do site e serve com Nginx:

```dockerfile
# Stage 1: Build
FROM ruby:3.1-alpine AS builder
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install
COPY . .
RUN JEKYLL_ENV=production bundle exec jekyll build

# Stage 2: Serve
FROM nginx:alpine
COPY --from=builder /app/_site /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**Configuração Nginx (nginx.conf):**

```nginx
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    server {
        listen 80;
        server_name _;
        root /usr/share/nginx/html;
        index index.html;

        # Cache estático
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # HTML sem cache
        location ~* \.html$ {
            expires -1;
            add_header Cache-Control "no-cache";
        }

        # Fallback para index.html
        location / {
            try_files $uri $uri/ $uri.html =404;
        }

        # Erro 404
        error_page 404 /404.html;
    }
}
```

**Prós:**
- Muito mais rápido
- Otimizado para produção
- Menor uso de recursos
- Imagem final menor

### Configuração fly.toml para Jekyll

```toml
app = "seu-jekyll-site"
primary_region = "gru"

[build]

[env]
  JEKYLL_ENV = "production"

[http_service]
  internal_port = 80              # Nginx usa porta 80
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0

  [[http_service.checks]]
    interval = "30s"
    timeout = "5s"
    method = "GET"
    path = "/"

[vm]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256                 # Suficiente para site estático
```

### Configurar baseurl para Fly.io

No `_config.yml`:

```yaml
# Para servir na raiz (https://seu-app.fly.dev/)
url: "https://seu-app.fly.dev"
baseurl: ""

# OU para subdiretório
url: "https://seudominio.com"
baseurl: "/blog"
```

---

## Regiões Disponíveis

O Fly.io opera em **18 regiões** globalmente (janeiro 2026):

### América do Norte (7)
- `dfw` - Dallas, Texas
- `ewr` - Secaucus, New Jersey
- `iad` - Ashburn, Virginia
- `lax` - Los Angeles, California
- `ord` - Chicago, Illinois
- `sjc` - San Jose, California
- `yyz` - Toronto, Canada

### Europa (5)
- `ams` - Amsterdam, Netherlands
- `cdg` - Paris, France
- `fra` - Frankfurt, Germany
- `lhr` - London, United Kingdom
- `arn` - Stockholm, Sweden

### Ásia-Pacífico (4)
- `sin` - Singapore
- `nrt` - Tokyo, Japan
- `syd` - Sydney, Australia
- `bom` - Mumbai, India

### América do Sul (1)
- `gru` - **São Paulo, Brazil** ⭐

### África (1)
- `jnb` - Johannesburg, South Africa

### Comandos Úteis

```bash
# Listar regiões disponíveis
fly platform regions

# Ver regiões onde seu app está rodando
fly status

# Adicionar Machine em região específica
fly machine clone --region nrt

# Ver latência
fly checks list
```

### Recomendações

- **Brasil**: Use `gru` (São Paulo)
- **América do Norte**: `ord` (Chicago) ou `iad` (Virginia)
- **Europa**: `fra` (Frankfurt) ou `ams` (Amsterdam)
- **Ásia**: `sin` (Singapore) ou `nrt` (Tokyo)

---

## Monitoramento e Logs

### Logs em Tempo Real

```bash
# Ver logs ao vivo
fly logs

# Filtrar por instância
fly logs -i <instance-id>

# Ver últimas N linhas
fly logs --lines 100

# Seguir logs (tail -f)
fly logs --follow
```

### Métricas (Prometheus + Grafana)

O Fly.io fornece Prometheus e Grafana gerenciados:

```bash
# Abrir dashboard Grafana
fly dashboard

# Ver métricas da aplicação
fly dashboard metrics
```

**Métricas disponíveis:**
- CPU usage
- Memory usage
- Network I/O
- Disk usage
- Request rate
- Response times

### Custom Metrics

Exponha métricas Prometheus na sua aplicação:

```ruby
# Exemplo Ruby com prometheus-client
require 'prometheus/client'

prometheus = Prometheus::Client.registry
counter = prometheus.counter(:requests_total, 'Total requests')

# Na requisição
counter.increment
```

### Health Checks

Configure health checks no `fly.toml`:

```toml
[[http_service.checks]]
  interval = "10s"
  timeout = "2s"
  grace_period = "5s"
  method = "GET"
  path = "/health"
  
  [[http_service.checks.headers]]
    name = "Authorization"
    value = "Bearer token"
```

### Integração com Sentry

Fly.io oferece créditos do Sentry:

```bash
# Configurar Sentry
fly ext sentry create

# Ver status
fly ext sentry status
```

### Alertas

Configure alertas via Grafana ou exportando métricas para serviços externos.

---

## Preços e Custos

### Modelo de Cobrança (Janeiro 2026)

- **Sem tier gratuito para novas organizações**
- **Free trial**: 2 horas de runtime OU 7 dias (o que vier primeiro)
- **Pay-as-you-go**: Pague apenas pelo que usar

### Compute (Machines)

Cobrado por segundo de uso:

| Tipo | vCPU | Memória | Preço/mês* |
|------|------|---------|-----------|
| shared-cpu-1x | 1 | 256MB | ~$1.94 |
| shared-cpu-1x | 1 | 512MB | ~$3.88 |
| shared-cpu-1x | 1 | 1GB | ~$7.76 |
| shared-cpu-2x | 2 | 512MB | ~$7.76 |
| shared-cpu-2x | 2 | 1GB | ~$15.52 |
| performance-1x | 1 | 2GB | ~$23 |
| performance-2x | 2 | 4GB | ~$46 |

*Preços aproximados para 730 horas/mês (24/7)

### Armazenamento

- **Volumes**: $0.15/GB/mês
- **Snapshots**: $0.08/GB/mês (primeiros 10GB grátis)

### Rede

**Transferência de dados (Outbound):**
- América do Norte e Europa: $0.02/GB
- Ásia-Pacífico: $0.04/GB
- América do Sul e África: $0.06/GB
- Oceania: $0.08/GB

**IPs:**
- IPv6: Grátis
- IPv4 dedicado: $2/mês
- Egress IPs (scoped): $3.60/mês (a partir de 01/01/2026)

### Exemplo: Site Jekyll Pequeno

**Configuração:**
- 1 Machine shared-cpu-1x (256MB)
- Auto-stop habilitado (roda ~12h/dia em média)
- 1GB de volume
- 10GB de transferência/mês

**Custo estimado:**
- Compute: $1.94 × 50% = $0.97
- Volume: $0.15
- Transferência: $0.20
- **Total: ~$1.32/mês**

### Otimização de Custos

1. **Use auto-stop**: Pare Machines quando ociosas
2. **Compartilhe CPUs**: Use `shared-cpu` para apps pequenos
3. **Minimize volumes**: Use apenas o necessário
4. **Otimize imagens**: Imagens menores = deploy mais rápido e barato
5. **Use CDN externo**: Para assets estáticos pesados

---

## Comandos Úteis

### Gerenciamento de Apps

```bash
# Listar apps
fly apps list

# Ver informações do app
fly info

# Ver status
fly status

# Restart app
fly apps restart

# Destruir app
fly apps destroy <app-name>
```

### Deploy e Build

```bash
# Deploy normal
fly deploy

# Deploy com build remoto
fly deploy --remote-only

# Deploy de imagem específica
fly deploy --image registry.example.com/myapp:latest

# Deploy sem health checks
fly deploy --no-health-checks

# Fazer build sem deploy
fly build

# Ver histórico de builds
fly releases
```

### Machines

```bash
# Listar machines
fly machines list

# Ver detalhes
fly machines show <machine-id>

# Criar machine
fly machine run nginx

# Clonar machine
fly machine clone <machine-id>

# Parar machine
fly machine stop <machine-id>

# Iniciar machine
fly machine start <machine-id>

# Deletar machine
fly machine destroy <machine-id>

# SSH em machine
fly ssh console
```

### Debugging

```bash
# Ver logs
fly logs

# SSH na aplicação
fly ssh console

# Executar comando
fly ssh console -C "ps aux"

# Ver configuração
fly config show

# Validar fly.toml
fly config validate

# Ver health checks
fly checks list
```

### Rede e DNS

```bash
# Listar IPs
fly ips list

# Alocar IPv4
fly ips allocate-v4

# Alocar IPv6
fly ips allocate-v6

# Liberar IP
fly ips release <ip-address>

# Ver informações de rede
fly dig <hostname>
```

### Monitoramento

```bash
# Dashboard web
fly dashboard

# Ver métricas
fly dashboard metrics

# Status da plataforma
fly platform status

# Ver região mais próxima
fly platform regions
```

---

## Dicas Finais

### Segurança

1. **Nunca commite secrets** no código ou Dockerfile
2. **Use `fly secrets`** para dados sensíveis
3. **Execute como non-root** no container
4. **Escaneie vulnerabilidades**: `fly registry vulns`
5. **Use HTTPS**: Sempre configure `force_https = true`

### Performance

1. **Multi-stage builds**: Reduz tamanho da imagem
2. **Cache de layers**: Estruture Dockerfile para otimizar cache
3. **Região próxima**: Deploy na região mais próxima dos usuários
4. **Auto-scaling**: Configure adequadamente soft/hard limits
5. **Health checks**: Configure timeouts apropriados

### Custos

1. **Auto-stop**: Essencial para economizar
2. **Shared CPUs**: Suficiente para maioria dos casos
3. **Monitore uso**: `fly dashboard` regularmente
4. **Dimensione corretamente**: Não use recursos excessivos

### Desenvolvimento

1. **Teste localmente**: Use Docker antes de fazer deploy
2. **CI/CD**: Integre com GitHub Actions
3. **Staged secrets**: Use `--stage` para testar sem deploy
4. **Logs**: Sempre monitore `fly logs` após deploy

---

## Recursos Adicionais

- **Documentação Oficial**: https://fly.io/docs/
- **Community Forum**: https://community.fly.io/
- **Status Page**: https://status.flyio.net/
- **Blog**: https://fly.io/blog/
- **GitHub**: https://github.com/superfly

---

## Suporte

### Planos de Suporte

- **Community (Grátis)**: Forum da comunidade
- **Email Support**: $29/mês - Resposta em 24h úteis
- **Standard Support**: $99/mês - Resposta em 8h úteis
- **Enterprise**: Customizado - SLA dedicado

### Contato

- **Email**: support@fly.io
- **Forum**: https://community.fly.io/
- **Twitter**: @flydotio

---

**Última atualização**: Janeiro 2026

Esta documentação foi compilada a partir das fontes oficiais do Fly.io e representa o estado da plataforma em janeiro de 2026.